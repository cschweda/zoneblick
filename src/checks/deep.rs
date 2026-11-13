//! The deep checks: nameserver behaviour (`NSB`), network (`NET-02`), SOA
//! sanity (`SOA`) and the deeper DNSSEC checks that need no cryptography
//! (`SEC-07`, `SEC-09`, `SEC-10`). They read the deep probes, so they give
//! nothing for a light run.

use std::collections::BTreeSet;
use std::net::IpAddr;

use super::{Evidence, Finding, Severity};
use crate::dnssec::algorithm_name;
use crate::observe::{DeepObservation, ServerDeep, Soa, ZoneObservation};

fn deep(obs: &ZoneObservation) -> Option<&DeepObservation> {
    obs.deep.as_ref()
}

fn server_finding(
    check_id: &str,
    severity: Severity,
    s: &ServerDeep,
    summary: String,
    details: Vec<String>,
) -> Finding {
    Finding::new(
        check_id,
        severity,
        &s.ns_name,
        summary,
        Evidence::ServerBehaviour {
            ns_name: s.ns_name.clone(),
            address: s.address,
            details,
        },
    )
}

fn zone_finding(
    check_id: &str,
    severity: Severity,
    name: &str,
    summary: String,
    details: Vec<String>,
) -> Finding {
    Finding::new(
        check_id,
        severity,
        name,
        summary,
        Evidence::ZoneDetail { details },
    )
}

/// NSB-01: the server mishandles EDNS: a version that does not exist yet
/// must be answered with BADVERS, and an unknown option must be ignored.
pub fn nsb_01_edns_compliance(obs: &ZoneObservation) -> Vec<Finding> {
    let mut findings = Vec::new();
    for s in deep(obs).iter().flat_map(|d| &d.servers) {
        let mut details = Vec::new();
        match (&s.edns_version.rcode, &s.edns_version.error) {
            (Some(rcode), _) if rcode == "BADVERS" => {}
            (Some(rcode), _) => details.push(format!(
                "EDNS version 1 query: answered {rcode}; BADVERS is required"
            )),
            (None, error) => details.push(format!(
                "EDNS version 1 query: no answer ({})",
                error.as_deref().unwrap_or("unknown")
            )),
        }
        match (&s.edns_option.rcode, &s.edns_option.error) {
            (Some(rcode), _) if rcode == "NOERROR" && s.edns_option.opt_present => {}
            (Some(rcode), _) if rcode == "NOERROR" => details.push(
                "query with an unknown EDNS option: the answer carried no EDNS record".to_string(),
            ),
            (Some(rcode), _) => details.push(format!(
                "query with an unknown EDNS option: answered {rcode}; the option must be ignored"
            )),
            (None, error) => details.push(format!(
                "query with an unknown EDNS option: no answer ({})",
                error.as_deref().unwrap_or("unknown")
            )),
        }
        if !details.is_empty() {
            findings.push(server_finding(
                "NSB-01",
                Severity::Warning,
                s,
                format!(
                    "{} ({}) does not follow the EDNS rules",
                    s.ns_name, s.address
                ),
                details,
            ));
        }
    }
    findings
}

/// NSB-02: the server hands the whole zone to anyone who asks.
pub fn nsb_02_open_transfer(obs: &ZoneObservation) -> Vec<Finding> {
    deep(obs)
        .iter()
        .flat_map(|d| &d.servers)
        .filter(|s| s.axfr_allowed == Some(true))
        .map(|s| {
            server_finding(
                "NSB-02",
                Severity::Warning,
                s,
                format!(
                    "{} ({}) allows a zone transfer to anyone",
                    s.ns_name, s.address
                ),
                vec!["an AXFR request from this machine was answered with the zone".to_string()],
            )
        })
        .collect()
}

/// NSB-03: an authoritative server also offers recursion.
pub fn nsb_03_recursion(obs: &ZoneObservation) -> Vec<Finding> {
    deep(obs)
        .iter()
        .flat_map(|d| &d.servers)
        .filter(|s| s.recursion_available == Some(true))
        .map(|s| {
            server_finding(
                "NSB-03",
                Severity::Warning,
                s,
                format!("{} ({}) offers recursion", s.ns_name, s.address),
                vec!["the answer to a query asking for recursion had the RA flag set".to_string()],
            )
        })
        .collect()
}

/// NSB-04: the answer does not repeat the query name as it was written.
pub fn nsb_04_case(obs: &ZoneObservation) -> Vec<Finding> {
    deep(obs)
        .iter()
        .flat_map(|d| &d.servers)
        .filter(|s| s.case_preserved == Some(false))
        .map(|s| {
            server_finding(
                "NSB-04",
                Severity::Notice,
                s,
                format!(
                    "{} ({}) does not keep the case of the query name",
                    s.ns_name, s.address
                ),
                vec![
                    "a query in mixed upper and lower case came back with the name changed"
                        .to_string(),
                ],
            )
        })
        .collect()
}

/// Why an address cannot be reached from the public internet, if so.
pub(crate) fn special_use(address: IpAddr) -> Option<&'static str> {
    match address {
        IpAddr::V4(a) => {
            let o = a.octets();
            if a.is_private() {
                Some("private")
            } else if a.is_loopback() {
                Some("loopback")
            } else if a.is_link_local() {
                Some("link-local")
            } else if a.is_documentation() {
                Some("reserved for documentation")
            } else if o[0] == 100 && (64..128).contains(&o[1]) {
                Some("carrier-grade NAT")
            } else if o[0] == 0 || o[0] >= 240 {
                Some("reserved")
            } else {
                None
            }
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            if a.is_loopback() || a.is_unspecified() {
                Some("loopback or unspecified")
            } else if s[0] & 0xfe00 == 0xfc00 {
                Some("unique local")
            } else if s[0] & 0xffc0 == 0xfe80 {
                Some("link-local")
            } else if s[0] == 0x2001 && s[1] == 0x0db8 {
                Some("reserved for documentation")
            } else {
                None
            }
        }
    }
}

/// NET-02: a nameserver address is in private or reserved space, so the
/// rest of the internet cannot reach it.
pub fn net_02_reserved_address(obs: &ZoneObservation) -> Vec<Finding> {
    if deep(obs).is_none() {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for host in &obs.ns_hosts {
        let details: Vec<String> = host
            .addresses()
            .into_iter()
            .filter_map(|a| special_use(a).map(|why| format!("{a} is {why}")))
            .collect();
        if !details.is_empty() {
            findings.push(zone_finding(
                "NET-02",
                Severity::Warning,
                &host.name,
                format!("Nameserver {} has an address that is not public", host.name),
                details,
            ));
        }
    }
    findings
}

fn apex_soa(obs: &ZoneObservation) -> Option<&Soa> {
    obs.probes
        .iter()
        .filter_map(|p| p.outcome.response())
        .filter(|r| r.is_authoritative_answer())
        .find_map(|r| r.soa.as_ref())
}

/// SOA-01: a timer in the SOA record is outside a sane range. The limits
/// are loose on purpose: they catch mistakes, not tastes.
pub fn soa_01_timers(obs: &ZoneObservation) -> Vec<Finding> {
    let (Some(_), Some(soa)) = (deep(obs), apex_soa(obs)) else {
        return Vec::new();
    };
    let mut details = Vec::new();
    if soa.refresh < 1200 {
        details.push(format!("refresh is {} s; under 20 minutes", soa.refresh));
    }
    if soa.retry < 120 {
        details.push(format!("retry is {} s; under 2 minutes", soa.retry));
    }
    if soa.retry >= soa.refresh {
        details.push(format!(
            "retry ({} s) is not shorter than refresh ({} s)",
            soa.retry, soa.refresh
        ));
    }
    if soa.expire < 604_800 {
        details.push(format!("expire is {} s; under one week", soa.expire));
    }
    if soa.expire <= soa.refresh {
        details.push(format!(
            "expire ({} s) is not longer than refresh ({} s)",
            soa.expire, soa.refresh
        ));
    }
    if soa.minimum < 60 || soa.minimum > 86_400 {
        details.push(format!(
            "negative-caching TTL is {} s; outside one minute to one day",
            soa.minimum
        ));
    }
    if details.is_empty() {
        return Vec::new();
    }
    vec![zone_finding(
        "SOA-01",
        Severity::Notice,
        &obs.zone,
        format!("The SOA timers of {} are outside sane ranges", obs.zone),
        details,
    )]
}

/// SOA-02: the primary named in the SOA record is not a listed nameserver,
/// or has no address. A hidden primary is a legitimate design; mute the
/// finding if that is yours.
pub fn soa_02_mname(obs: &ZoneObservation) -> Vec<Finding> {
    let (Some(d), Some(soa)) = (deep(obs), apex_soa(obs)) else {
        return Vec::new();
    };
    let mut details = Vec::new();
    if !obs.ns_hosts.iter().any(|h| h.name == soa.mname) {
        details.push("it is not one of the zone's nameservers".to_string());
    }
    if let Some(lookup) = &d.mname
        && lookup.is_empty_answer()
    {
        details.push("it has no address".to_string());
    }
    if details.is_empty() {
        return Vec::new();
    }
    vec![zone_finding(
        "SOA-02",
        Severity::Notice,
        &soa.mname,
        format!(
            "The primary named in the SOA record, {}, is not a reachable listed nameserver",
            soa.mname
        ),
        details,
    )]
}

/// SOA-03: the contact address in the SOA record is at a domain that does
/// not accept mail.
pub fn soa_03_rname(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(d) = deep(obs) else {
        return Vec::new();
    };
    let (Some(domain), Some(mx)) = (&d.rname_domain, &d.rname_mx) else {
        return Vec::new();
    };
    let problem = match mx.status.as_str() {
        "nxdomain" => "the domain does not exist",
        "answer" if mx.rdata.iter().all(|r| r.ends_with(" .")) => {
            "the domain publishes a null MX: it accepts no mail"
        }
        "nodata" if d.rname_address.as_ref().is_some_and(|a| !a.exists()) => {
            "the domain has no MX record and no address"
        }
        _ => return Vec::new(),
    };
    vec![zone_finding(
        "SOA-03",
        Severity::Notice,
        &obs.zone,
        format!(
            "The SOA contact of {} is at {domain}, which takes no mail",
            obs.zone
        ),
        vec![problem.to_string()],
    )]
}

/// SEC-07: NSEC3 with extra iterations or a salt. Both cost resolvers
/// work and add no protection (RFC 9276).
pub fn sec_07_nsec3_parameters(obs: &ZoneObservation) -> Vec<Finding> {
    let params: BTreeSet<_> = deep(obs)
        .iter()
        .flat_map(|d| &d.servers)
        .filter_map(|s| s.nsec3param.as_ref())
        .flatten()
        .filter(|p| p.iterations > 0 || !p.salt.is_empty())
        .collect();
    if params.is_empty() {
        return Vec::new();
    }
    let details = params
        .iter()
        .map(|p| {
            format!(
                "NSEC3PARAM: {} iterations, {}",
                p.iterations,
                if p.salt.is_empty() {
                    "no salt".to_string()
                } else {
                    format!("salt {}", p.salt)
                }
            )
        })
        .collect();
    vec![zone_finding(
        "SEC-07",
        Severity::Notice,
        &obs.zone,
        format!(
            "{} uses NSEC3 with extra iterations or a salt; current guidance is 0 and none",
            obs.zone
        ),
        details,
    )]
}

/// The labels of a name, last first, for comparing in DNSSEC's canonical
/// order (RFC 4034, section 6.1).
fn canonical(name: &str) -> Vec<Vec<u8>> {
    name.trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
        .rev()
        .map(|label| {
            // Undo the \DDD escapes, so labels compare as their bytes.
            let bytes = label.as_bytes();
            let mut out = Vec::new();
            let mut i = 0;
            while i < bytes.len() {
                let escaped = (bytes[i] == b'\\' && i + 3 < bytes.len())
                    .then(|| {
                        std::str::from_utf8(&bytes[i + 1..i + 4])
                            .ok()?
                            .parse::<u8>()
                            .ok()
                    })
                    .flatten();
                match escaped {
                    Some(b) => {
                        out.push(b);
                        i += 4;
                    }
                    None => {
                        out.push(bytes[i].to_ascii_lowercase());
                        i += 1;
                    }
                }
            }
            out
        })
        .collect()
}

/// True when the NSEC record `owner` -> `next` proves that `name` does not
/// exist: the name lies between the two, or is the owner itself (a server
/// that answers "the name exists but has no such record").
pub(crate) fn nsec_covers(owner: &str, next: &str, name: &str) -> bool {
    let (o, n, q) = (canonical(owner), canonical(next), canonical(name));
    if o == q {
        return true;
    }
    if o < n {
        o < q && q < n
    } else {
        // The last record of the chain wraps around to the apex.
        q > o || q < n
    }
}

/// SEC-06: a signed zone must prove that a name does not exist, with
/// signed NSEC or NSEC3 records. Without the proof, validating resolvers
/// reject the answer. NSEC3 proofs are checked for presence only.
pub fn sec_06_denial(obs: &ZoneObservation) -> Vec<Finding> {
    let (Some(d), Some(sec)) = (deep(obs), obs.dnssec.as_ref()) else {
        return Vec::new();
    };
    let mut details = Vec::new();
    for s in &d.servers {
        let signed_here = sec
            .servers
            .iter()
            .any(|x| x.address == s.address && x.dnskeys.as_ref().is_some_and(|k| !k.is_empty()));
        let Some(denial) = s.denial.as_ref().filter(|x| signed_here && !x.answered) else {
            continue;
        };
        let problem = if denial.nsec.is_empty() && denial.nsec3 == 0 {
            "no NSEC or NSEC3 record came with the answer"
        } else if !denial.signed {
            "the NSEC or NSEC3 records came without a signature"
        } else if denial.nsec3 == 0
            && !denial
                .nsec
                .iter()
                .any(|(owner, next)| nsec_covers(owner, next, &denial.qname))
        {
            "no NSEC record covers the name"
        } else {
            continue;
        };
        details.push(format!(
            "{} ({}), asked for {}: {problem}",
            s.ns_name, s.address, denial.qname
        ));
    }
    if details.is_empty() {
        return Vec::new();
    }
    vec![zone_finding(
        "SEC-06",
        Severity::Warning,
        &obs.zone,
        format!("{} does not prove that a missing name is missing", obs.zone),
        details,
    )]
}

/// SEC-08: the DNSKEY set changed since the previous stored run. That is
/// a key rollover, and a warning when a key went away that the parent's DS
/// set or a signature still depends on; otherwise it is only noted.
pub fn sec_08_rollover(obs: &ZoneObservation) -> Vec<Finding> {
    let (Some(d), Some(sec)) = (deep(obs), obs.dnssec.as_ref()) else {
        return Vec::new();
    };
    let Some(previous) = &d.previous_dnskeys else {
        return Vec::new();
    };
    type Key = (u16, u8);
    let before: BTreeSet<Key> = previous.iter().map(|k| (k.key_tag, k.algorithm)).collect();
    let now: BTreeSet<Key> = sec
        .servers
        .iter()
        .filter_map(|s| s.dnskeys.as_ref())
        .flatten()
        .map(|k| (k.key_tag, k.algorithm))
        .collect();
    // No server gave a key set this time: nothing can be said.
    if before == now || !sec.servers.iter().any(|s| s.dnskeys.is_some()) {
        return Vec::new();
    }
    let show = |k: &Key| format!("key {} ({})", k.0, algorithm_name(k.1));
    let mut details: Vec<String> = now
        .difference(&before)
        .map(|k| format!("added: {}", show(k)))
        .chain(
            before
                .difference(&now)
                .map(|k| format!("removed: {}", show(k))),
        )
        .collect();
    let gone: BTreeSet<&Key> = before.difference(&now).collect();
    let mut problems = BTreeSet::new();
    for ds in sec
        .parent_ds
        .iter()
        .filter_map(|p| p.records.as_ref())
        .flatten()
    {
        if gone.contains(&(ds.key_tag, ds.algorithm)) {
            problems.insert(format!(
                "the parent's DS set still names the removed {}",
                show(&(ds.key_tag, ds.algorithm))
            ));
        }
    }
    for s in &sec.servers {
        for sig in s.dnskey_sigs.iter().chain(s.soa_sigs.iter().flatten()) {
            if gone.contains(&(sig.key_tag, sig.algorithm)) {
                problems.insert(format!(
                    "{} ({}) still serves a {} signature made with the removed {}",
                    s.ns_name,
                    s.address,
                    sig.type_covered,
                    show(&(sig.key_tag, sig.algorithm))
                ));
            }
        }
    }
    let (severity, summary) = if problems.is_empty() {
        (
            Severity::Info,
            format!("The DNSKEY set of {} changed since the last run", obs.zone),
        )
    } else {
        (
            Severity::Warning,
            format!(
                "A key of {} was withdrawn while it is still needed",
                obs.zone
            ),
        )
    };
    details.extend(problems);
    vec![zone_finding(
        "SEC-08", severity, &obs.zone, summary, details,
    )]
}

/// SEC-09: the CDS or CDNSKEY records, which ask the parent to change the
/// DS set, differ between servers or name a key the zone does not publish.
pub fn sec_09_cds(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(d) = deep(obs) else {
        return Vec::new();
    };
    let mut details = Vec::new();
    let cds_sets: BTreeSet<_> = d.servers.iter().filter_map(|s| s.cds.as_ref()).collect();
    let key_sets: BTreeSet<_> = d
        .servers
        .iter()
        .filter_map(|s| s.cdnskey.as_ref())
        .collect();
    if cds_sets.len() > 1 {
        details.push("the nameservers serve different CDS record sets".to_string());
    }
    if key_sets.len() > 1 {
        details.push("the nameservers serve different CDNSKEY record sets".to_string());
    }
    let published: BTreeSet<(u16, u8)> = obs
        .dnssec
        .iter()
        .flat_map(|x| &x.servers)
        .filter_map(|s| s.dnskeys.as_ref())
        .flatten()
        .map(|k| (k.key_tag, k.algorithm))
        .collect();
    // Algorithm 0 is the request to remove the DS set; it names no key.
    let named: BTreeSet<(&str, u16, u8)> = cds_sets
        .iter()
        .flat_map(|set| set.iter())
        .filter(|c| c.algorithm != 0)
        .map(|c| ("CDS", c.key_tag, c.algorithm))
        .chain(
            key_sets
                .iter()
                .flat_map(|set| set.iter())
                .filter(|k| k.algorithm != 0)
                .map(|k| ("CDNSKEY", k.key_tag, k.algorithm)),
        )
        .collect();
    for (kind, tag, algorithm) in named {
        if !published.contains(&(tag, algorithm)) {
            details.push(format!(
                "{kind} names key {tag} ({}), which is not in the DNSKEY set",
                algorithm_name(algorithm)
            ));
        }
    }
    if details.is_empty() {
        return Vec::new();
    }
    vec![zone_finding(
        "SEC-09",
        Severity::Warning,
        &obs.zone,
        format!(
            "The CDS or CDNSKEY records of {} are inconsistent",
            obs.zone
        ),
        details,
    )]
}

/// SEC-10: an algorithm in the DS or DNSKEY set has no signature over the
/// DNSKEY set or the SOA record. Validators that only know that algorithm
/// then treat the zone as bogus.
pub fn sec_10_algorithm_completeness(obs: &ZoneObservation) -> Vec<Finding> {
    let (Some(_), Some(sec)) = (deep(obs), obs.dnssec.as_ref()) else {
        return Vec::new();
    };
    let ds_algorithms: BTreeSet<u8> = sec
        .parent_ds
        .iter()
        .filter_map(|p| p.records.as_ref())
        .flatten()
        .map(|ds| ds.algorithm)
        .collect();
    let mut details = BTreeSet::new();
    for s in &sec.servers {
        let Some(keys) = s.dnskeys.as_ref().filter(|k| !k.is_empty()) else {
            continue;
        };
        let algorithms: BTreeSet<u8> = keys
            .iter()
            .map(|k| k.algorithm)
            .chain(ds_algorithms.iter().copied())
            .collect();
        for algorithm in algorithms {
            let signs =
                |sigs: &[crate::dnssec::Rrsig]| sigs.iter().any(|g| g.algorithm == algorithm);
            if !signs(&s.dnskey_sigs) {
                details.insert(format!(
                    "{} ({}): no {} signature over the DNSKEY set",
                    s.ns_name,
                    s.address,
                    algorithm_name(algorithm)
                ));
            }
            if s.soa_sigs.as_ref().is_some_and(|sigs| !signs(sigs)) {
                details.insert(format!(
                    "{} ({}): no {} signature over the SOA record",
                    s.ns_name,
                    s.address,
                    algorithm_name(algorithm)
                ));
            }
        }
    }
    if details.is_empty() {
        return Vec::new();
    }
    vec![zone_finding(
        "SEC-10",
        Severity::Warning,
        &obs.zone,
        format!(
            "{} is not signed with every algorithm it announces",
            obs.zone
        ),
        details.into_iter().collect(),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::run_all;
    use crate::checks::testkit::*;
    use crate::dnssec::{Dnskey, Ds, Rrsig};
    use crate::observe::{DnssecObservation, Lookup, Nsec3Param, ProbeAnswer, QType, ServerDnssec};

    fn ok(rcode: &str) -> ProbeAnswer {
        ProbeAnswer {
            rcode: Some(rcode.to_string()),
            opt_present: true,
            error: None,
        }
    }

    fn lookup(name: &str, qtype: QType, status: &str, rdata: &[&str]) -> Lookup {
        Lookup {
            name: name.to_string(),
            qtype,
            status: status.to_string(),
            rdata: rdata.iter().map(|s| s.to_string()).collect(),
            cname: None,
            enclosing: None,
            error: None,
        }
    }

    /// A deep observation of a zone that does everything right, on public
    /// addresses.
    fn sound() -> ZoneObservation {
        let mut obs = healthy();
        let public = ["9.9.9.9", "149.112.112.112"];
        for (host, address) in obs.ns_hosts.iter_mut().zip(public) {
            let old = host.resolved[0];
            host.glue = vec![ip(address)];
            host.resolved = vec![ip(address)];
            for p in obs.probes.iter_mut().filter(|p| p.address == old) {
                p.address = ip(address);
            }
        }
        let servers = obs
            .ns_hosts
            .iter()
            .map(|h| ServerDeep {
                ns_name: h.name.clone(),
                address: h.resolved[0],
                edns_version: ok("BADVERS"),
                edns_option: ok("NOERROR"),
                recursion_available: Some(false),
                case_preserved: Some(true),
                axfr_allowed: Some(false),
                nsec3param: Some(vec![]),
                cds: Some(vec![]),
                cdnskey: Some(vec![]),
                denial: None,
            })
            .collect();
        obs.deep = Some(DeepObservation {
            servers,
            mname: Some(lookup(
                "ns1.example.test.",
                QType::A,
                "answer",
                &["9.9.9.9"],
            )),
            rname_domain: Some("example.test.".to_string()),
            rname_mx: Some(lookup(
                "example.test.",
                QType::Mx,
                "answer",
                &["10 mx.example.test."],
            )),
            rname_address: None,
            previous_dnskeys: None,
        });
        obs
    }

    fn d(obs: &mut ZoneObservation) -> &mut DeepObservation {
        obs.deep.as_mut().unwrap()
    }

    fn ids(obs: &ZoneObservation) -> Vec<(String, Severity)> {
        run_all(obs)
            .into_iter()
            .map(|f| (f.check_id, f.severity))
            .collect()
    }

    #[test]
    fn a_sound_zone_is_clean_and_a_light_run_says_nothing() {
        assert_eq!(ids(&sound()), []);
        // Without the deep probes, even a zone on documentation addresses
        // and with bad timers gets no deep finding.
        let mut light = healthy();
        for p in &mut light.probes {
            if let crate::observe::Outcome::Response(r) = &mut p.outcome
                && let Some(soa) = &mut r.soa
            {
                soa.refresh = 10;
            }
        }
        assert_eq!(ids(&light), []);
    }

    #[test]
    fn nameserver_behaviour() {
        let mut obs = sound();
        let s = &mut d(&mut obs).servers[0];
        s.edns_version = ok("NOERROR");
        s.edns_option = ok("FORMERR");
        s.recursion_available = Some(true);
        s.case_preserved = Some(false);
        s.axfr_allowed = Some(true);
        assert_eq!(
            ids(&obs),
            [
                ("NSB-01".to_string(), Severity::Warning),
                ("NSB-02".to_string(), Severity::Warning),
                ("NSB-03".to_string(), Severity::Warning),
                ("NSB-04".to_string(), Severity::Notice),
            ]
        );
        let f = &nsb_01_edns_compliance(&obs)[0];
        assert_eq!(f.name, "ns1.example.test.");
        match &f.evidence {
            Evidence::ServerBehaviour { details, .. } => {
                assert_eq!(details.len(), 2);
                assert!(details[0].contains("answered NOERROR; BADVERS is required"));
                assert!(details[1].contains("answered FORMERR"));
            }
            other => panic!("unexpected evidence: {other:?}"),
        }
        // No answer at all to a probe is a finding too; an untried transfer is not.
        let mut obs = sound();
        d(&mut obs).servers[1].edns_version = ProbeAnswer {
            rcode: None,
            opt_present: false,
            error: Some("timeout".to_string()),
        };
        d(&mut obs).servers[1].axfr_allowed = None;
        assert_eq!(ids(&obs), [("NSB-01".to_string(), Severity::Warning)]);
    }

    #[test]
    fn reserved_addresses() {
        for (address, expected) in [
            ("10.1.2.3", Some("private")),
            ("192.168.0.1", Some("private")),
            ("127.0.0.1", Some("loopback")),
            ("100.64.0.1", Some("carrier-grade NAT")),
            ("192.0.2.1", Some("reserved for documentation")),
            ("240.0.0.1", Some("reserved")),
            ("fd00::1", Some("unique local")),
            ("fe80::1", Some("link-local")),
            ("2001:db8::1", Some("reserved for documentation")),
            ("9.9.9.9", None),
            ("100.128.0.1", None),
            ("2620:fe::fe", None),
        ] {
            assert_eq!(special_use(ip(address)), expected, "{address}");
        }
        let mut obs = sound();
        obs.ns_hosts[1].resolved.push(ip("10.0.0.53"));
        let found = net_02_reserved_address(&obs);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "ns2.example.test.");
    }

    #[test]
    fn soa_values() {
        let set = |obs: &mut ZoneObservation, change: &dyn Fn(&mut Soa)| {
            for p in &mut obs.probes {
                if let crate::observe::Outcome::Response(r) = &mut p.outcome
                    && let Some(soa) = &mut r.soa
                {
                    change(soa);
                }
            }
        };
        let mut obs = sound();
        set(&mut obs, &|soa| {
            soa.refresh = 600;
            soa.retry = 900;
            soa.expire = 3600;
            soa.minimum = 172_800;
        });
        let found = soa_01_timers(&obs);
        assert_eq!(found.len(), 1);
        match &found[0].evidence {
            Evidence::ZoneDetail { details } => assert_eq!(details.len(), 4, "{details:?}"),
            other => panic!("unexpected evidence: {other:?}"),
        }

        // A primary that is not listed and has no address.
        let mut obs = sound();
        set(&mut obs, &|soa| {
            soa.mname = "hidden.example.test.".to_string()
        });
        d(&mut obs).mname = Some(lookup("hidden.example.test.", QType::A, "nxdomain", &[]));
        let found = soa_02_mname(&obs);
        assert_eq!(found[0].name, "hidden.example.test.");
        assert!(
            matches!(&found[0].evidence, Evidence::ZoneDetail { details } if details.len() == 2)
        );

        // The contact's domain takes no mail, in three ways.
        let mut obs = sound();
        d(&mut obs).rname_mx = Some(lookup("example.test.", QType::Mx, "answer", &["0 ."]));
        assert_eq!(soa_03_rname(&obs).len(), 1);
        d(&mut obs).rname_mx = Some(lookup("example.test.", QType::Mx, "nxdomain", &[]));
        assert_eq!(soa_03_rname(&obs).len(), 1);
        d(&mut obs).rname_mx = Some(lookup("example.test.", QType::Mx, "nodata", &[]));
        d(&mut obs).rname_address = Some(lookup("example.test.", QType::A, "nodata", &[]));
        assert_eq!(soa_03_rname(&obs).len(), 1);
        // No MX but an address: mail can still be delivered.
        d(&mut obs).rname_address = Some(lookup("example.test.", QType::A, "answer", &["9.9.9.9"]));
        assert!(soa_03_rname(&obs).is_empty());
    }

    fn key(tag: u16, algorithm: u8) -> Dnskey {
        Dnskey {
            key_tag: tag,
            flags: 257,
            algorithm,
            rdata: format!("{tag:04x}"),
        }
    }

    fn sig(covered: &str, algorithm: u8) -> Rrsig {
        Rrsig {
            type_covered: covered.to_string(),
            algorithm,
            key_tag: 1,
            expiration: u32::MAX,
            inception: 0,
            signer: ZONE.to_string(),
        }
    }

    fn signed(obs: &mut ZoneObservation, keys: &[Dnskey], algorithms: &[u8]) {
        let servers = obs
            .deep
            .as_ref()
            .unwrap()
            .servers
            .iter()
            .map(|s| ServerDnssec {
                ns_name: s.ns_name.clone(),
                address: s.address,
                dnskeys: Some(keys.to_vec()),
                dnskey_sigs: algorithms.iter().map(|a| sig("DNSKEY", *a)).collect(),
                soa_sigs: Some(algorithms.iter().map(|a| sig("SOA", *a)).collect()),
            })
            .collect();
        obs.dnssec = Some(DnssecObservation {
            parent_ds: None,
            servers,
        });
    }

    #[test]
    fn nsec3_parameters() {
        let mut obs = sound();
        d(&mut obs).servers[0].nsec3param = Some(vec![Nsec3Param {
            algorithm: 1,
            iterations: 0,
            salt: String::new(),
        }]);
        assert!(sec_07_nsec3_parameters(&obs).is_empty());
        d(&mut obs).servers[0].nsec3param = Some(vec![Nsec3Param {
            algorithm: 1,
            iterations: 10,
            salt: "abcd".to_string(),
        }]);
        let found = sec_07_nsec3_parameters(&obs);
        assert_eq!(found[0].severity, Severity::Notice);
        assert!(
            matches!(&found[0].evidence, Evidence::ZoneDetail { details }
            if details == &["NSEC3PARAM: 10 iterations, salt abcd"])
        );
    }

    #[test]
    fn cds_records() {
        let mut obs = sound();
        signed(&mut obs, &[key(100, 13)], &[13]);
        let cds = |tag: u16, algorithm: u8| Ds {
            key_tag: tag,
            algorithm,
            digest_type: 2,
            digest: "00".to_string(),
        };
        // Matching the published key, on every server: fine. So is "delete".
        for s in &mut d(&mut obs).servers {
            s.cds = Some(vec![cds(100, 13)]);
            s.cdnskey = Some(vec![key(100, 13)]);
        }
        assert!(sec_09_cds(&obs).is_empty());
        for s in &mut d(&mut obs).servers {
            s.cds = Some(vec![cds(0, 0)]);
            s.cdnskey = Some(vec![key(0, 0)]);
        }
        assert!(sec_09_cds(&obs).is_empty());
        // One server differs, and names a key nobody publishes.
        d(&mut obs).servers[0].cds = Some(vec![cds(999, 13)]);
        let found = sec_09_cds(&obs);
        assert_eq!(found[0].severity, Severity::Warning);
        match &found[0].evidence {
            Evidence::ZoneDetail { details } => {
                assert_eq!(details.len(), 2, "{details:?}");
                assert!(details[1].contains("CDS names key 999"));
            }
            other => panic!("unexpected evidence: {other:?}"),
        }
    }

    #[test]
    fn algorithm_completeness() {
        let mut obs = sound();
        signed(&mut obs, &[key(100, 13), key(200, 8)], &[13, 8]);
        assert!(sec_10_algorithm_completeness(&obs).is_empty());
        // Two algorithms announced, one signing.
        signed(&mut obs, &[key(100, 13), key(200, 8)], &[13]);
        let found = sec_10_algorithm_completeness(&obs);
        assert_eq!(found.len(), 1);
        match &found[0].evidence {
            // Two servers, each missing the DNSKEY and the SOA signature.
            Evidence::ZoneDetail { details } => assert_eq!(details.len(), 4, "{details:?}"),
            other => panic!("unexpected evidence: {other:?}"),
        }
        // An unsigned zone has nothing to complete.
        signed(&mut obs, &[], &[]);
        assert!(sec_10_algorithm_completeness(&obs).is_empty());
    }

    #[test]
    fn nsec_records_cover_names_in_canonical_order() {
        // b.example.test lies between a and d.
        assert!(nsec_covers(
            "a.example.test.",
            "d.example.test.",
            "b.example.test."
        ));
        assert!(!nsec_covers(
            "a.example.test.",
            "d.example.test.",
            "e.example.test."
        ));
        // Order goes by labels from the right: z.a sorts before b.
        assert!(nsec_covers(
            "a.example.test.",
            "b.example.test.",
            "z.a.example.test."
        ));
        // The last record wraps around to the apex.
        assert!(nsec_covers(
            "x.example.test.",
            "example.test.",
            "zz.example.test."
        ));
        assert!(!nsec_covers(
            "x.example.test.",
            "example.test.",
            "b.example.test."
        ));
        // A record at the name itself is the "exists, but no such type" form.
        assert!(nsec_covers(
            "b.example.test.",
            "\\000.b.example.test.",
            "B.example.test."
        ));
    }

    #[test]
    fn denial_of_existence() {
        use crate::observe::Denial;
        let qname = "zz--zoneblick-absent.example.test.";
        let denial = |nsec: &[(&str, &str)], nsec3: usize, signed: bool| Denial {
            qname: qname.to_string(),
            rcode: "NXDOMAIN".to_string(),
            answered: false,
            nsec: nsec
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            nsec3,
            signed,
        };
        let mut obs = sound();
        // An unsigned zone owes no proof.
        d(&mut obs).servers[0].denial = Some(denial(&[], 0, false));
        assert!(sec_06_denial(&obs).is_empty());

        signed(&mut obs, &[key(100, 13)], &[13]);
        let cases: [(Denial, Option<&str>); 6] = [
            (denial(&[], 0, false), Some("no NSEC or NSEC3 record")),
            (
                denial(&[("www.example.test.", "example.test.")], 0, false),
                Some("without a signature"),
            ),
            (
                denial(&[("a.example.test.", "b.example.test.")], 0, true),
                Some("no NSEC record covers"),
            ),
            (
                denial(&[("www.example.test.", "example.test.")], 0, true),
                None,
            ),
            (denial(&[], 2, true), None),
            (
                Denial {
                    answered: true,
                    ..denial(&[], 0, false)
                },
                None,
            ),
        ];
        for (case, expected) in cases {
            d(&mut obs).servers[0].denial = Some(case.clone());
            let found = sec_06_denial(&obs);
            match expected {
                None => assert!(found.is_empty(), "{case:?}"),
                Some(text) => {
                    assert_eq!(found[0].severity, Severity::Warning);
                    assert!(
                        matches!(&found[0].evidence, Evidence::ZoneDetail { details } if details[0].contains(text)),
                        "{case:?}: {:?}",
                        found[0].evidence
                    );
                }
            }
        }
    }

    #[test]
    fn key_rollover() {
        let mut obs = sound();
        signed(&mut obs, &[key(100, 13), key(200, 13)], &[13]);
        // No earlier run, or the same keys as then: nothing.
        assert!(sec_08_rollover(&obs).is_empty());
        d(&mut obs).previous_dnskeys = Some(vec![key(100, 13), key(200, 13)]);
        assert!(sec_08_rollover(&obs).is_empty());

        // A new key appeared and an old one left cleanly: only noted.
        d(&mut obs).previous_dnskeys = Some(vec![key(100, 13), key(300, 13)]);
        let found = sec_08_rollover(&obs);
        assert_eq!(found[0].severity, Severity::Info);
        assert!(
            matches!(&found[0].evidence, Evidence::ZoneDetail { details }
            if details == &["added: key 200 (ECDSAP256SHA256)", "removed: key 300 (ECDSAP256SHA256)"]),
            "{:?}",
            found[0].evidence
        );

        // The removed key is still named by the DS set and still signs.
        let sec = obs.dnssec.as_mut().unwrap();
        sec.parent_ds = Some(crate::observe::ParentDs {
            parent_zone: "test.".to_string(),
            server_name: None,
            server_address: ip("203.0.113.1"),
            records: Some(vec![Ds {
                key_tag: 300,
                algorithm: 13,
                digest_type: 2,
                digest: "00".to_string(),
            }]),
            error: None,
        });
        sec.servers[0].soa_sigs = Some(vec![Rrsig {
            key_tag: 300,
            ..sig("SOA", 13)
        }]);
        let found = sec_08_rollover(&obs);
        assert_eq!(found[0].severity, Severity::Warning);
        assert!(
            matches!(&found[0].evidence, Evidence::ZoneDetail { details } if details.len() == 4)
        );

        // Servers that gave no key set this time say nothing about a rollover.
        for s in &mut obs.dnssec.as_mut().unwrap().servers {
            s.dnskeys = None;
        }
        assert!(sec_08_rollover(&obs).is_empty());
    }
}
