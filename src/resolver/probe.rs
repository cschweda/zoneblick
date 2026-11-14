//! Builds the observation of one zone: finds the delegation, resolves every
//! nameserver hostname, then asks every nameserver address directly.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::rr::{Name, RData};
use tokio::task::JoinSet;

use super::ResolveError;
use super::hints::ROOT_HINTS;
use super::iterate::{Resolver, norm, parse_response, printable, rcode_name};
use super::policy::{cname_targets, collect_policy, service_probes};
use super::signed::collect_dnssec;
use super::transport::{Client, QuerySpec, RawOutcome, record_type};
use crate::observe::{
    NsHost, Outcome, QType, RecordAnswer, RecordObservation, RecordOutcome, ResponseObs,
    ServerProbe, Soa, Transport, Vantage, ZoneObservation, is_ancestor_or_equal,
};

/// The apex queries sent to every nameserver address.
///
/// SOA and NS over UDP and TCP with EDNS, plus one SOA over UDP without EDNS
/// so EDNS handling can be compared (CON-05).
const PROBE_PLAN: [(QType, Transport, bool); 5] = [
    (QType::Soa, Transport::Udp, true),
    (QType::Ns, Transport::Udp, true),
    (QType::Soa, Transport::Udp, false),
    (QType::Soa, Transport::Tcp, true),
    (QType::Ns, Transport::Tcp, true),
];

/// Turn user input into a lowercase, fully qualified zone name.
pub fn normalise_zone(input: &str) -> Result<String, ResolveError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ResolveError::InvalidName(input.to_string()));
    }
    let name =
        Name::from_utf8(trimmed).map_err(|_| ResolveError::InvalidName(input.to_string()))?;
    Ok(norm(&name))
}

/// Observe one zone: delegation path, nameserver addresses and per-server
/// answers. This does all the network I/O of a `check` run.
/// At most this many nameserver names of a zone are resolved and probed.
/// The root has 13; no sane zone comes near this.
pub const MAX_NS_NAMES: usize = 26;
/// At most this many addresses of one nameserver name are probed.
pub const MAX_NS_ADDRESSES: usize = 8;
/// At most this many nameserver names without an address are followed up.
const MAX_UNRESOLVED_NS: usize = 10;

pub async fn observe_zone(
    client: Arc<Client>,
    zone: &str,
    started_at_unix: u64,
) -> Result<ZoneObservation, ResolveError> {
    let zone = normalise_zone(zone)?;
    let vantage = detect_vantage(&client).await;
    if !vantage.ipv4 && !vantage.ipv6 {
        return Err(ResolveError::NoNetwork);
    }
    let resolver = Resolver::new(client.clone(), vantage);
    let delegation = resolver.find_delegation(&zone).await?;

    let mut hosts: BTreeMap<String, NsHost> = BTreeMap::new();
    let delegated = delegation.undelegated_ns.is_none();
    if let Some(parent) = delegation.path.last().filter(|_| delegated) {
        for name in &parent.ns {
            let host = hosts.entry(name.clone()).or_insert_with(|| new_host(name));
            host.in_parent = true;
            host.glue = parent
                .glue
                .iter()
                .filter(|g| &g.name == name)
                .map(|g| g.address)
                .collect();
        }
    }
    for name in delegation.undelegated_ns.iter().flatten() {
        hosts.entry(name.clone()).or_insert_with(|| new_host(name));
    }

    // Round one: the nameservers the parent lists. Round two: any nameserver
    // that only the zone itself lists.
    let mut probes: Vec<ServerProbe> = Vec::new();
    let mut probed: BTreeSet<IpAddr> = BTreeSet::new();
    let mut pending: Vec<String> = hosts.keys().cloned().collect();
    // Whoever serves the zone chooses how many nameservers it lists and
    // how many addresses each has. Both are capped, so that a hostile or
    // hijacked zone cannot keep a run busy for hours.
    let mut resolved_names = 0;
    for _round in 0..2 {
        let mut tasks = JoinSet::new();
        for name in &pending {
            let host = hosts.get_mut(name).expect("pending host exists");
            if resolved_names >= MAX_NS_NAMES {
                host.resolve_error = Some(format!(
                    "not checked: the zone lists more than {MAX_NS_NAMES} nameservers"
                ));
                continue;
            }
            resolved_names += 1;
            let res = resolver.resolve_host(name.clone(), 0).await;
            host.resolved = res.addresses;
            host.cname = res.cname;
            host.resolve_error = res.error;
            for address in host.addresses().into_iter().take(MAX_NS_ADDRESSES) {
                if !vantage.can_reach(&address) || !probed.insert(address) {
                    continue;
                }
                for (qtype, transport, edns) in PROBE_PLAN {
                    let client = client.clone();
                    let zone = zone.clone();
                    let ns_name = name.clone();
                    tasks.spawn(async move {
                        probe_one(&client, &zone, ns_name, address, qtype, transport, edns).await
                    });
                }
            }
        }
        while let Some(joined) = tasks.join_next().await {
            probes.push(joined.expect("probe task does not panic"));
        }

        let child_ns: BTreeSet<String> = probes
            .iter()
            .filter_map(|p| p.outcome.response())
            .filter(|r| r.is_authoritative_answer())
            .flat_map(|r| r.ns.iter().cloned())
            .collect();
        pending.clear();
        for name in child_ns {
            if !hosts.contains_key(&name) {
                pending.push(name.clone());
            }
            hosts
                .entry(name.clone())
                .or_insert_with(|| new_host(&name))
                .in_child = true;
        }
        if pending.is_empty() {
            break;
        }
    }

    if !probes.iter().any(|p| p.outcome.response().is_some()) {
        return Err(ResolveError::NoServerReachable { zone });
    }
    probes.sort();

    let parent = delegation.path.last().filter(|_| delegated);
    let dnssec = collect_dnssec(&client, &zone, parent, &responding_servers(&probes)).await;
    let unresolved_ns: Vec<String> = hosts
        .values()
        .filter(|h| h.resolved.is_empty() && !is_ancestor_or_equal(&zone, &h.name))
        .map(|h| h.name.clone())
        .take(MAX_UNRESOLVED_NS)
        .collect();
    let policy = collect_policy(&resolver, &client, &zone, &unresolved_ns).await;

    Ok(ZoneObservation {
        zone,
        started_at_unix,
        vantage,
        delegation_path: delegation.path,
        ns_hosts: hosts.into_values().collect(),
        probes,
        records: Vec::new(),
        dnssec: Some(dnssec),
        policy: Some(policy),
        deep: None,
        declared: None,
        certificates: None,
    })
}

/// The nameserver addresses that answered at least one probe, in order.
pub(crate) fn responding_servers(probes: &[ServerProbe]) -> Vec<(String, IpAddr)> {
    let mut servers: Vec<(String, IpAddr)> = Vec::new();
    for probe in probes {
        if probe.outcome.response().is_some() && !servers.iter().any(|(_, a)| *a == probe.address) {
            servers.push((probe.ns_name.clone(), probe.address));
        }
    }
    servers
}

/// Turn a name given on the command line into a full name inside `zone`.
///
/// `www` becomes `www.<zone>`, `@` is the apex, and a name that already ends
/// with the zone is kept. A name outside the zone is an error.
pub fn name_in_zone(zone: &str, input: &str) -> Result<String, ResolveError> {
    let trimmed = input.trim();
    if trimmed == "@" {
        return Ok(zone.to_string());
    }
    let bad = || ResolveError::InvalidName(input.to_string());
    if trimmed.is_empty() {
        return Err(bad());
    }
    let name = norm(&Name::from_utf8(trimmed).map_err(|_| bad())?);
    if is_ancestor_or_equal(zone, &name) {
        return Ok(name);
    }
    if trimmed.ends_with('.') {
        // An absolute name that is not in the zone.
        return Err(ResolveError::NameOutsideZone {
            name,
            zone: zone.to_string(),
        });
    }
    let joined = if zone == "." {
        name
    } else {
        format!("{name}{zone}")
    };
    Name::from_ascii(&joined).map_err(|_| bad())?;
    Ok(joined)
}

/// Observe a zone as [`observe_zone`] does, then ask every responding
/// nameserver address for the record sets of the apex and of each of `names`.
///
/// `names` must be full names inside the zone (see [`name_in_zone`]).
pub async fn observe_zone_records(
    client: Arc<Client>,
    zone: &str,
    started_at_unix: u64,
    names: &[String],
) -> Result<ZoneObservation, ResolveError> {
    let mut obs = observe_zone(client.clone(), zone, started_at_unix).await?;
    let zone = obs.zone.clone();

    // Only servers that answered something are asked; a dead server is
    // already reported and would only slow the run down.
    let servers = responding_servers(&obs.probes);

    let mut all_names: Vec<String> = vec![zone.clone()];
    for name in names {
        if !all_names.contains(name) {
            all_names.push(name.clone());
        }
    }

    let mut records: Vec<RecordObservation> = Vec::new();

    // The apex SOA and NS sets come from the probes already made.
    for (ns_name, address) in &servers {
        for qtype in [QType::Soa, QType::Ns] {
            let mut candidates: Vec<&ServerProbe> = obs
                .probes
                .iter()
                .filter(|p| p.address == *address && p.qtype == qtype && p.edns)
                .collect();
            candidates.sort_by_key(|p| p.transport);
            let Some((probe, r)) = candidates
                .into_iter()
                .find_map(|p| p.outcome.response().map(|r| (p, r)))
            else {
                continue;
            };
            let rdata = match qtype {
                QType::Soa => r.soa.iter().map(soa_text).collect(),
                _ => r.ns.clone(),
            };
            records.push(RecordObservation {
                name: zone.clone(),
                qtype,
                ns_name: ns_name.clone(),
                address: *address,
                transport: probe.transport,
                outcome: RecordOutcome::Answer(RecordAnswer {
                    rcode: r.rcode.clone(),
                    authoritative: r.authoritative,
                    ttl: None,
                    rdata,
                }),
            });
        }
    }

    let mut tasks = JoinSet::new();
    for name in &all_names {
        for qtype in QType::SWEEP {
            // A CNAME cannot exist at a zone apex.
            if qtype == QType::Cname && *name == zone {
                continue;
            }
            for (ns_name, address) in &servers {
                let client = client.clone();
                let (name, ns_name, address) = (name.clone(), ns_name.clone(), *address);
                tasks
                    .spawn(async move { ask_record(&client, name, qtype, ns_name, address).await });
            }
        }
    }
    while let Some(joined) = tasks.join_next().await {
        records.push(joined.expect("record task does not panic"));
    }
    records.sort();
    obs.records = records;

    // Where the collected aliases lead, for the takeover checks.
    if let Some(policy) = &mut obs.policy {
        let resolver = Resolver::new(client.clone(), obs.vantage);
        policy
            .targets
            .extend(cname_targets(&resolver, &obs.records).await);
        policy.services = service_probes(&resolver, &client, &policy.targets).await;
    }
    Ok(obs)
}

fn soa_text(soa: &Soa) -> String {
    format!(
        "{} {} {} {} {} {} {}",
        soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
    )
}

/// Ask one server for one record set: UDP with EDNS, then TCP if truncated.
async fn ask_record(
    client: &Client,
    name: String,
    qtype: QType,
    ns_name: String,
    address: IpAddr,
) -> RecordObservation {
    let mut spec = QuerySpec {
        server: address,
        transport: Transport::Udp,
        qname: name.clone(),
        qtype,
        edns: true,
        dnssec: false,
        probe: Default::default(),
    };
    let mut outcome = record_outcome(&spec, client.exchange(&spec).await);
    if let Some(true) = outcome.as_ref().err().copied() {
        spec.transport = Transport::Tcp;
        outcome = record_outcome(&spec, client.exchange(&spec).await);
    }
    let outcome = match outcome {
        Ok(outcome) => outcome,
        // Still truncated over TCP: nothing sensible to record.
        Err(_) => RecordOutcome::Malformed {
            message: "truncated".to_string(),
        },
    };
    RecordObservation {
        name,
        qtype,
        ns_name,
        address,
        transport: spec.transport,
        outcome,
    }
}

/// Reduce a raw outcome to a record outcome. `Err(true)` means the response
/// was truncated and should be retried over TCP.
fn record_outcome(spec: &QuerySpec, raw: RawOutcome) -> Result<RecordOutcome, bool> {
    let wire = match raw {
        RawOutcome::Response { wire } => wire,
        RawOutcome::Timeout => return Ok(RecordOutcome::Timeout),
        RawOutcome::NetError { message } => return Ok(RecordOutcome::NetError { message }),
    };
    let msg = match parse_response(spec, &wire) {
        Ok(msg) => msg,
        Err(message) => return Ok(RecordOutcome::Malformed { message }),
    };
    if msg.metadata.truncation {
        return Err(true);
    }
    let wanted = record_type(spec.qtype);
    let mut ttl: Option<u32> = None;
    let mut rdata: Vec<String> = Vec::new();
    for rec in &msg.answers {
        if rec.record_type() != wanted || norm(&rec.name) != spec.qname {
            continue;
        }
        ttl = Some(ttl.map_or(rec.ttl, |t| t.min(rec.ttl)));
        rdata.push(rdata_text(&rec.data));
    }
    rdata.sort();
    rdata.dedup();
    Ok(RecordOutcome::Answer(RecordAnswer {
        rcode: rcode_name(msg.metadata.response_code),
        authoritative: msg.metadata.authoritative,
        ttl,
        rdata,
    }))
}

/// Record data in a canonical text form: names lowercase and fully
/// qualified, TXT strings quoted, and nothing unprintable (see
/// [`printable`]).
pub(crate) fn rdata_text(data: &RData) -> String {
    printable(&rdata_raw_text(data))
}

fn rdata_raw_text(data: &RData) -> String {
    match data {
        RData::A(a) => a.0.to_string(),
        RData::AAAA(a) => a.0.to_string(),
        RData::NS(n) => norm(&n.0),
        RData::CNAME(c) => norm(&c.0),
        RData::MX(mx) => format!("{} {}", mx.preference, norm(&mx.exchange)),
        RData::TXT(txt) => txt
            .txt_data
            .iter()
            .map(|chunk| {
                let text = String::from_utf8_lossy(chunk)
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"");
                format!("\"{text}\"")
            })
            .collect::<Vec<_>>()
            .join(" "),
        other => other.to_string(),
    }
}

fn new_host(name: &str) -> NsHost {
    NsHost {
        name: name.to_string(),
        in_parent: false,
        in_child: false,
        glue: Vec::new(),
        resolved: Vec::new(),
        cname: None,
        resolve_error: None,
    }
}

/// Find out which address families work from here by asking root servers.
async fn detect_vantage(client: &Client) -> Vantage {
    let mut works = [false, false];
    for (family, slot) in works.iter_mut().enumerate() {
        for (_, v4, v6) in ROOT_HINTS.iter().take(2) {
            let server = if family == 0 { v4 } else { v6 };
            let spec = QuerySpec {
                server: server.parse().expect("root hint address is valid"),
                transport: Transport::Udp,
                qname: ".".to_string(),
                qtype: QType::Ns,
                edns: true,
                dnssec: false,
                probe: Default::default(),
            };
            if matches!(client.exchange(&spec).await, RawOutcome::Response { .. }) {
                *slot = true;
                break;
            }
        }
    }
    Vantage {
        ipv4: works[0],
        ipv6: works[1],
    }
}

async fn probe_one(
    client: &Client,
    zone: &str,
    ns_name: String,
    address: IpAddr,
    qtype: QType,
    transport: Transport,
    edns: bool,
) -> ServerProbe {
    let spec = QuerySpec {
        server: address,
        transport,
        qname: zone.to_string(),
        qtype,
        edns,
        dnssec: false,
        probe: Default::default(),
    };
    let outcome = match client.exchange(&spec).await {
        RawOutcome::Response { wire } => observe_response(&spec, &wire),
        RawOutcome::Timeout => Outcome::Timeout,
        RawOutcome::NetError { message } => Outcome::NetError { message },
    };
    ServerProbe {
        ns_name,
        address,
        qtype,
        transport,
        edns,
        outcome,
    }
}

/// Reduce one response to the facts the checks need.
fn observe_response(spec: &QuerySpec, wire: &[u8]) -> Outcome {
    let msg = match parse_response(spec, wire) {
        Ok(msg) => msg,
        Err(message) => return Outcome::Malformed { message },
    };
    let mut soa = None;
    let mut ns = Vec::new();
    for rec in msg.answers.iter().filter(|r| norm(&r.name) == spec.qname) {
        match &rec.data {
            RData::SOA(s) => {
                soa = Some(Soa {
                    mname: norm(&s.mname),
                    rname: norm(&s.rname),
                    serial: s.serial,
                    refresh: s.refresh,
                    retry: s.retry,
                    expire: s.expire,
                    minimum: s.minimum,
                });
            }
            RData::NS(target) => ns.push(norm(&target.0)),
            _ => {}
        }
    }
    ns.sort();
    ns.dedup();
    Outcome::Response(ResponseObs {
        rcode: rcode_name(msg.metadata.response_code),
        authoritative: msg.metadata.authoritative,
        truncated: msg.metadata.truncation,
        opt_present: msg.edns.is_some(),
        size: wire.len(),
        soa,
        ns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_names_are_normalised() {
        assert_eq!(normalise_zone("Example.COM").unwrap(), "example.com.");
        assert_eq!(normalise_zone("example.com.").unwrap(), "example.com.");
        assert_eq!(normalise_zone(".").unwrap(), ".");
        assert!(normalise_zone("  ").is_err());
        assert!(normalise_zone("bad..name").is_err());
    }

    #[test]
    fn record_data_cannot_carry_terminal_control_sequences() {
        use hickory_proto::rr::rdata::TXT;
        // A TXT record that tries to clear the screen and fake a clean result.
        let hostile: &[u8] = b"ok\x1b[2J\x1b[1;32mAll checks passed\x07\r\n";
        let text = rdata_text(&RData::TXT(TXT::from_bytes(vec![hostile])));
        assert!(!text.chars().any(|c| c.is_control()), "{text:?}");
        assert_eq!(
            text,
            r#""ok\027[2J\027[1;32mAll checks passed\007\013\010""#
        );
        // Direction overrides are made visible too.
        let rtl = "a\u{202e}b".as_bytes();
        let text = rdata_text(&RData::TXT(TXT::from_bytes(vec![rtl])));
        assert_eq!(text, r#""a\u{202e}b""#);
        // Ordinary text, including non-ASCII, is left alone.
        let plain = "v=spf1 -all caf\u{e9}".as_bytes();
        let text = rdata_text(&RData::TXT(TXT::from_bytes(vec![plain])));
        assert_eq!(text, "\"v=spf1 -all caf\u{e9}\"");
    }

    #[test]
    fn names_are_placed_in_the_zone() {
        let zone = "example.com.";
        assert_eq!(name_in_zone(zone, "www").unwrap(), "www.example.com.");
        assert_eq!(
            name_in_zone(zone, "WWW.Example.COM").unwrap(),
            "www.example.com."
        );
        assert_eq!(
            name_in_zone(zone, "a.b.example.com.").unwrap(),
            "a.b.example.com."
        );
        assert_eq!(name_in_zone(zone, "_dmarc").unwrap(), "_dmarc.example.com.");
        assert_eq!(name_in_zone(zone, "@").unwrap(), "example.com.");
        assert_eq!(name_in_zone(zone, "example.com").unwrap(), "example.com.");
        // A relative name that happens to look like another domain stays inside.
        assert_eq!(
            name_in_zone(zone, "www.other.org").unwrap(),
            "www.other.org.example.com."
        );
        assert!(matches!(
            name_in_zone(zone, "www.other.org."),
            Err(ResolveError::NameOutsideZone { .. })
        ));
        assert!(name_in_zone(zone, " ").is_err());
    }
}
