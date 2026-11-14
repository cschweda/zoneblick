//! The deep checks that look past the zone's own nameservers: names it
//! delegates away (`TKO-07`), the domains it depends on (`REG-05`), what
//! its mail and web servers present over TLS (`POL-11`, `TLS-01`), the
//! routes to its nameservers (`NET-03`), what public resolvers say about
//! it (`RES-01`, `RES-02`), blocklists (`BLK-01`), the strength of its
//! SPF and DMARC records (`POL-12`, `POL-13`) and domains that look like
//! it (`LAL-01`). They read what `resolver::exposure` collects.

use super::{Evidence, Finding, Severity};
use crate::observe::{DeepObservation, Lookup, ServedTls, ZoneObservation};
use crate::output::utc;
use crate::resolver::exposure::{dmarc_record, report_domains};
use crate::resolver::policy::txt_value;
use crate::resolver::smtp::certificate_covers;

fn deep(obs: &ZoneObservation) -> Option<&DeepObservation> {
    obs.deep.as_ref()
}

fn detail(
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

/// "a", "a and b", "a, b and c".
fn list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [head @ .., last] => format!("{} and {last}", head.join(", ")),
    }
}

/// TKO-07: a name is delegated to nameservers that do not serve it. At a
/// DNS host where any customer can add any zone, whoever adds the name
/// there answers for it and for everything under it.
pub fn tko_07_subzone(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(deep) = deep(obs) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for subzone in &deep.subzones {
        let mut unregistered = false;
        for server in subzone
            .servers
            .iter()
            .filter(|s| s.status == "unregistered")
        {
            unregistered = true;
            let domain = server.detail.clone().unwrap_or_default();
            out.push(Finding::new(
                "TKO-07",
                Severity::Critical,
                &subzone.name,
                format!(
                    "{} is delegated to {}, whose domain {domain} is not registered: whoever registers it answers for {}",
                    subzone.name, server.ns_name, subzone.name
                ),
                Evidence::DanglingTarget {
                    owner: subzone.name.clone(),
                    rtype: "NS".to_string(),
                    target: server.ns_name.clone(),
                    said_by: None,
                    unregistered_domain: server.detail.clone(),
                },
            ));
        }
        let serving = subzone
            .servers
            .iter()
            .filter(|s| s.status == "authoritative")
            .count();
        if unregistered || subzone.servers.is_empty() || serving == subzone.servers.len() {
            continue;
        }
        let details: Vec<String> = subzone
            .servers
            .iter()
            .map(|s| {
                let what = match (s.status.as_str(), &s.detail) {
                    ("authoritative", _) => "serves the name".to_string(),
                    ("refused", Some(d)) => format!("does not serve the name ({d})"),
                    ("refused", None) => "does not serve the name".to_string(),
                    ("silent", Some(d)) => format!("gave no answer ({d})"),
                    ("silent", None) => "gave no answer".to_string(),
                    _ => "has no address".to_string(),
                };
                match s.address {
                    Some(a) => format!("{} ({a}): {what}", s.ns_name),
                    None => format!("{}: {what}", s.ns_name),
                }
            })
            .collect();
        let refused = subzone.servers.iter().any(|s| s.status == "refused");
        let (severity, summary) = if serving == 0 && refused {
            (
                Severity::Critical,
                format!(
                    "{} is delegated to nameservers that do not serve it: where a DNS host lets a customer add any zone, whoever adds {} there answers for it",
                    subzone.name, subzone.name
                ),
            )
        } else if serving == 0 {
            (
                Severity::Warning,
                format!(
                    "{} is delegated to nameservers that do not answer for it",
                    subzone.name
                ),
            )
        } else {
            (
                Severity::Warning,
                format!(
                    "{} of the {} nameservers {} is delegated to do not serve it",
                    subzone.servers.len() - serving,
                    subzone.servers.len(),
                    subzone.name
                ),
            )
        };
        out.push(detail("TKO-07", severity, &subzone.name, summary, details));
    }
    out
}

/// REG-05: a domain that the zone's nameservers or mail servers are in is
/// about to run out, or is held by its registry. When it goes, so do they.
pub fn reg_05_dependency(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(deep) = deep(obs) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for dependency in &deep.dependencies {
        let r = &dependency.registration;
        if r.error.is_some() {
            continue;
        }
        let mut details = vec![format!("used by: {}", dependency.used_by.join(", "))];
        if let Some(registrar) = &r.registrar {
            details.push(format!("registrar: {registrar}"));
        }
        if let Some(at) = r.expires_unix {
            details.push(format!("expires: {}", utc(at)));
        }
        if !r.status.is_empty() {
            details.push(format!("status: {}", r.status.join(", ")));
        }
        let held: Vec<&str> = r
            .status
            .iter()
            .map(String::as_str)
            .filter(|s| {
                s.ends_with(" hold")
                    || matches!(*s, "redemption period" | "pending delete" | "inactive")
            })
            .collect();
        let what = if dependency
            .used_by
            .iter()
            .all(|u| u.starts_with("nameserver"))
        {
            "nameservers"
        } else if dependency
            .used_by
            .iter()
            .all(|u| u.starts_with("mail server"))
        {
            "mail servers"
        } else {
            "nameservers and mail servers"
        };
        if !held.is_empty() {
            out.push(detail(
                "REG-05",
                Severity::Critical,
                &r.domain,
                format!(
                    "{}, which the {what} of {} are in, is marked by its registry as: {}",
                    r.domain,
                    obs.zone,
                    held.join(", ")
                ),
                details,
            ));
            continue;
        }
        let Some(expires) = r.expires_unix else {
            continue;
        };
        let seconds_left = expires as i64 - obs.started_at_unix as i64;
        let days = seconds_left.div_euclid(86_400);
        if days > 30 {
            continue;
        }
        let (severity, when) = if seconds_left <= 0 {
            (Severity::Critical, format!("ran out on {}", utc(expires)))
        } else {
            (
                if days <= 7 {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                match days {
                    0 => "runs out in less than a day".to_string(),
                    1 => "runs out in 1 day".to_string(),
                    n => format!("runs out in {n} days"),
                },
            )
        };
        out.push(detail(
            "REG-05",
            severity,
            &r.domain,
            format!(
                "the registration of {}, which the {what} of {} are in, {when}",
                r.domain, obs.zone
            ),
            details,
        ));
    }
    out
}

/// What is wrong with a certificate a server presented: whether it has
/// run out, how many days are left, and whether it is for another name.
struct CertificateState {
    expired: bool,
    days_left: i64,
    wrong_name: bool,
}

fn certificate_state(entry: &ServedTls, now: u64) -> Option<CertificateState> {
    let not_after = entry.not_after_unix?;
    let seconds_left = not_after as i64 - now as i64;
    Some(CertificateState {
        expired: seconds_left <= 0,
        days_left: seconds_left.div_euclid(86_400),
        // A certificate with no names at all is not judged.
        wrong_name: !entry.names.is_empty() && !certificate_covers(&entry.names, &entry.host),
    })
}

fn certificate_details(entry: &ServedTls) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(address) = entry.address {
        out.push(format!("address: {address}"));
    }
    if let Some(at) = entry.not_after_unix {
        out.push(format!("certificate valid until: {}", utc(at)));
    }
    if !entry.names.is_empty() {
        let shown: Vec<&str> = entry.names.iter().take(8).map(String::as_str).collect();
        let more = entry.names.len() - shown.len();
        out.push(format!(
            "certificate names: {}{}",
            shown.join(", "),
            if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            }
        ));
    }
    out
}

/// POL-11: a mail server does not offer STARTTLS, or presents a
/// certificate that has run out or is for another name. Senders that
/// require TLS (MTA-STS in enforce mode, DANE) then refuse to deliver.
pub fn pol_11_mail_tls(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(deep) = deep(obs) else {
        return Vec::new();
    };
    let policy = obs.policy.as_ref();
    let enforced = policy
        .and_then(|p| p.mta_sts.as_ref())
        .is_some_and(|m| m.mode.as_deref() == Some("enforce"));
    let mut out = Vec::new();
    for entry in deep.served_tls.iter().filter(|e| e.role == "mail") {
        let dane = policy.and_then(|p| p.mail.as_ref()).is_some_and(|m| {
            m.tlsa
                .iter()
                .any(|l| !l.rdata.is_empty() && l.name == format!("_25._tcp.{}", entry.host))
        });
        // With DANE the certificate's dates and names do not count; with
        // MTA-STS they do.
        let strict = enforced && !dane;
        let mut problems: Vec<(Severity, String)> = Vec::new();
        if entry.starttls == Some(false) {
            problems.push((
                if enforced || dane {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                "does not offer STARTTLS, so mail to it crosses the network unencrypted"
                    .to_string(),
            ));
        }
        if let Some(state) = certificate_state(entry, obs.started_at_unix).filter(|_| !dane) {
            if state.expired {
                problems.push((
                    if strict {
                        Severity::Critical
                    } else {
                        Severity::Warning
                    },
                    "presents a certificate that has run out".to_string(),
                ));
            } else if state.days_left <= 7 {
                problems.push((
                    Severity::Notice,
                    format!(
                        "presents a certificate that runs out in {} days",
                        state.days_left
                    ),
                ));
            }
            if state.wrong_name {
                problems.push((
                    if strict {
                        Severity::Critical
                    } else {
                        Severity::Notice
                    },
                    "presents a certificate that is not for its name".to_string(),
                ));
            }
        }
        let Some(severity) = problems.iter().map(|(s, _)| *s).min() else {
            continue;
        };
        let what: Vec<String> = problems.into_iter().map(|(_, text)| text).collect();
        let mut summary = format!("the mail server {} {}", entry.host, list(&what));
        if strict {
            summary.push_str("; senders that follow the MTA-STS policy will not deliver to it");
        }
        out.push(detail(
            "POL-11",
            severity,
            &entry.host,
            summary,
            certificate_details(entry),
        ));
    }
    out
}

/// TLS-01: the certificate a name serves on port 443 has run out, is
/// about to, or is for another name. This is the certificate visitors
/// get, which the public logs (CRT-01) cannot show.
pub fn tls_01_served_certificate(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(deep) = deep(obs) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in deep.served_tls.iter().filter(|e| e.role == "web") {
        let Some(state) = certificate_state(entry, obs.started_at_unix) else {
            continue;
        };
        let mut problems: Vec<(Severity, String)> = Vec::new();
        if state.expired {
            problems.push((Severity::Critical, "has run out".to_string()));
        } else if state.days_left <= 14 {
            problems.push((
                if state.days_left <= 3 {
                    Severity::Warning
                } else {
                    Severity::Notice
                },
                match state.days_left {
                    0 => "runs out in less than a day".to_string(),
                    1 => "runs out in 1 day".to_string(),
                    n => format!("runs out in {n} days"),
                },
            ));
        }
        if state.wrong_name {
            problems.push((Severity::Warning, "is not for that name".to_string()));
        }
        let Some(severity) = problems.iter().map(|(s, _)| *s).min() else {
            continue;
        };
        let what: Vec<String> = problems.into_iter().map(|(_, text)| text).collect();
        out.push(detail(
            "TLS-01",
            severity,
            &entry.host,
            format!(
                "the certificate {} serves on port 443 {}",
                entry.host,
                list(&what)
            ),
            certificate_details(entry),
        ));
    }
    out
}

/// NET-03: the announcement of a nameserver's network contradicts its
/// route origin authorisation, or has none. Networks that filter invalid
/// routes cannot reach a server behind one; a network with no
/// authorisation can be announced by anyone.
pub fn net_03_route_origin(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(deep) = deep(obs) else {
        return Vec::new();
    };
    let line = |r: &crate::observe::RouteOrigin, what: &str| {
        let addresses: Vec<String> = r.addresses.iter().map(|a| a.to_string()).collect();
        format!(
            "{} from AS{}: {what} (nameserver {})",
            r.prefix,
            r.asn,
            addresses.join(", ")
        )
    };
    let mut invalid = Vec::new();
    let mut missing = Vec::new();
    for route in &deep.routes {
        match route.status.as_deref() {
            Some("invalid_asn") => {
                invalid.push(line(route, "the authorisation names another network"))
            }
            Some("invalid_length") => {
                invalid.push(line(route, "more specific than the authorisation allows"))
            }
            Some("unknown") => missing.push(line(route, "no authorisation")),
            _ => {}
        }
    }
    if invalid.is_empty() && missing.is_empty() {
        return Vec::new();
    }
    let (severity, summary) = if !invalid.is_empty() {
        (
            Severity::Warning,
            format!(
                "{} of {} is announced against its route origin authorisation (RPKI): networks that filter such routes cannot reach it",
                if invalid.len() == 1 {
                    "A nameserver network"
                } else {
                    "Nameserver networks"
                },
                obs.zone
            ),
        )
    } else {
        (
            Severity::Notice,
            format!(
                "{} of the {} nameserver networks of {} {} no route origin authorisation (RPKI), so nothing marks a false announcement of {} as false",
                missing.len(),
                deep.routes.len(),
                obs.zone,
                if missing.len() == 1 { "has" } else { "have" },
                if missing.len() == 1 { "it" } else { "them" },
            ),
        )
    };
    invalid.extend(missing);
    vec![detail("NET-03", severity, &obs.zone, summary, invalid)]
}

/// RES-01: a public resolver cannot resolve the zone. When it can once
/// validation is switched off, the zone's DNSSEC is what it rejects, and
/// every validating resolver will.
pub fn res_01_resolver_failure(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(deep) = deep(obs) else {
        return Vec::new();
    };
    let failing: Vec<_> = deep
        .resolvers
        .iter()
        .filter(|r| r.rcode.as_deref() == Some("SERVFAIL"))
        .collect();
    if failing.is_empty() {
        return Vec::new();
    }
    let rejected: Vec<String> = failing
        .iter()
        .filter(|r| r.rcode_unvalidated.as_deref() == Some("NOERROR"))
        .map(|r| r.operator.clone())
        .collect();
    let details = failing
        .iter()
        .map(|r| {
            format!(
                "{} ({}): SERVFAIL{}",
                r.operator,
                r.address,
                match r.rcode_unvalidated.as_deref() {
                    Some(rcode) => format!("; with validation switched off: {rcode}"),
                    None => String::new(),
                }
            )
        })
        .collect();
    let (severity, summary) = if rejected.is_empty() {
        let names: Vec<String> = failing.iter().map(|r| r.operator.clone()).collect();
        (
            Severity::Warning,
            format!(
                "the public resolver{} of {} cannot resolve {}",
                if names.len() == 1 { "" } else { "s" },
                list(&names),
                obs.zone
            ),
        )
    } else {
        (
            Severity::Critical,
            format!(
                "the public resolver{} of {} reject{} the DNSSEC of {}: their users cannot resolve any name in it",
                if rejected.len() == 1 { "" } else { "s" },
                list(&rejected),
                if rejected.len() == 1 { "s" } else { "" },
                obs.zone
            ),
        )
    };
    vec![detail("RES-01", severity, &obs.zone, summary, details)]
}

/// RES-02: a public resolver says the zone does not exist, while its own
/// nameservers serve it. The resolver blocks the name, or holds old data.
pub fn res_02_resolver_denies(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(deep) = deep(obs) else {
        return Vec::new();
    };
    let denying: Vec<_> = deep
        .resolvers
        .iter()
        .filter(|r| r.rcode.as_deref() == Some("NXDOMAIN"))
        .collect();
    if denying.is_empty() {
        return Vec::new();
    }
    let names: Vec<String> = denying.iter().map(|r| r.operator.clone()).collect();
    let details = denying
        .iter()
        .map(|r| format!("{} ({}): NXDOMAIN", r.operator, r.address))
        .collect();
    vec![detail(
        "RES-02",
        Severity::Warning,
        &obs.zone,
        format!(
            "the public resolver{} of {} say{} that {} does not exist: the name is blocked there, or the resolver holds old data",
            if names.len() == 1 { "" } else { "s" },
            list(&names),
            if names.len() == 1 { "s" } else { "" },
            obs.zone
        ),
        details,
    )]
}

/// What a listing code means, for the lists zoneblick asks.
fn blocklist_meaning(list: &str, code: &str) -> &'static str {
    let last: u8 = code
        .rsplit('.')
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    match (list, code.starts_with("127.0.1."), last) {
        ("zen.spamhaus.org.", _, 2) => "Spamhaus SBL: a source of spam",
        ("zen.spamhaus.org.", _, 3) => "Spamhaus CSS: a source of spam",
        ("zen.spamhaus.org.", _, 4..=7) => "Spamhaus XBL: a hijacked or infected machine",
        ("zen.spamhaus.org.", _, 10 | 11) => {
            "Spamhaus PBL: an address that should not send mail directly"
        }
        ("bl.spamcop.net.", _, _) => "SpamCop: reported for spam",
        ("dbl.spamhaus.org.", true, _) => "Spamhaus DBL: a domain seen in spam or abuse",
        _ => "listed",
    }
}

/// BLK-01: an address the zone's mail uses, or the domain itself, is on a
/// blocklist that mail servers consult. Mail from it is refused or filed
/// as spam.
pub fn blk_01_blocklisted(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(deep) = deep(obs) else {
        return Vec::new();
    };
    let mut details = Vec::new();
    let mut subjects = Vec::new();
    for lookup in &deep.blocklists {
        for code in &lookup.codes {
            let meaning = blocklist_meaning(&lookup.list, code);
            // The policy list names addresses that should not send mail
            // directly. For a server that only receives it, that is no fault.
            if meaning.starts_with("Spamhaus PBL") && lookup.role.starts_with("mail server") {
                continue;
            }
            if !subjects.contains(&lookup.subject) {
                subjects.push(lookup.subject.clone());
            }
            details.push(format!(
                "{} ({}) on {}: {code}, {meaning}",
                lookup.subject,
                lookup.role,
                lookup.list.trim_end_matches('.')
            ));
        }
    }
    if details.is_empty() {
        return Vec::new();
    }
    vec![detail(
        "BLK-01",
        Severity::Warning,
        &obs.zone,
        format!(
            "{} {} on a blocklist that mail servers consult: mail from {} may be refused or filed as spam",
            list(&subjects),
            if subjects.len() == 1 { "is" } else { "are" },
            obs.zone
        ),
        details,
    )]
}

/// What is weak about an SPF record, each with how serious it is.
pub fn spf_weaknesses(record: &str) -> Vec<(Severity, String)> {
    let mut out = Vec::new();
    let terms: Vec<String> = record
        .split_whitespace()
        .skip(1)
        .map(str::to_ascii_lowercase)
        .collect();
    let all = terms
        .iter()
        .find(|t| t.trim_start_matches(['+', '-', '~', '?']) == "all");
    let redirect = terms.iter().any(|t| t.starts_with("redirect="));
    match all.map(String::as_str) {
        Some("+all" | "all") => out.push((
            Severity::Critical,
            "it ends in +all, which allows every server on the internet to send as the domain"
                .to_string(),
        )),
        Some("?all") => out.push((
            Severity::Notice,
            "it ends in ?all, which tells receivers nothing about other senders".to_string(),
        )),
        None if !redirect => out.push((
            Severity::Notice,
            "it has no \"all\" at the end, so it tells receivers nothing about other senders"
                .to_string(),
        )),
        _ => {}
    }
    if terms.iter().any(|t| {
        let t = t.trim_start_matches(['+', '-', '~', '?']);
        t == "ptr" || t.starts_with("ptr:")
    }) {
        out.push((
            Severity::Notice,
            "it uses the ptr mechanism, which is slow, unreliable and should not be used (RFC 7208)".to_string(),
        ));
    }
    out
}

/// POL-12: the SPF record allows too much, or says too little.
pub fn pol_12_spf_strength(obs: &ZoneObservation) -> Vec<Finding> {
    if deep(obs).is_none() {
        return Vec::new();
    }
    let Some(spf) = obs.policy.as_ref().and_then(|p| p.spf.as_ref()) else {
        return Vec::new();
    };
    // More than one record is POL-01, and neither is used.
    let [record] = spf.records.as_slice() else {
        return Vec::new();
    };
    let weaknesses = spf_weaknesses(record);
    let Some(severity) = weaknesses.iter().map(|(s, _)| *s).min() else {
        return Vec::new();
    };
    let what: Vec<String> = weaknesses.into_iter().map(|(_, text)| text).collect();
    vec![detail(
        "POL-12",
        severity,
        &obs.zone,
        format!(
            "the SPF record of {} is weak: {}",
            obs.zone,
            what.join("; ")
        ),
        vec![format!("record: {record}")],
    )]
}

/// What is weak about a DMARC record. `reports` are the lookups of the
/// records by which outside report destinations agree to receive.
pub fn dmarc_weaknesses(record: &str, zone: &str, reports: &[Lookup]) -> Vec<String> {
    let tag = |name: &str| {
        record
            .split(';')
            .filter_map(|part| part.split_once('='))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_ascii_lowercase())
    };
    let mut out = Vec::new();
    let policy = tag("p");
    if tag("rua").is_none() {
        out.push("it names no address for reports (rua), so you never learn who sends mail as the domain".to_string());
    }
    for domain in report_domains(record) {
        let name = format!("{zone}_report._dmarc.{domain}");
        let Some(lookup) = reports.iter().find(|l| l.name == name) else {
            continue;
        };
        let agreed = lookup
            .rdata
            .iter()
            .any(|r| txt_value(r).to_ascii_lowercase().starts_with("v=dmarc1"));
        if lookup.status != "failed" && !agreed {
            out.push(format!(
                "reports are to go to {domain}, which has not agreed to receive them (no record at {name}), so receivers will not send them"
            ));
        }
    }
    if matches!(policy.as_deref(), Some("quarantine" | "reject")) {
        if tag("sp").as_deref() == Some("none") {
            out.push("sp=none leaves every subdomain without protection".to_string());
        }
        if let Some(pct) = tag("pct")
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|p| *p < 100)
        {
            out.push(format!(
                "pct={pct} applies the policy to only {pct}% of failing mail"
            ));
        }
    }
    out
}

/// POL-13: the DMARC record is there, and weaker than it looks.
pub fn pol_13_dmarc_strength(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(deep) = deep(obs) else {
        return Vec::new();
    };
    let Some(record) = dmarc_record(obs) else {
        return Vec::new();
    };
    let weaknesses = dmarc_weaknesses(&record, &obs.zone, &deep.dmarc_reports);
    if weaknesses.is_empty() {
        return Vec::new();
    }
    let name = obs
        .policy
        .as_ref()
        .map(|p| p.dmarc.name.clone())
        .unwrap_or_else(|| obs.zone.clone());
    vec![detail(
        "POL-13",
        Severity::Notice,
        &name,
        format!(
            "the DMARC record of {} is weaker than it looks: {}",
            obs.zone,
            weaknesses.join("; ")
        ),
        vec![format!("record: {record}")],
    )]
}

/// LAL-01: a domain that looks like the zone's is registered and takes
/// mail. It can receive mail meant for the zone, and send mail that
/// looks as if it came from it.
pub fn lal_01_lookalike(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(deep) = deep(obs) else {
        return Vec::new();
    };
    deep.lookalikes
        .iter()
        .filter(|l| !l.mx.is_empty())
        .map(|l| {
            detail(
                "LAL-01",
                Severity::Notice,
                &l.domain,
                format!(
                    "{} is registered and takes mail; it differs from {} by {}",
                    l.domain, obs.zone, l.kind
                ),
                vec![format!("mail servers: {}", l.mx.join(", "))],
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::run_all;
    use crate::checks::testkit::healthy;
    use crate::observe::{
        BlocklistLookup, Dependency, Lookalike, QType, Registration, ResolverView, RouteOrigin,
        Subzone, SubzoneServer,
    };

    fn sound() -> ZoneObservation {
        let mut obs = healthy();
        obs.started_at_unix = 1_700_000_000;
        obs.deep = Some(DeepObservation::default());
        obs
    }

    fn d(obs: &mut ZoneObservation) -> &mut DeepObservation {
        obs.deep.as_mut().unwrap()
    }

    fn found(obs: &ZoneObservation, check: &str) -> Vec<(Severity, String)> {
        run_all(obs)
            .into_iter()
            .filter(|f| f.check_id == check)
            .map(|f| (f.severity, f.summary))
            .collect()
    }

    fn server(name: &str, status: &str, detail: Option<&str>) -> SubzoneServer {
        SubzoneServer {
            ns_name: name.to_string(),
            address: (status != "no_address" && status != "unregistered")
                .then(|| "192.0.2.1".parse().unwrap()),
            status: status.to_string(),
            detail: detail.map(str::to_string),
        }
    }

    #[test]
    fn a_delegated_name_must_be_served_by_its_nameservers() {
        let mut obs = sound();
        let sub = |servers: Vec<SubzoneServer>| Subzone {
            name: "shop.example.test.".to_string(),
            servers,
        };
        d(&mut obs).subzones = vec![sub(vec![
            server("ns1.host.example.", "authoritative", None),
            server("ns2.host.example.", "authoritative", None),
        ])];
        assert!(found(&obs, "TKO-07").is_empty());

        // Every server answers, and none for this name: the takeover case.
        d(&mut obs).subzones = vec![sub(vec![
            server("ns1.host.example.", "refused", Some("REFUSED")),
            server("ns2.host.example.", "silent", Some("timeout")),
        ])];
        let f = found(&obs, "TKO-07");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].0, Severity::Critical);

        // Nobody answers at all: broken, but nothing to take.
        d(&mut obs).subzones = vec![sub(vec![server(
            "ns1.host.example.",
            "silent",
            Some("timeout"),
        )])];
        assert_eq!(found(&obs, "TKO-07")[0].0, Severity::Warning);

        // One of two is lame.
        d(&mut obs).subzones = vec![sub(vec![
            server("ns1.host.example.", "authoritative", None),
            server("ns2.host.example.", "refused", Some("REFUSED")),
        ])];
        let f = found(&obs, "TKO-07");
        assert_eq!(f[0].0, Severity::Warning);
        assert!(f[0].1.starts_with("1 of the 2 nameservers"));

        // A nameserver in a domain nobody owns.
        d(&mut obs).subzones = vec![sub(vec![
            server("ns1.host.example.", "authoritative", None),
            server("ns.gone.example.", "unregistered", Some("gone.example.")),
        ])];
        let f = found(&obs, "TKO-07");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].0, Severity::Critical);
        assert!(f[0].1.contains("gone.example. is not registered"));
    }

    #[test]
    fn a_domain_the_zone_depends_on_must_not_lapse() {
        let mut obs = sound();
        let now = obs.started_at_unix;
        let dep = |expires: Option<u64>, status: &[&str]| Dependency {
            used_by: vec!["nameserver ns1.host.example.".to_string()],
            registration: Registration {
                domain: "host.example.".to_string(),
                expires_unix: expires,
                status: status.iter().map(|s| s.to_string()).collect(),
                ..Registration::default()
            },
        };
        d(&mut obs).dependencies = vec![dep(
            Some(now + 200 * 86_400),
            &["client transfer prohibited"],
        )];
        assert!(found(&obs, "REG-05").is_empty());
        d(&mut obs).dependencies = vec![dep(Some(now + 20 * 86_400), &[])];
        assert_eq!(found(&obs, "REG-05")[0].0, Severity::Warning);
        d(&mut obs).dependencies = vec![dep(Some(now + 3 * 86_400), &[])];
        assert_eq!(found(&obs, "REG-05")[0].0, Severity::Critical);
        d(&mut obs).dependencies = vec![dep(Some(now - 1), &[])];
        assert!(found(&obs, "REG-05")[0].1.contains("ran out"));
        d(&mut obs).dependencies = vec![dep(Some(now + 200 * 86_400), &["client hold"])];
        assert_eq!(found(&obs, "REG-05")[0].0, Severity::Critical);
        // A lookup that failed says nothing.
        let mut failed = dep(Some(now - 1), &[]);
        failed.registration.error = Some("no answer".to_string());
        d(&mut obs).dependencies = vec![failed];
        assert!(found(&obs, "REG-05").is_empty());
    }

    fn tls(role: &str, host: &str, days: i64, names: &[&str], now: u64) -> ServedTls {
        ServedTls {
            role: role.to_string(),
            host: host.to_string(),
            address: Some("192.0.2.9".parse().unwrap()),
            starttls: (role == "mail").then_some(true),
            not_after_unix: Some((now as i64 + days * 86_400 + 60) as u64),
            names: names.iter().map(|n| n.to_string()).collect(),
            error: None,
        }
    }

    #[test]
    fn the_certificate_a_web_name_serves_is_judged() {
        let mut obs = sound();
        let now = obs.started_at_unix;
        let host = "www.example.test.";
        d(&mut obs).served_tls = vec![tls("web", host, 60, &["www.example.test"], now)];
        assert!(found(&obs, "TLS-01").is_empty());
        d(&mut obs).served_tls = vec![tls("web", host, 60, &["*.example.test"], now)];
        assert!(found(&obs, "TLS-01").is_empty());
        d(&mut obs).served_tls = vec![tls("web", host, 10, &["www.example.test"], now)];
        assert_eq!(found(&obs, "TLS-01")[0].0, Severity::Notice);
        d(&mut obs).served_tls = vec![tls("web", host, 2, &["www.example.test"], now)];
        assert_eq!(found(&obs, "TLS-01")[0].0, Severity::Warning);
        d(&mut obs).served_tls = vec![tls("web", host, -2, &["www.example.test"], now)];
        assert_eq!(found(&obs, "TLS-01")[0].0, Severity::Critical);
        d(&mut obs).served_tls = vec![tls("web", host, 60, &["other.example"], now)];
        let f = found(&obs, "TLS-01");
        assert_eq!(f[0].0, Severity::Warning);
        assert!(f[0].1.contains("is not for that name"));
        // Nothing on port 443 is not a finding.
        let mut closed = tls("web", host, 60, &[], now);
        closed.not_after_unix = None;
        closed.error = Some("connection refused".to_string());
        d(&mut obs).served_tls = vec![closed];
        assert!(found(&obs, "TLS-01").is_empty());
    }

    #[test]
    fn a_mail_server_must_offer_tls_with_a_current_certificate() {
        let mut obs = sound();
        let now = obs.started_at_unix;
        let host = "mx.example.test.";
        d(&mut obs).served_tls = vec![tls("mail", host, 60, &["mx.example.test"], now)];
        assert!(found(&obs, "POL-11").is_empty());
        let mut plain = tls("mail", host, 60, &[], now);
        plain.starttls = Some(false);
        plain.not_after_unix = None;
        d(&mut obs).served_tls = vec![plain];
        let f = found(&obs, "POL-11");
        assert_eq!(f[0].0, Severity::Warning);
        assert!(f[0].1.contains("does not offer STARTTLS"));
        d(&mut obs).served_tls = vec![tls("mail", host, -1, &["mx.example.test"], now)];
        assert_eq!(found(&obs, "POL-11")[0].0, Severity::Warning);
        // Without a policy that requires it, another name is only noted.
        d(&mut obs).served_tls = vec![tls("mail", host, 60, &["mail.provider.example"], now)];
        assert_eq!(found(&obs, "POL-11")[0].0, Severity::Notice);
        // A server that could not be reached says nothing.
        let mut unreachable = tls("mail", host, 60, &[], now);
        unreachable.starttls = None;
        unreachable.not_after_unix = None;
        unreachable.error = Some("timed out".to_string());
        d(&mut obs).served_tls = vec![unreachable];
        assert!(found(&obs, "POL-11").is_empty());
    }

    #[test]
    fn routes_without_or_against_an_authorisation_are_reported_once() {
        let mut obs = sound();
        let route = |prefix: &str, status: Option<&str>| RouteOrigin {
            prefix: prefix.to_string(),
            asn: 64496,
            addresses: vec!["192.0.2.1".parse().unwrap()],
            status: status.map(str::to_string),
            error: None,
        };
        d(&mut obs).routes = vec![
            route("192.0.2.0/24", Some("valid")),
            route("198.51.100.0/24", None),
        ];
        assert!(found(&obs, "NET-03").is_empty());
        d(&mut obs).routes = vec![
            route("192.0.2.0/24", Some("valid")),
            route("198.51.100.0/24", Some("unknown")),
        ];
        let f = found(&obs, "NET-03");
        assert_eq!((f.len(), f[0].0), (1, Severity::Notice));
        assert!(f[0].1.starts_with("1 of the 2 nameserver networks"));
        d(&mut obs).routes = vec![
            route("192.0.2.0/24", Some("invalid_asn")),
            route("198.51.100.0/24", Some("unknown")),
        ];
        let f = found(&obs, "NET-03");
        assert_eq!((f.len(), f[0].0), (1, Severity::Warning));
    }

    #[test]
    fn public_resolvers_that_fail_or_deny_are_reported() {
        let mut obs = sound();
        let view = |operator: &str, rcode: &str, unvalidated: Option<&str>| ResolverView {
            operator: operator.to_string(),
            address: "192.0.2.53".parse().unwrap(),
            rcode: Some(rcode.to_string()),
            rcode_unvalidated: unvalidated.map(str::to_string),
            error: None,
        };
        d(&mut obs).resolvers = vec![
            view("Cloudflare", "NOERROR", None),
            view("Google", "NOERROR", None),
        ];
        assert!(found(&obs, "RES-01").is_empty() && found(&obs, "RES-02").is_empty());
        // Fails with validation, answers without: the DNSSEC is rejected.
        d(&mut obs).resolvers = vec![
            view("Cloudflare", "SERVFAIL", Some("NOERROR")),
            view("Google", "SERVFAIL", Some("NOERROR")),
        ];
        let f = found(&obs, "RES-01");
        assert_eq!(f[0].0, Severity::Critical);
        assert!(f[0].1.contains("Cloudflare and Google reject the DNSSEC"));
        // Fails either way: it cannot reach the zone.
        d(&mut obs).resolvers = vec![view("Quad9", "SERVFAIL", Some("SERVFAIL"))];
        let f = found(&obs, "RES-01");
        assert_eq!(f[0].0, Severity::Warning);
        assert!(f[0].1.contains("resolver of Quad9 cannot resolve"));
        d(&mut obs).resolvers = vec![
            view("Quad9", "NXDOMAIN", None),
            view("Google", "NOERROR", None),
        ];
        let f = found(&obs, "RES-02");
        assert_eq!(f[0].0, Severity::Warning);
        assert!(
            f[0].1
                .contains("Quad9 says that example.test. does not exist")
        );
    }

    #[test]
    fn listings_are_reported_and_the_policy_list_is_no_fault_of_a_receiver() {
        let mut obs = sound();
        let entry = |subject: &str, role: &str, list: &str, codes: &[&str]| BlocklistLookup {
            subject: subject.to_string(),
            role: role.to_string(),
            list: list.to_string(),
            codes: codes.iter().map(|c| c.to_string()).collect(),
            error: None,
        };
        d(&mut obs).blocklists = vec![
            entry(
                "192.0.2.25",
                "mail server mx.example.test.",
                "zen.spamhaus.org.",
                &[],
            ),
            entry(
                "192.0.2.25",
                "mail server mx.example.test.",
                "bl.spamcop.net.",
                &[],
            ),
        ];
        assert!(found(&obs, "BLK-01").is_empty());
        d(&mut obs).blocklists = vec![entry(
            "192.0.2.25",
            "mail server mx.example.test.",
            "zen.spamhaus.org.",
            &["127.0.0.10"],
        )];
        assert!(found(&obs, "BLK-01").is_empty());
        d(&mut obs).blocklists = vec![
            entry(
                "192.0.2.25",
                "SPF record",
                "zen.spamhaus.org.",
                &["127.0.0.10"],
            ),
            entry(
                "192.0.2.26",
                "mail server mx.example.test.",
                "zen.spamhaus.org.",
                &["127.0.0.2", "127.0.0.4"],
            ),
            entry(
                "example.test.",
                "the domain",
                "dbl.spamhaus.org.",
                &["127.0.1.2"],
            ),
        ];
        let all = run_all(&obs);
        let f: Vec<_> = all.iter().filter(|f| f.check_id == "BLK-01").collect();
        assert_eq!(f.len(), 1);
        assert!(
            f[0].summary
                .starts_with("192.0.2.25, 192.0.2.26 and example.test. are on a blocklist")
        );
        let Evidence::ZoneDetail { details } = &f[0].evidence else {
            panic!("zone detail expected");
        };
        assert_eq!(details.len(), 4);
        assert!(details[1].contains("Spamhaus SBL") && details[3].contains("Spamhaus DBL"));
    }

    #[test]
    fn spf_endings_and_mechanisms() {
        let worst = |record: &str| spf_weaknesses(record).iter().map(|(s, _)| *s).min();
        assert_eq!(worst("v=spf1 mx -all"), None);
        assert_eq!(worst("v=spf1 include:x.example ~all"), None);
        assert_eq!(worst("v=spf1 redirect=x.example"), None);
        assert_eq!(worst("v=spf1 mx +all"), Some(Severity::Critical));
        assert_eq!(worst("v=spf1 mx ALL"), Some(Severity::Critical));
        assert_eq!(worst("v=spf1 mx ?all"), Some(Severity::Notice));
        assert_eq!(worst("v=spf1 mx"), Some(Severity::Notice));
        assert_eq!(worst("v=spf1 ptr -all"), Some(Severity::Notice));
        assert_eq!(spf_weaknesses("v=spf1 ptr:x.example ?all").len(), 2);
    }

    #[test]
    fn dmarc_records_that_are_weaker_than_they_look() {
        let zone = "example.test.";
        let agreement = |status: &str, rdata: &[&str]| Lookup {
            name: "example.test._report._dmarc.reports.example.".to_string(),
            qtype: QType::Txt,
            status: status.to_string(),
            rdata: rdata.iter().map(|r| r.to_string()).collect(),
            cname: None,
            enclosing: None,
            error: None,
        };
        let outside = "v=DMARC1; p=reject; rua=mailto:d@reports.example";
        assert!(
            dmarc_weaknesses("v=DMARC1; p=reject; rua=mailto:d@example.test", zone, &[]).is_empty()
        );
        assert!(
            dmarc_weaknesses(outside, zone, &[agreement("answer", &["\"v=DMARC1\""])]).is_empty()
        );
        let w = dmarc_weaknesses(outside, zone, &[agreement("nxdomain", &[])]);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("has not agreed"));
        // A lookup that failed is not held against the record.
        assert!(dmarc_weaknesses(outside, zone, &[agreement("failed", &[])]).is_empty());
        let w = dmarc_weaknesses("v=DMARC1; p=quarantine; sp=none; pct=20", zone, &[]);
        assert_eq!(w.len(), 3);
        // With p=none, sp and pct change nothing; POL-02 covers the policy.
        assert_eq!(
            dmarc_weaknesses(
                "v=DMARC1; p=none; sp=none; pct=20; rua=mailto:d@example.test",
                zone,
                &[]
            )
            .len(),
            0
        );
    }

    #[test]
    fn a_lookalike_is_reported_only_when_it_takes_mail() {
        let mut obs = sound();
        d(&mut obs).lookalikes = vec![
            Lookalike {
                domain: "exmaple.test.".to_string(),
                kind: "two letters swapped".to_string(),
                mx: vec!["10 mx.exmaple.test.".to_string()],
            },
            Lookalike {
                domain: "exampl.test.".to_string(),
                kind: "one letter left out".to_string(),
                mx: vec![],
            },
        ];
        let f = found(&obs, "LAL-01");
        assert_eq!(f.len(), 1);
        assert!(
            f[0].1
                .starts_with("exmaple.test. is registered and takes mail")
        );
    }

    #[test]
    fn a_light_run_makes_none_of_these_checks() {
        let obs = healthy();
        for check in [
            tko_07_subzone,
            reg_05_dependency,
            pol_11_mail_tls,
            tls_01_served_certificate,
            net_03_route_origin,
            res_01_resolver_failure,
            res_02_resolver_denies,
            blk_01_blocklisted,
            pol_12_spf_strength,
            pol_13_dmarc_strength,
            lal_01_lookalike,
        ] {
            assert!(check(&obs).is_empty());
        }
    }
}
