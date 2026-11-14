//! Collects mail and policy data for the POL and TKO checks: the apex TXT,
//! MX and CAA records, the DMARC record, the SPF include chain, the MTA-STS
//! policy file, and where mail exchangers and aliases lead.
//!
//! Lookups here go through the iterative resolver from the root, because
//! SPF includes and alias targets usually live in other people's zones.

use std::collections::{BTreeSet, VecDeque};

use super::iterate::{Resolver, printable};
use super::probe::normalise_zone;
use super::transport::{Client, HttpOutcome};
use crate::observe::{
    DkimSelector, Lookup, MailTransport, MtaSts, PolicyObservation, QType, RecordObservation,
    ServiceProbe, SpfLookup, SpfObservation, TargetResolution,
};
use crate::signatures::Signature;

/// SPF allows ten lookups; following a little past that shows by how much a
/// record overshoots without querying without end.
const MAX_SPF_LOOKUPS: usize = 30;
const MAX_SPF_DEPTH: usize = 10;
/// At most this many alias targets are resolved per run.
const MAX_TARGETS: usize = 50;

/// The text of a TXT record: its quoted strings joined, escapes undone.
pub(crate) fn txt_value(rdata: &str) -> String {
    let mut out = String::new();
    let mut in_quotes = false;
    let mut chars = rdata.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => in_quotes = !in_quotes,
            '\\' if in_quotes => {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            _ if in_quotes => out.push(c),
            _ => {}
        }
    }
    out
}

fn is_spf(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower == "v=spf1" || lower.starts_with("v=spf1 ")
}

fn spf_records(lookup: &Lookup) -> Vec<String> {
    lookup
        .rdata
        .iter()
        .map(|r| txt_value(r))
        .filter(|v| is_spf(v))
        .collect()
}

/// Follow an SPF record through its includes and redirects, noting every
/// DNS lookup a receiver would have to make.
async fn follow_spf(resolver: &Resolver, zone: &str, record: &str) -> (Vec<SpfLookup>, bool) {
    let mut lookups: Vec<SpfLookup> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::from([zone.to_string()]);
    let mut queue: VecDeque<(String, String, usize)> =
        VecDeque::from([(zone.to_string(), record.to_string(), 0)]);
    while let Some((domain, record, depth)) = queue.pop_front() {
        for term in record.split_whitespace().skip(1) {
            if lookups.len() >= MAX_SPF_LOOKUPS {
                return (lookups, true);
            }
            let term = term
                .trim_start_matches(['+', '-', '~', '?'])
                .to_ascii_lowercase();
            let (mechanism, spec) = if let Some(d) = term.strip_prefix("include:") {
                ("include", Some(d))
            } else if let Some(d) = term.strip_prefix("redirect=") {
                ("redirect", Some(d))
            } else if let Some(d) = term.strip_prefix("exists:") {
                ("exists", Some(d))
            } else if term == "ptr" || term.starts_with("ptr:") {
                ("ptr", term.strip_prefix("ptr:"))
            } else if term == "a" || term.starts_with("a:") || term.starts_with("a/") {
                ("a", term.strip_prefix("a:"))
            } else if term == "mx" || term.starts_with("mx:") || term.starts_with("mx/") {
                ("mx", term.strip_prefix("mx:"))
            } else {
                continue;
            };
            // Drop a CIDR suffix; a macro (`%{...}`) cannot be resolved here.
            let spec = spec.map(|d| d.split('/').next().unwrap_or(d));
            let target_name = match spec {
                Some(d) if !d.contains('%') => normalise_zone(d).ok(),
                Some(_) => None,
                None => Some(domain.clone()),
            };
            let shown = target_name
                .clone()
                .unwrap_or_else(|| printable(spec.unwrap_or("")));
            let mut target = None;
            if matches!(mechanism, "include" | "redirect")
                && let Some(name) = &target_name
            {
                let lookup = resolver.lookup(name, QType::Txt).await;
                if depth < MAX_SPF_DEPTH
                    && seen.insert(name.clone())
                    && let Some(next) = spf_records(&lookup).into_iter().next()
                {
                    queue.push_back((name.clone(), next, depth + 1));
                }
                target = Some(lookup);
            }
            lookups.push(SpfLookup {
                mechanism: mechanism.to_string(),
                domain: shown,
                depth,
                target,
            });
        }
    }
    (lookups, false)
}

/// Resolve what a record points at.
pub(crate) async fn resolve_target(
    resolver: &Resolver,
    owner: &str,
    rtype: &str,
    target: &str,
) -> TargetResolution {
    let lookup = resolver.lookup(target, QType::A).await;
    let has_ipv6_only =
        lookup.status == "nodata" && resolver.lookup(target, QType::Aaaa).await.status == "answer";
    TargetResolution {
        owner: owner.to_string(),
        rtype: rtype.to_string(),
        target: target.to_string(),
        lookup,
        has_ipv6_only,
    }
}

/// Why zoneblick will not fetch a page from an address, if it will not:
/// anything that is not a public address. The hosts in question are named
/// by the zone being checked, and a zone can point a name at this
/// machine, at a private network, or at a cloud metadata service.
pub fn not_public(address: std::net::IpAddr) -> Option<&'static str> {
    let unmapped = match address {
        std::net::IpAddr::V6(a) => a
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(address),
        v4 => v4,
    };
    super::transport::never_contacted(address)
        .or_else(|| crate::checks::deep::special_use(unmapped))
        .or_else(|| match unmapped {
            std::net::IpAddr::V4(a) => {
                let o = a.octets();
                // Special-purpose blocks the checks above do not name:
                // protocol assignments, benchmarking, the old 6to4 relay.
                let special = (o[0] == 192 && o[1] == 0 && o[2] == 0)
                    || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                    || (o[0] == 192 && o[1] == 88 && o[2] == 99);
                special.then_some("special-purpose")
            }
            std::net::IpAddr::V6(a) => {
                let s = a.segments();
                // Forms that carry an IPv4 address inside, which a
                // gateway turns back into a connection to that address:
                // NAT64, 6to4, Teredo, and IPv4-compatible addresses.
                let embeds_ipv4 = (s[0] == 0x0064 && s[1] == 0xff9b)
                    || s[0] == 0x2002
                    || (s[0] == 0x2001 && s[1] == 0)
                    || (s[..6].iter().all(|x| *x == 0) && (s[6] != 0 || s[7] > 1));
                embeds_ipv4.then_some("IPv4-embedding")
            }
        })
}

/// True for a name that is safe to put into a URL as its host: letters,
/// digits, hyphens, underscores and dots only, and not something that
/// reads as an IP address. Record names can hold any byte, and `/`, `@`,
/// `#` or `:` would change what the URL means.
pub fn plain_host(name: &str) -> bool {
    let name = name.trim_end_matches('.');
    !name.is_empty()
        && name.len() <= 253
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && name.parse::<std::net::IpAddr>().is_err()
        && !name
            .rsplit('.')
            .next()
            .is_some_and(|last| last.chars().all(|c| c.is_ascii_digit()) || last.starts_with("0x"))
}

/// The address to fetch a page of `host` from: resolved by zoneblick
/// itself, following aliases, and refused unless every address found is
/// public.
async fn public_address(resolver: &Resolver, host: &str) -> Result<std::net::IpAddr, String> {
    let mut name = host.to_string();
    for _ in 0..6 {
        for qtype in [QType::A, QType::Aaaa] {
            let lookup = resolver.lookup(&name, qtype).await;
            let addresses: Vec<std::net::IpAddr> =
                lookup.rdata.iter().filter_map(|r| r.parse().ok()).collect();
            if let Some((bad, why)) = addresses
                .iter()
                .find_map(|a| not_public(*a).map(|why| (a, why)))
            {
                return Err(format!("not fetched: {name} has the {why} address {bad}"));
            }
            if let Some(address) = addresses.first() {
                return Ok(*address);
            }
            if qtype == QType::A
                && let Some(next) = lookup.cname.filter(|c| *c != name)
            {
                name = next;
                break;
            }
        }
    }
    Err(format!("not fetched: no address found for {host}"))
}

async fn fetch_mta_sts(resolver: &Resolver, client: &Client, zone: &str, record: String) -> MtaSts {
    let host = zone.trim_end_matches('.');
    let policy_url = format!("https://mta-sts.{host}/.well-known/mta-sts.txt");
    let mut out = MtaSts {
        record,
        policy_url: policy_url.clone(),
        http_status: None,
        error: None,
        version: None,
        mode: None,
        max_age: None,
        mx_patterns: Vec::new(),
    };
    // A replayed run answers from its fixture and connects to nothing.
    let fetched = if !plain_host(host) {
        HttpOutcome::Error {
            message: "not fetched: the zone's name cannot be written as a web address".to_string(),
        }
    } else if client.is_live() {
        match public_address(resolver, &format!("mta-sts.{zone}")).await {
            Ok(address) => client.http_get_at(&policy_url, address).await,
            Err(message) => HttpOutcome::Error { message },
        }
    } else {
        client.http_get(&policy_url).await
    };
    match fetched {
        HttpOutcome::Error { message } => out.error = Some(printable(&message)),
        HttpOutcome::Response { status, body } => {
            out.http_status = Some(status);
            for line in body.lines() {
                let Some((key, value)) = line.split_once(':') else {
                    continue;
                };
                let value = printable(value.trim());
                match key.trim().to_ascii_lowercase().as_str() {
                    "version" => out.version = Some(value),
                    "mode" => out.mode = Some(value.to_ascii_lowercase()),
                    "max_age" => out.max_age = Some(value),
                    "mx" => out.mx_patterns.push(value.to_ascii_lowercase()),
                    _ => {}
                }
            }
        }
    }
    out
}

/// The selector names the large mail services use. A key found under one
/// of them is checked; a missing one means nothing.
pub const COMMON_DKIM_SELECTORS: [&str; 8] = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "s1",
    "s2",
    "mail",
];
/// At most this many mail servers are asked for TLSA records.
const MAX_TLSA: usize = 10;

async fn dkim_lookup(
    resolver: &Resolver,
    zone: &str,
    selector: &str,
    asked_for: bool,
) -> DkimSelector {
    let name = if zone == "." {
        format!("{selector}._domainkey.")
    } else {
        format!("{selector}._domainkey.{zone}")
    };
    DkimSelector {
        selector: selector.to_string(),
        asked_for,
        lookup: resolver.lookup(&name, QType::Txt).await,
    }
}

/// A DKIM selector as a label: letters, digits, hyphens and dots.
pub fn valid_selector(selector: &str) -> bool {
    !selector.is_empty()
        && selector.len() <= 63
        && selector
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !selector.starts_with('.')
        && !selector.ends_with('.')
}

/// Look up the DKIM keys under the selectors the user named, and mark
/// them as asked for, so a missing one is reported.
pub async fn add_dkim_selectors(
    client: std::sync::Arc<Client>,
    obs: &mut crate::observe::ZoneObservation,
    selectors: &[String],
) {
    let resolver = Resolver::new(client, obs.vantage);
    let zone = obs.zone.clone();
    let Some(policy) = &mut obs.policy else {
        return;
    };
    for selector in selectors {
        let selector = selector.to_ascii_lowercase();
        if !valid_selector(&selector) {
            continue;
        }
        let mail = policy.mail.get_or_insert_with(|| MailTransport {
            tls_rpt: unasked(&zone, "_smtp._tls"),
            bimi: unasked(&zone, "default._bimi"),
            dkim: Vec::new(),
            tlsa: Vec::new(),
        });
        match mail.dkim.iter_mut().find(|d| d.selector == selector) {
            Some(known) => known.asked_for = true,
            None => mail
                .dkim
                .push(dkim_lookup(&resolver, &zone, &selector, true).await),
        }
    }
}

/// A lookup that was not made, for a zone that takes no mail.
fn unasked(zone: &str, label: &str) -> Lookup {
    Lookup {
        name: format!("{label}.{zone}"),
        qtype: QType::Txt,
        status: "failed".to_string(),
        rdata: Vec::new(),
        cname: None,
        enclosing: None,
        error: Some("not asked: the zone has no mail servers".to_string()),
    }
}

/// Collect the apex mail and policy data of a zone.
pub(crate) async fn collect_policy(
    resolver: &Resolver,
    client: &Client,
    zone: &str,
    unresolved_ns: &[String],
) -> PolicyObservation {
    let sub = |label: &str| {
        if zone == "." {
            format!("{label}.")
        } else {
            format!("{label}.{zone}")
        }
    };
    let apex_txt = resolver.lookup(zone, QType::Txt).await;
    let dmarc = resolver.lookup(&sub("_dmarc"), QType::Txt).await;
    let caa = resolver.lookup(zone, QType::Caa).await;
    let mx = resolver.lookup(zone, QType::Mx).await;

    let records = spf_records(&apex_txt);
    let spf = match records.first() {
        None => None,
        Some(first) => {
            let (lookups, truncated) = follow_spf(resolver, zone, first).await;
            Some(SpfObservation {
                records,
                lookups,
                truncated,
            })
        }
    };

    let sts = resolver.lookup(&sub("_mta-sts"), QType::Txt).await;
    let sts_record = sts
        .rdata
        .iter()
        .map(|r| txt_value(r))
        .find(|v| v.to_ascii_lowercase().starts_with("v=stsv1"));
    let mta_sts = match sts_record {
        Some(record) => Some(fetch_mta_sts(resolver, client, zone, record).await),
        None => None,
    };

    let mut targets = Vec::new();
    for entry in &mx.rdata {
        // "10 mail.example.org."; "0 ." is a null MX: the zone takes no mail.
        let Some(target) = entry.split_whitespace().nth(1).filter(|t| *t != ".") else {
            continue;
        };
        targets.push(resolve_target(resolver, zone, "MX", target).await);
    }

    // A nameserver hostname without an address: find out whether its
    // domain still exists.
    for name in unresolved_ns {
        targets.push(resolve_target(resolver, zone, "NS", name).await);
    }

    // The wildcard itself, asked for by its literal name.
    let wildcard = if zone == "." {
        None
    } else {
        Some(resolver.lookup(&sub("*"), QType::A).await)
    };

    // Mail transport security: TLS reporting, the logo record, DKIM keys
    // under the selector names most mail services use, and TLSA records
    // for the mail servers. Only for a zone that takes mail.
    let mail = if targets.iter().any(|t| t.rtype == "MX") {
        let mut dkim = Vec::new();
        for selector in COMMON_DKIM_SELECTORS {
            dkim.push(dkim_lookup(resolver, zone, selector, false).await);
        }
        let mut tlsa = Vec::new();
        for t in targets.iter().filter(|t| t.rtype == "MX").take(MAX_TLSA) {
            tlsa.push(
                resolver
                    .lookup(&format!("_25._tcp.{}", t.target), QType::Tlsa)
                    .await,
            );
        }
        Some(MailTransport {
            tls_rpt: resolver.lookup(&sub("_smtp._tls"), QType::Txt).await,
            bimi: resolver.lookup(&sub("default._bimi"), QType::Txt).await,
            dkim,
            tlsa,
        })
    } else {
        None
    };

    PolicyObservation {
        mail,
        services: Vec::new(),
        wildcard,
        apex_txt,
        dmarc,
        caa,
        mx,
        spf,
        mta_sts,
        targets,
    }
}

/// Resolve the target of every CNAME a stored run collected.
pub(crate) async fn cname_targets(
    resolver: &Resolver,
    records: &[RecordObservation],
) -> Vec<TargetResolution> {
    let mut pairs: BTreeSet<(String, String)> = BTreeSet::new();
    for rec in records.iter().filter(|r| r.qtype == QType::Cname) {
        if let Some(answer) = rec.outcome.answer().filter(|a| a.authoritative) {
            for target in &answer.rdata {
                pairs.insert((rec.name.clone(), target.clone()));
            }
        }
    }
    let mut out = Vec::new();
    for (owner, target) in pairs.into_iter().take(MAX_TARGETS) {
        out.push(resolve_target(resolver, &owner, "CNAME", &target).await);
    }
    out
}

/// Resolve what the SRV, HTTPS, SVCB and PTR records of a stored run
/// point at. A target of `.` means "no service here" (SRV) or "this name
/// itself" (HTTPS, SVCB), and is left alone. For a PTR record the lookup
/// is for the address family of the reverse zone, so the answer can be
/// compared with the address the record's own name stands for.
pub(crate) async fn service_targets(
    resolver: &Resolver,
    records: &[RecordObservation],
) -> Vec<TargetResolution> {
    let mut wanted: BTreeSet<(String, &'static str, String)> = BTreeSet::new();
    for rec in records {
        let (rtype, field) = match rec.qtype {
            QType::Srv => ("SRV", 3),
            QType::Https => ("HTTPS", 1),
            QType::Svcb => ("SVCB", 1),
            QType::Ptr => ("PTR", 0),
            _ => continue,
        };
        let Some(answer) = rec.outcome.answer().filter(|a| a.authoritative) else {
            continue;
        };
        for rdata in &answer.rdata {
            let Some(target) = rdata.split_whitespace().nth(field) else {
                continue;
            };
            if target == "." {
                continue;
            }
            if let Ok(target) = normalise_zone(target) {
                wanted.insert((rec.name.clone(), rtype, target));
            }
        }
    }
    let mut out = Vec::new();
    for (owner, rtype, target) in wanted.into_iter().take(MAX_TARGETS) {
        if rtype == "PTR" && owner.ends_with(".ip6.arpa.") {
            out.push(TargetResolution {
                lookup: resolver.lookup(&target, QType::Aaaa).await,
                owner,
                rtype: rtype.to_string(),
                target,
                has_ipv6_only: false,
            });
        } else {
            out.push(resolve_target(resolver, &owner, rtype, &target).await);
        }
    }
    out
}

/// At most this many hostnames are fetched per run.
const MAX_SERVICE_PROBES: usize = 20;

/// For every alias that points at a known hosting service and resolves,
/// fetch the hostname's front page once and see whether the service says
/// that nobody has claimed the site. Nothing else is sent.
pub(crate) async fn service_probes(
    resolver: &Resolver,
    client: &Client,
    targets: &[TargetResolution],
) -> Vec<ServiceProbe> {
    let mut out = Vec::new();
    for t in targets
        .iter()
        .filter(|t| t.rtype == "CNAME" && (t.lookup.exists() || t.has_ipv6_only))
    {
        // The service is named by the alias target, or by what that is
        // itself an alias of.
        let Some((target, signature)) = [Some(&t.target), t.lookup.cname.as_ref()]
            .into_iter()
            .flatten()
            .find_map(|name| Signature::for_target(name).map(|s| (name, s)))
        else {
            continue;
        };
        if out.len() >= MAX_SERVICE_PROBES {
            break;
        }
        let url = format!("http://{}/", t.owner.trim_end_matches('.'));
        let mut probe = ServiceProbe {
            owner: t.owner.clone(),
            target: target.clone(),
            service: signature.service.to_string(),
            url: url.clone(),
            status: None,
            error: None,
            unclaimed: false,
        };
        let fetched = if !plain_host(&t.owner) {
            HttpOutcome::Error {
                message: "not fetched: the name cannot be written as a web address".to_string(),
            }
        } else if client.is_live() {
            match public_address(resolver, &t.target).await {
                Ok(address) => client.http_get_at(&url, address).await,
                Err(message) => HttpOutcome::Error { message },
            }
        } else {
            client.http_get(&url).await
        };
        match fetched {
            HttpOutcome::Error { message } => probe.error = Some(printable(&message)),
            HttpOutcome::Response { status, body } => {
                probe.status = Some(status);
                probe.unclaimed = signature.matches(status, &body);
            }
        }
        out.push(probe);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_values() {
        assert_eq!(txt_value(r#""v=spf1 -all""#), "v=spf1 -all");
        assert_eq!(
            txt_value(r#""v=spf1 include:a.example " "-all""#),
            "v=spf1 include:a.example -all"
        );
        assert_eq!(txt_value(r#""say \"hi\" \\ there""#), r#"say "hi" \ there"#);
        assert!(
            is_spf("v=spf1 -all") && is_spf("V=SPF1") && !is_spf("v=spf10 x") && !is_spf("spf")
        );
    }
}
