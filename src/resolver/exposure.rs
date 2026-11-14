//! The deep probes that look past the zone's own nameservers: at names it
//! delegates away, at the domains it depends on, at what its mail and web
//! servers present over TLS, at the routes to its nameservers, at what
//! public resolvers say about it, at blocklists, and at domains that look
//! like it.
//!
//! Most of these name the zone, or addresses it uses, to a third party
//! (a registry, RIPE, a public resolver, a blocklist), so they run only
//! as part of a deep run.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RData;
use tokio::task::JoinSet;

use super::iterate::{Resolver, norm, parse_response, printable, rcode_name};
use super::policy::{not_public, txt_value};
use super::probe::responding_servers;
use super::transport::{Client, HttpOutcome, QuerySpec, RawOutcome};
use crate::observe::{
    BlocklistLookup, DeepObservation, Dependency, Lookalike, Lookup, Probe, QType, ResolverView,
    RouteOrigin, ServedTls, Subzone, SubzoneServer, Transport, ZoneObservation,
    is_ancestor_or_equal, parent_name,
};

/// Limits, so that a zone with thousands of names cannot turn a deep run
/// into thousands of connections.
const MAX_SUBZONE_CANDIDATES: usize = 60;
const MAX_SUBZONES: usize = 10;
const MAX_SUBZONE_SERVERS: usize = 6;
const MAX_DEPENDENCIES: usize = 6;
const MAX_MAIL_SERVERS: usize = 5;
const MAX_WEB_NAMES: usize = 20;
const MAX_ROUTES: usize = 8;
const MAX_BLOCKLIST_ADDRESSES: usize = 10;
const MAX_REPORT_DOMAINS: usize = 4;
const MAX_LOOKALIKES: usize = 60;

/// How long each probe may take. A name in the zone, or a lookalike
/// domain somebody registered for the purpose, can lead a lookup through
/// a long chain of servers that never answer; without a limit one such
/// name would hold up everything after it.
const SUBZONE_SECONDS: u64 = 40;
const REPORT_SECONDS: u64 = 15;
const BLOCKLIST_SECONDS: u64 = 25;
const LOOKALIKE_SECONDS: u64 = 45;
const RESOLVER_SECONDS: u64 = 15;
const ROUTE_SECONDS: u64 = 25;
const DEPENDENCY_SECONDS: u64 = 30;
const TLS_SECONDS: u64 = 90;
/// All of them together, whatever the single limits add up to.
pub const TOTAL_SECONDS: u64 = 300;

/// Values quoted from an answer someone else controls: at most this
/// many, each cut to this length (the rule from the second audit).
const MAX_QUOTED_VALUES: usize = 20;
const MAX_QUOTED_LENGTH: usize = 200;

/// Keep a list of values from outside to a size fit to store and show.
pub fn clip(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .take(MAX_QUOTED_VALUES)
        .map(|v| {
            if v.chars().count() > MAX_QUOTED_LENGTH {
                let cut: String = v.chars().take(MAX_QUOTED_LENGTH).collect();
                format!("{cut}...")
            } else {
                v
            }
        })
        .collect()
}

/// Run one probe for at most `seconds`. What it had put into its output
/// by then is kept.
async fn within(seconds: u64, probe: impl std::future::Future<Output = ()>) {
    let _ = tokio::time::timeout(Duration::from_secs(seconds), probe).await;
}

/// Run the probes and put what they find into `deep`. Each has its own
/// time limit and fills its own part, so one that is held up costs only
/// its own result.
pub async fn add_exposure(client: &Arc<Client>, obs: &ZoneObservation, deep: &mut DeepObservation) {
    let resolver = Resolver::new(client.clone(), obs.vantage);
    within(
        SUBZONE_SECONDS,
        subzones(&resolver, obs, &mut deep.subzones),
    )
    .await;
    within(
        REPORT_SECONDS,
        dmarc_reports(&resolver, obs, &mut deep.dmarc_reports),
    )
    .await;
    within(
        BLOCKLIST_SECONDS,
        blocklists(&resolver, obs, &mut deep.blocklists),
    )
    .await;
    within(
        LOOKALIKE_SECONDS,
        lookalikes(&resolver, obs, &mut deep.lookalikes),
    )
    .await;
    within(
        RESOLVER_SECONDS,
        resolvers(client, obs, &mut deep.resolvers),
    )
    .await;
    let origins = deep.origins.clone();
    within(ROUTE_SECONDS, routes(client, &origins, &mut deep.routes)).await;
    let own = deep.registration.as_ref().map(|r| r.domain.clone());
    within(
        DEPENDENCY_SECONDS,
        dependencies(client, obs, own, &mut deep.dependencies),
    )
    .await;
    within(
        TLS_SECONDS,
        served_tls(client, &resolver, obs, &mut deep.served_tls),
    )
    .await;
}

// ---------------------------------------------------------------------
// Delegated names

/// The names to ask about: every name the run collected records for, and
/// every name between it and the zone.
fn subzone_candidates(obs: &ZoneObservation) -> Vec<String> {
    let mut out = BTreeSet::new();
    for record in &obs.records {
        let mut name = record.name.as_str();
        while name != obs.zone && name != "." && is_ancestor_or_equal(&obs.zone, name) {
            if !name.starts_with('*') {
                out.insert(name.to_string());
            }
            name = parent_name(name);
        }
    }
    out.into_iter().take(MAX_SUBZONE_CANDIDATES).collect()
}

/// Find the names the zone hands to other nameservers, and ask each of
/// those nameservers whether it serves the name.
async fn subzones(resolver: &Resolver, obs: &ZoneObservation, out: &mut Vec<Subzone>) {
    let Some((_, server)) = responding_servers(&obs.probes)
        .into_iter()
        .find(|(_, a)| obs.vantage.can_reach(a))
    else {
        return;
    };
    let mut cuts: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for name in subzone_candidates(obs) {
        // A name under a cut already found belongs to that subzone.
        if cuts.keys().any(|cut| is_ancestor_or_equal(cut, &name)) {
            continue;
        }
        let Ok(msg) = resolver.ask(server, &name, QType::Ns).await else {
            continue;
        };
        if msg.metadata.response_code != ResponseCode::NoError {
            continue;
        }
        // A delegation shows as NS records in the authority part of an
        // answer that is not authoritative, or, when the same servers
        // hold both zones, as an NS answer at the name.
        let records = if msg.metadata.authoritative {
            &msg.answers
        } else {
            &msg.authorities
        };
        // One answer can carry NS records under many owner names. Only
        // the delegation nearest the zone is real (what lies below it is
        // the other servers' business), so one answer gives one cut.
        let mut nearest: Option<String> = None;
        for record in records {
            if let RData::NS(_) = &record.data {
                let owner = norm(&record.name);
                if owner != obs.zone
                    && is_ancestor_or_equal(&obs.zone, &owner)
                    && is_ancestor_or_equal(&owner, &name)
                    && nearest.as_ref().is_none_or(|n| owner.len() < n.len())
                {
                    nearest = Some(owner);
                }
            }
        }
        let Some(cut) = nearest else {
            continue;
        };
        if cuts.len() >= MAX_SUBZONES && !cuts.contains_key(&cut) {
            break;
        }
        let servers = cuts.entry(cut.clone()).or_default();
        for record in records {
            if let RData::NS(target) = &record.data
                && norm(&record.name) == cut
                && servers.len() < MAX_SUBZONE_SERVERS
            {
                servers.insert(norm(&target.0));
            }
        }
    }
    for (name, ns) in cuts {
        let mut servers = Vec::new();
        for ns_name in ns.into_iter().take(MAX_SUBZONE_SERVERS) {
            servers.push(subzone_server(resolver, obs, &name, ns_name).await);
        }
        out.push(Subzone { name, servers });
    }
}

async fn subzone_server(
    resolver: &Resolver,
    obs: &ZoneObservation,
    subzone: &str,
    ns_name: String,
) -> SubzoneServer {
    let mut out = SubzoneServer {
        ns_name: ns_name.clone(),
        address: None,
        status: "no_address".to_string(),
        detail: None,
    };
    let mut lookup = resolver.lookup(&ns_name, QType::A).await;
    if let Some(domain) = lookup.unregistered_domain() {
        out.status = "unregistered".to_string();
        out.detail = Some(domain);
        return out;
    }
    if lookup.rdata.is_empty() && obs.vantage.ipv6 {
        lookup = resolver.lookup(&ns_name, QType::Aaaa).await;
    }
    let Some(address) = lookup
        .rdata
        .iter()
        .filter_map(|r| r.parse::<IpAddr>().ok())
        .find(|a| obs.vantage.can_reach(a) && not_public(*a).is_none())
    else {
        if lookup.status == "failed" {
            out.status = "silent".to_string();
            out.detail = lookup.error.map(|e| printable(&e));
        }
        return out;
    };
    out.address = Some(address);
    match resolver.ask(address, subzone, QType::Soa).await {
        Ok(msg)
            if msg.metadata.authoritative
                && msg.metadata.response_code == ResponseCode::NoError =>
        {
            out.status = "authoritative".to_string();
        }
        Ok(msg) => {
            out.status = "refused".to_string();
            out.detail = Some(match msg.metadata.response_code {
                ResponseCode::NoError => "answered without authority".to_string(),
                other => rcode_name(other),
            });
        }
        Err(e) => {
            out.status = "silent".to_string();
            out.detail = Some(printable(&e));
        }
    }
    out
}

// ---------------------------------------------------------------------
// DMARC report destinations

/// The domains a DMARC record sends reports to (`rua` and `ruf`).
pub fn report_domains(record: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for part in record.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        if !matches!(key.trim().to_ascii_lowercase().as_str(), "rua" | "ruf") {
            continue;
        }
        for uri in value.split(',') {
            let uri = uri.trim();
            let Some(address) = uri
                .get(..7)
                .filter(|scheme| scheme.eq_ignore_ascii_case("mailto:"))
                .map(|_| &uri[7..])
            else {
                continue;
            };
            // A size limit may follow the address: `mailto:a@b.example!10m`.
            let address = address.split('!').next().unwrap_or(address);
            if let Some((_, domain)) = address.rsplit_once('@')
                && let Ok(domain) = super::normalise_zone(domain)
            {
                out.insert(domain);
            }
        }
    }
    out.into_iter().collect()
}

/// The zone's DMARC record, when it has one.
pub fn dmarc_record(obs: &ZoneObservation) -> Option<String> {
    obs.policy
        .as_ref()?
        .dmarc
        .rdata
        .iter()
        .map(|r| txt_value(r))
        .find(|v| v.to_ascii_lowercase().starts_with("v=dmarc1"))
}

/// A domain that receives another domain's DMARC reports must say so in
/// a record of its own (RFC 7489, 7.1). Look that record up for every
/// destination outside the zone.
async fn dmarc_reports(resolver: &Resolver, obs: &ZoneObservation, out: &mut Vec<Lookup>) {
    let Some(record) = dmarc_record(obs) else {
        return;
    };
    for domain in report_domains(&record)
        .into_iter()
        .filter(|d| !is_ancestor_or_equal(&obs.zone, d) && !is_ancestor_or_equal(d, &obs.zone))
        .take(MAX_REPORT_DOMAINS)
    {
        let name = format!("{}_report._dmarc.{domain}", obs.zone);
        let mut lookup = resolver.lookup(&name, QType::Txt).await;
        lookup.rdata = clip(lookup.rdata);
        out.push(lookup);
    }
}

// ---------------------------------------------------------------------
// Blocklists

/// The lists asked about an address, and the one asked about the domain.
pub const ADDRESS_BLOCKLISTS: [&str; 2] = ["zen.spamhaus.org.", "bl.spamcop.net."];
pub const DOMAIN_BLOCKLIST: &str = "dbl.spamhaus.org.";

/// The single IPv4 addresses an SPF record allows to send (`ip4:` with no
/// prefix length, or `/32`).
pub fn spf_addresses(record: &str) -> Vec<std::net::Ipv4Addr> {
    record
        .split_whitespace()
        .filter_map(|term| {
            let term = term.trim_start_matches('+');
            let value = term
                .get(..4)
                .filter(|k| k.eq_ignore_ascii_case("ip4:"))
                .map(|_| &term[4..])?;
            let address = value.strip_suffix("/32").unwrap_or(value);
            address.parse().ok()
        })
        .collect()
}

/// The addresses mail for or from the zone uses, with where each comes
/// from: its mail servers, and single addresses in its SPF record.
fn mail_addresses(obs: &ZoneObservation) -> Vec<(std::net::Ipv4Addr, String)> {
    let Some(policy) = &obs.policy else {
        return Vec::new();
    };
    let mut out: Vec<(std::net::Ipv4Addr, String)> = Vec::new();
    let mut add = |address: std::net::Ipv4Addr, role: String| {
        if not_public(IpAddr::V4(address)).is_some() {
            return;
        }
        // An address can be a mail server and a sender at once; both
        // count, since some lists matter only for senders.
        match out.iter_mut().find(|(a, _)| *a == address) {
            Some((_, roles)) if !roles.contains(&role) => {
                roles.push_str(" and ");
                roles.push_str(&role);
            }
            Some(_) => {}
            None => out.push((address, role)),
        }
    };
    for target in policy.targets.iter().filter(|t| t.rtype == "MX") {
        for address in target.lookup.rdata.iter().filter_map(|r| r.parse().ok()) {
            add(address, format!("mail server {}", target.target));
        }
    }
    for record in policy.spf.iter().flat_map(|s| &s.records) {
        for address in spf_addresses(record) {
            add(address, "SPF record".to_string());
        }
    }
    out.truncate(MAX_BLOCKLIST_ADDRESSES);
    out
}

/// Read a blocklist's answer. Lists answer `127.0.x.y` for a listing;
/// Spamhaus answers `127.255.255.x` when it refuses the query itself,
/// which says nothing about the subject.
pub fn blocklist_answer(lookup: &Lookup) -> (Vec<String>, Option<String>) {
    match lookup.status.as_str() {
        "answer" => {
            let codes: Vec<String> = lookup
                .rdata
                .iter()
                .filter(|r| r.starts_with("127.") && r.parse::<std::net::Ipv4Addr>().is_ok())
                .cloned()
                .collect();
            if codes.iter().any(|c| c.starts_with("127.255.255.")) {
                (Vec::new(), Some("the list refused the query".to_string()))
            } else {
                (codes.into_iter().take(8).collect(), None)
            }
        }
        "nxdomain" | "nodata" => (Vec::new(), None),
        _ => (
            Vec::new(),
            Some(printable(
                lookup.error.as_deref().unwrap_or("the list did not answer"),
            )),
        ),
    }
}

async fn blocklists(resolver: &Resolver, obs: &ZoneObservation, out: &mut Vec<BlocklistLookup>) {
    for (address, role) in mail_addresses(obs) {
        let o = address.octets();
        for list in ADDRESS_BLOCKLISTS {
            let name = format!("{}.{}.{}.{}.{list}", o[3], o[2], o[1], o[0]);
            let (codes, error) = blocklist_answer(&resolver.lookup(&name, QType::A).await);
            out.push(BlocklistLookup {
                subject: address.to_string(),
                role: role.clone(),
                list: list.to_string(),
                codes,
                error,
            });
        }
    }
    // The domain itself, when it sends or receives mail at all.
    if obs
        .policy
        .as_ref()
        .is_some_and(|p| p.mx.exists() || p.spf.is_some())
    {
        let name = format!("{}{DOMAIN_BLOCKLIST}", obs.zone);
        let (codes, error) = blocklist_answer(&resolver.lookup(&name, QType::A).await);
        out.push(BlocklistLookup {
            subject: obs.zone.clone(),
            role: "the domain".to_string(),
            list: DOMAIN_BLOCKLIST.to_string(),
            codes,
            error,
        });
    }
}

// ---------------------------------------------------------------------
// Lookalike domains

/// Names that look like `label`: one letter left out, two neighbours
/// swapped, one letter doubled, and letters replaced by ones that look
/// the same. Each comes with how it differs. The order is fixed.
pub fn lookalike_labels(label: &str) -> Vec<(String, &'static str)> {
    let chars: Vec<char> = label.chars().collect();
    let mut out: Vec<(String, &'static str)> = Vec::new();
    let mut add = |candidate: String, kind: &'static str| {
        let valid = !candidate.is_empty()
            && candidate != label
            && !candidate.starts_with('-')
            && !candidate.ends_with('-')
            && candidate
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-');
        if valid && !out.iter().any(|(c, _)| *c == candidate) {
            out.push((candidate, kind));
        }
    };
    if chars.len() < 3 || !label.is_ascii() {
        return out;
    }
    const ALIKE: [(&str, &str); 10] = [
        ("o", "0"),
        ("0", "o"),
        ("l", "1"),
        ("1", "l"),
        ("i", "1"),
        ("i", "l"),
        ("l", "i"),
        ("m", "rn"),
        ("rn", "m"),
        ("w", "vv"),
    ];
    for (from, to) in ALIKE {
        for (at, _) in label.match_indices(from) {
            add(
                format!("{}{to}{}", &label[..at], &label[at + from.len()..]),
                "a letter replaced by one that looks alike",
            );
        }
    }
    for i in 0..chars.len() {
        let mut c = chars.clone();
        c.remove(i);
        add(c.into_iter().collect(), "one letter left out");
    }
    for i in 0..chars.len() - 1 {
        let mut c = chars.clone();
        c.swap(i, i + 1);
        add(c.into_iter().collect(), "two letters swapped");
    }
    for i in 0..chars.len() {
        let mut c = chars.clone();
        c.insert(i, chars[i]);
        add(c.into_iter().collect(), "one letter doubled");
    }
    out
}

/// The domains to look for: lookalikes of the zone's first label under
/// the same parent, and the same label under a few other common endings.
pub fn lookalike_candidates(zone: &str) -> Vec<(String, &'static str)> {
    let parent = parent_name(zone);
    if parent == "." {
        return Vec::new();
    }
    let label = &zone[..zone.len() - parent.len() - 1];
    let mut out: Vec<(String, &'static str)> = lookalike_labels(label)
        .into_iter()
        .map(|(l, kind)| (format!("{l}.{parent}"), kind))
        .collect();
    // Another ending only makes sense for a name directly under one.
    if parent.matches('.').count() == 1 && label.len() >= 3 {
        for other in ["com.", "net.", "org.", "co.", "io."] {
            if other != parent {
                out.push((
                    format!("{label}.{other}"),
                    "the same name under another ending",
                ));
            }
        }
    }
    out.truncate(MAX_LOOKALIKES);
    out
}

/// Which lookalikes are registered, and whether they take mail.
async fn lookalikes(resolver: &Resolver, obs: &ZoneObservation, out: &mut Vec<Lookalike>) {
    for (domain, kind) in lookalike_candidates(&obs.zone) {
        let ns = resolver.lookup(&domain, QType::Ns).await;
        if !ns.exists() {
            continue;
        }
        let mx = resolver.lookup(&domain, QType::Mx).await;
        // A "null MX" (RFC 7505) says the domain takes no mail.
        let mx: Vec<String> = mx
            .rdata
            .into_iter()
            .filter(|r| r.split_whitespace().nth(1) != Some("."))
            .collect();
        // The lookalike's owner writes these records; a few are enough.
        let mut mx = clip(mx);
        mx.truncate(5);
        out.push(Lookalike {
            domain,
            kind: kind.to_string(),
            mx,
        });
    }
}

// ---------------------------------------------------------------------
// Public resolvers

/// The public resolvers asked, with who runs each.
pub const PUBLIC_RESOLVERS: [(&str, [u8; 4]); 3] = [
    ("Cloudflare", [1, 1, 1, 1]),
    ("Google", [8, 8, 8, 8]),
    ("Quad9", [9, 9, 9, 9]),
];

async fn ask_resolver(
    client: &Client,
    address: IpAddr,
    zone: &str,
    probe: Probe,
) -> Result<String, String> {
    let spec = QuerySpec {
        server: address,
        transport: Transport::Udp,
        qname: zone.to_string(),
        qtype: QType::Soa,
        edns: true,
        dnssec: false,
        probe,
    };
    match client.exchange(&spec).await {
        RawOutcome::Response { wire } => {
            parse_response(&spec, &wire).map(|msg| rcode_name(msg.metadata.response_code))
        }
        RawOutcome::Timeout => Err("timeout".to_string()),
        RawOutcome::NetError { message } => Err(message),
    }
}

/// Ask each public resolver for the zone's SOA record, as any user's
/// computer would. After a SERVFAIL, ask again with validation switched
/// off: an answer then means the resolver rejects the zone's DNSSEC.
async fn resolvers(client: &Client, obs: &ZoneObservation, out: &mut Vec<ResolverView>) {
    if !obs.vantage.ipv4 {
        return;
    }
    for (operator, octets) in PUBLIC_RESOLVERS {
        let address = IpAddr::from(octets);
        let mut view = ResolverView {
            operator: operator.to_string(),
            address,
            rcode: None,
            rcode_unvalidated: None,
            error: None,
        };
        match ask_resolver(client, address, &obs.zone, Probe::Recursion).await {
            Ok(rcode) => {
                if rcode == "SERVFAIL" {
                    view.rcode_unvalidated =
                        ask_resolver(client, address, &obs.zone, Probe::RecursionUnvalidated)
                            .await
                            .ok();
                }
                view.rcode = Some(rcode);
            }
            Err(e) => view.error = Some(printable(&e)),
        }
        out.push(view);
    }
}

// ---------------------------------------------------------------------
// Route origins

/// RIPE's public service that says whether an announcement is covered by
/// a route origin authorisation.
pub fn route_url(asn: u32, prefix: &str) -> String {
    format!(
        "https://stat.ripe.net/data/rpki-validation/data.json?resource=AS{asn}&prefix={prefix}&sourceapp=zoneblick"
    )
}

/// Read the `status` of an answer from that service.
pub fn parse_route_status(body: &str) -> Result<String, String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|_| "the answer is not JSON".to_string())?;
    let status = value["data"]["status"]
        .as_str()
        .unwrap_or("")
        .to_ascii_lowercase();
    match status.as_str() {
        "valid" | "invalid_asn" | "invalid_length" | "unknown" => Ok(status),
        _ => Err("the answer names no known status".to_string()),
    }
}

async fn routes(
    client: &Client,
    origins: &[crate::observe::AddressOrigin],
    out: &mut Vec<RouteOrigin>,
) {
    let mut seen: BTreeMap<(String, u32), Vec<IpAddr>> = BTreeMap::new();
    for origin in origins {
        // An address announced by several networks at once is left out:
        // there is no single origin to judge.
        if let (Some(prefix), [asn]) = (&origin.prefix, origin.asns.as_slice()) {
            seen.entry((prefix.clone(), *asn))
                .or_default()
                .push(origin.address);
        }
    }
    for ((prefix, asn), addresses) in seen.into_iter().take(MAX_ROUTES) {
        let (status, error) = match client
            .http_get_with(
                &route_url(asn, &prefix),
                256 * 1024,
                Duration::from_secs(15),
            )
            .await
        {
            HttpOutcome::Response { status: 200, body } => match parse_route_status(&body) {
                Ok(status) => (Some(status), None),
                Err(e) => (None, Some(e)),
            },
            HttpOutcome::Response { status, .. } => (None, Some(format!("HTTP {status}"))),
            HttpOutcome::Error { message } => (None, Some(printable(&message))),
        };
        out.push(RouteOrigin {
            prefix,
            asn,
            addresses,
            status,
            error,
        });
    }
}

// ---------------------------------------------------------------------
// The domains the zone depends on

/// The last `labels` labels of a name, when it has that many.
fn suffix(name: &str, labels: usize) -> Option<String> {
    let parts: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    (parts.len() >= labels && !parts.contains(&""))
        .then(|| format!("{}.", parts[parts.len() - labels..].join(".")))
}

/// The hosts the zone needs that are outside it, with what each is.
fn outside_hosts(obs: &ZoneObservation) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for host in &obs.ns_hosts {
        out.push((host.name.clone(), format!("nameserver {}", host.name)));
    }
    if let Some(policy) = &obs.policy {
        for target in policy.targets.iter().filter(|t| t.rtype == "MX") {
            out.push((
                target.target.clone(),
                format!("mail server {}", target.target),
            ));
        }
    }
    // A name with anything but letters, digits, hyphens and dots is left
    // out: it goes into the address of a request to the registry, where
    // a "?" or "/" would change what is asked.
    out.retain(|(name, _)| {
        !is_ancestor_or_equal(&obs.zone, name) && super::policy::plain_host(name)
    });
    out
}

/// Ask the registry about each domain the zone's nameservers and mail
/// servers are in, other than the zone's own.
async fn dependencies(
    client: &Client,
    obs: &ZoneObservation,
    own: Option<String>,
    out: &mut Vec<Dependency>,
) {
    // Grouped by the last two labels: one registry question per group.
    let mut groups: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for (name, role) in outside_hosts(obs) {
        let Some(key) = suffix(&name, 2) else {
            continue;
        };
        if own
            .as_deref()
            .is_some_and(|own| is_ancestor_or_equal(own, &name))
        {
            continue;
        }
        let entry = groups
            .entry(key)
            .or_insert_with(|| (name.clone(), Vec::new()));
        if !entry.1.contains(&role) {
            entry.1.push(role);
        }
    }
    for (key, (name, used_by)) in groups.into_iter().take(MAX_DEPENDENCIES) {
        // `example.net.` first; under an ending such as `co.uk.` the
        // registry has no record of that, and the next name is tried.
        let mut candidates = vec![key];
        candidates.extend(suffix(&name, 3));
        if let Some(registration) =
            crate::registration::collect_candidates(client, &candidates).await
        {
            out.push(Dependency {
                used_by,
                registration,
            });
        }
    }
}

// ---------------------------------------------------------------------
// What the mail and web servers present over TLS

/// The names that may be web sites: the zone, and every collected name
/// that has an address or is an alias.
fn web_names(obs: &ZoneObservation) -> Vec<String> {
    let mut out = BTreeSet::from([obs.zone.clone()]);
    for record in &obs.records {
        if matches!(record.qtype, QType::A | QType::Aaaa | QType::Cname)
            && !record.name.starts_with(['_', '*'])
            && !record.name.contains("._")
            && record.outcome.answer().is_some_and(|a| !a.rdata.is_empty())
        {
            out.insert(record.name.clone());
        }
    }
    out.into_iter().take(MAX_WEB_NAMES).collect()
}

fn tls_entry(role: &str, host: &str) -> ServedTls {
    ServedTls {
        role: role.to_string(),
        host: host.to_string(),
        address: None,
        starttls: None,
        not_after_unix: None,
        names: Vec::new(),
        error: None,
    }
}

/// Fill an entry from what a connection attempt gave.
fn read_chain(entry: &mut ServedTls, result: Result<Vec<Vec<u8>>, String>) {
    match result {
        Ok(chain) => {
            if entry.role == "mail" {
                entry.starttls = Some(true);
            }
            match chain.first().and_then(|c| super::smtp::certificate_info(c)) {
                Some(info) => {
                    entry.not_after_unix = Some(info.not_after_unix);
                    entry.names = info.names;
                }
                None => entry.error = Some("the certificate could not be read".to_string()),
            }
        }
        Err(e) if e == super::smtp::NO_STARTTLS => entry.starttls = Some(false),
        Err(e) => entry.error = Some(printable(&e)),
    }
}

/// Connect to each mail server and each web name, start TLS, and note
/// when the certificate runs out and which names it is for. Only a live
/// run does this, and only to public addresses. No mail is sent and no
/// page is asked for.
async fn served_tls(
    client: &Client,
    resolver: &Resolver,
    obs: &ZoneObservation,
    out: &mut Vec<ServedTls>,
) {
    if !client.is_live() {
        return;
    }
    let mut targets: Vec<(ServedTls, u16)> = Vec::new();
    if let Some(policy) = &obs.policy {
        let mut seen = BTreeSet::new();
        for target in policy.targets.iter().filter(|t| t.rtype == "MX") {
            if seen.len() >= MAX_MAIL_SERVERS || !seen.insert(target.target.clone()) {
                continue;
            }
            let mut entry = tls_entry("mail", &target.target);
            entry.address = target
                .lookup
                .rdata
                .iter()
                .filter_map(|r| r.parse::<IpAddr>().ok())
                .find(|a| obs.vantage.can_reach(a));
            targets.push((entry, 25));
        }
    }
    for name in web_names(obs) {
        let mut entry = tls_entry("web", &name);
        // The address a visitor would reach: aliases are followed, and
        // only a public address is connected to.
        match super::policy::public_address(resolver, &name).await {
            Ok(address) if obs.vantage.can_reach(&address) => entry.address = Some(address),
            Ok(_) => entry.error = Some("not reachable from here".to_string()),
            Err(e) => entry.error = Some(printable(&e)),
        }
        targets.push((entry, 443));
    }
    let mut tasks = JoinSet::new();
    for (mut entry, port) in targets {
        let Some(address) = entry.address else {
            entry
                .error
                .get_or_insert_with(|| "no address is known".to_string());
            out.push(entry);
            continue;
        };
        if let Some(why) = not_public(address) {
            entry.error = Some(format!("not connected to: {address} is a {why} address"));
            out.push(entry);
            continue;
        }
        tasks.spawn(async move {
            let host = entry.host.clone();
            let read = tokio::task::spawn_blocking(move || {
                let addr = SocketAddr::new(address, port);
                if port == 25 {
                    super::smtp::starttls_certificates(addr, &host)
                } else {
                    super::smtp::tls_certificates(addr, &host)
                }
            });
            match tokio::time::timeout(Duration::from_secs(45), read).await {
                Ok(Ok(result)) => read_chain(&mut entry, result),
                Ok(Err(_)) => entry.error = Some("the connection attempt stopped".to_string()),
                Err(_) => entry.error = Some("timed out".to_string()),
            }
            entry
        });
    }
    while let Some(joined) = tasks.join_next().await {
        if let Ok(entry) = joined {
            out.push(entry);
        }
    }
    out.sort_by(|a, b| (&a.role, &a.host).cmp(&(&b.role, &b.host)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_destinations_are_read_from_a_dmarc_record() {
        assert_eq!(
            report_domains(
                "v=DMARC1; p=reject; rua=mailto:a@Reports.example, mailto:b@example.org!10m; ruf=MAILTO:c@x.example"
            ),
            ["example.org.", "reports.example.", "x.example."]
        );
        assert!(report_domains("v=DMARC1; p=none").is_empty());
        assert!(report_domains("v=DMARC1; rua=https://x.example/r").is_empty());
        assert!(report_domains("v=DMARC1; rua=mailto:nobody").is_empty());
    }

    #[test]
    fn single_addresses_are_read_from_an_spf_record() {
        assert_eq!(
            spf_addresses(
                "v=spf1 ip4:192.0.2.1 +IP4:192.0.2.2/32 ip4:198.51.100.0/24 ip6:2001:db8::1 include:x.example -all"
            ),
            [
                "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap(),
                "192.0.2.2".parse().unwrap()
            ]
        );
        assert!(spf_addresses("v=spf1 ip4:nonsense -all").is_empty());
    }

    #[test]
    fn a_blocklist_answer_is_a_listing_only_in_the_listing_range() {
        let lookup = |status: &str, rdata: &[&str]| Lookup {
            name: "x".to_string(),
            qtype: QType::A,
            status: status.to_string(),
            rdata: rdata.iter().map(|r| r.to_string()).collect(),
            cname: None,
            enclosing: None,
            error: None,
        };
        assert_eq!(
            blocklist_answer(&lookup("answer", &["127.0.0.2", "127.0.0.4"])),
            (vec!["127.0.0.2".to_string(), "127.0.0.4".to_string()], None)
        );
        assert_eq!(blocklist_answer(&lookup("nxdomain", &[])), (vec![], None));
        // Spamhaus refusing the query is not a listing.
        let (codes, error) = blocklist_answer(&lookup("answer", &["127.255.255.254"]));
        assert!(codes.is_empty() && error.is_some());
        // An answer outside 127/8 is not a listing either.
        assert_eq!(
            blocklist_answer(&lookup("answer", &["192.0.2.1"])),
            (vec![], None)
        );
        assert!(blocklist_answer(&lookup("failed", &[])).1.is_some());
    }

    #[test]
    fn lookalikes_are_made_in_a_fixed_order_and_stay_valid_names() {
        let all = lookalike_labels("mole");
        let names: Vec<&str> = all.iter().map(|(n, _)| n.as_str()).collect();
        for expected in [
            "m0le", "mo1e", "moie", "rnole", "ole", "mle", "omle", "mmole", "molee",
        ] {
            assert!(names.contains(&expected), "{expected} in {names:?}");
        }
        assert!(!names.contains(&"mole"));
        assert_eq!(all, lookalike_labels("mole"));
        // Too short to say anything, or not plain letters.
        assert!(lookalike_labels("ab").is_empty());
        assert!(lookalike_labels("bücher").is_empty());
        // No name starts or ends with a hyphen.
        assert!(
            lookalike_labels("a-b")
                .iter()
                .all(|(n, _)| !n.starts_with('-') && !n.ends_with('-'))
        );
    }

    #[test]
    fn lookalike_domains_keep_the_parent_and_try_other_endings() {
        let all = lookalike_candidates("mole.org.");
        assert!(all.iter().any(|(d, _)| d == "m0le.org."));
        assert!(all.iter().any(|(d, _)| d == "mole.com."));
        assert!(!all.iter().any(|(d, _)| d == "mole.org."));
        assert!(all.len() <= MAX_LOOKALIKES);
        // Under a longer parent, only the label changes.
        let all = lookalike_candidates("mole.co.uk.");
        assert!(all.iter().all(|(d, _)| d.ends_with(".co.uk.")));
        assert!(lookalike_candidates("org.").is_empty());
    }

    #[test]
    fn route_answers_are_read() {
        assert_eq!(
            parse_route_status(r#"{"data":{"status":"valid","validating_roas":[]}}"#).as_deref(),
            Ok("valid")
        );
        assert_eq!(
            parse_route_status(r#"{"data":{"status":"INVALID_ASN"}}"#).as_deref(),
            Ok("invalid_asn")
        );
        assert!(parse_route_status(r#"{"data":{"status":"<script>"}}"#).is_err());
        assert!(parse_route_status("<html>").is_err());
        assert!(route_url(64496, "192.0.2.0/24").contains("resource=AS64496&prefix=192.0.2.0/24"));
    }

    #[test]
    fn suffixes() {
        assert_eq!(
            suffix("ns1.example.net.", 2).as_deref(),
            Some("example.net.")
        );
        assert_eq!(
            suffix("ns1.example.co.uk.", 3).as_deref(),
            Some("example.co.uk.")
        );
        assert_eq!(suffix("net.", 2), None);
    }
}
