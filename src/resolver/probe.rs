//! Builds the observation of one zone: finds the delegation, resolves every
//! nameserver hostname, then asks every nameserver address directly.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::rr::{Name, RData};
use tokio::task::JoinSet;

use super::ResolveError;
use super::hints::ROOT_HINTS;
use super::iterate::{Resolver, norm, parse_response, rcode_name};
use super::transport::{Client, QuerySpec, RawOutcome};
use crate::observe::{
    NsHost, Outcome, QType, ResponseObs, ServerProbe, Soa, Transport, Vantage, ZoneObservation,
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
    for _round in 0..2 {
        let mut tasks = JoinSet::new();
        for name in &pending {
            let host = hosts.get_mut(name).expect("pending host exists");
            let res = resolver.resolve_host(name.clone(), 0).await;
            host.resolved = res.addresses;
            host.cname = res.cname;
            host.resolve_error = res.error;
            for address in host.addresses() {
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

    Ok(ZoneObservation {
        zone,
        started_at_unix,
        vantage,
        delegation_path: delegation.path,
        ns_hosts: hosts.into_values().collect(),
        probes,
    })
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
}
