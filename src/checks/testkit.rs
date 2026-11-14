//! Hand-built observations for check tests. No network, no resolver.

use std::net::IpAddr;

use crate::observe::{
    Glue, NsHost, Outcome, QType, ReferralStep, ResponseObs, ServerProbe, Soa, Transport, Vantage,
    ZoneObservation,
};

pub const ZONE: &str = "example.test.";
pub const V4_A: &str = "192.0.2.1";
pub const V4_B: &str = "198.51.100.1";
pub const V6_A: &str = "2001:db8:1::53";
pub const V6_B: &str = "2001:db8:2::53";

const NS_NAMES: [&str; 2] = ["ns1.example.test.", "ns2.example.test."];

pub fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub fn soa(serial: u32) -> Soa {
    Soa {
        mname: NS_NAMES[0].to_string(),
        rname: "hostmaster.example.test.".to_string(),
        serial,
        refresh: 7200,
        retry: 3600,
        expire: 1209600,
        minimum: 3600,
    }
}

pub fn response(rcode: &str, aa: bool, soa: Option<Soa>, ns: &[&str]) -> Outcome {
    Outcome::Response(ResponseObs {
        rcode: rcode.to_string(),
        authoritative: aa,
        truncated: false,
        opt_present: true,
        size: 120,
        soa,
        ns: ns.iter().map(|s| s.to_string()).collect(),
    })
}

/// The five apex probes for one address, all healthy.
fn healthy_probes(ns_name: &str, address: &str) -> Vec<ServerProbe> {
    let plan = [
        (QType::Soa, Transport::Udp, true),
        (QType::Ns, Transport::Udp, true),
        (QType::Soa, Transport::Udp, false),
        (QType::Soa, Transport::Tcp, true),
        (QType::Ns, Transport::Tcp, true),
    ];
    plan.into_iter()
        .map(|(qtype, transport, edns)| {
            let mut outcome = match qtype {
                QType::Soa => response("NOERROR", true, Some(soa(42)), &[]),
                _ => response("NOERROR", true, None, &NS_NAMES),
            };
            if let Outcome::Response(r) = &mut outcome {
                r.opt_present = edns;
            }
            ServerProbe {
                ns_name: ns_name.to_string(),
                address: ip(address),
                qtype,
                transport,
                edns,
                outcome,
            }
        })
        .collect()
}

fn build(addresses: [&[&str]; 2], vantage: Vantage) -> ZoneObservation {
    let mut ns_hosts = Vec::new();
    let mut probes = Vec::new();
    let mut glue = Vec::new();
    for (name, addrs) in NS_NAMES.iter().zip(addresses) {
        let addrs: Vec<IpAddr> = addrs.iter().map(|a| ip(a)).collect();
        for a in &addrs {
            glue.push(Glue {
                name: name.to_string(),
                address: *a,
            });
            probes.extend(healthy_probes(name, &a.to_string()));
        }
        ns_hosts.push(NsHost {
            name: name.to_string(),
            in_parent: true,
            in_child: true,
            glue: addrs.clone(),
            resolved: addrs,
            cname: None,
            resolve_error: None,
        });
    }
    probes.sort();
    ZoneObservation {
        zone: ZONE.to_string(),
        started_at_unix: 0,
        vantage,
        delegation_path: vec![
            ReferralStep {
                from_zone: ".".to_string(),
                to_zone: "test.".to_string(),
                server_name: Some("a.root-servers.net.".to_string()),
                server_address: ip("198.41.0.4"),
                ns: vec!["ns.nic.test.".to_string()],
                glue: vec![],
            },
            ReferralStep {
                from_zone: "test.".to_string(),
                to_zone: ZONE.to_string(),
                server_name: Some("ns.nic.test.".to_string()),
                server_address: ip("203.0.113.1"),
                ns: NS_NAMES.iter().map(|s| s.to_string()).collect(),
                glue,
            },
        ],
        ns_hosts,
        probes,
        records: Vec::new(),
        dnssec: None,
        policy: None,
        deep: None,
        declared: None,
        certificates: None,
        vantages: Vec::new(),
    }
}

/// Two nameservers, IPv4 only, everything in order.
pub fn healthy() -> ZoneObservation {
    build(
        [&[V4_A], &[V4_B]],
        Vantage {
            ipv4: true,
            ipv6: false,
        },
    )
}

/// Two dual-stack nameservers, everything in order, IPv6 working.
pub fn healthy_dual_stack() -> ZoneObservation {
    build(
        [&[V4_A, V6_A], &[V4_B, V6_B]],
        Vantage {
            ipv4: true,
            ipv6: true,
        },
    )
}

/// Replace the outcome of every probe sent to one address.
pub fn set_outcomes(obs: &mut ZoneObservation, address: &str, f: impl Fn(&ServerProbe) -> Outcome) {
    let address = ip(address);
    for probe in obs.probes.iter_mut().filter(|p| p.address == address) {
        probe.outcome = f(probe);
    }
}

/// Change the SOA serial one server reports.
pub fn set_serial(obs: &mut ZoneObservation, address: &str, serial: u32) {
    let address = ip(address);
    for probe in obs.probes.iter_mut().filter(|p| p.address == address) {
        if let Outcome::Response(r) = &mut probe.outcome
            && let Some(soa) = &mut r.soa
        {
            soa.serial = serial;
        }
    }
}

/// Change the NS set every server reports for the zone.
pub fn set_child_ns(obs: &mut ZoneObservation, ns: &[&str]) {
    for probe in obs.probes.iter_mut().filter(|p| p.qtype == QType::Ns) {
        if let Outcome::Response(r) = &mut probe.outcome {
            r.ns = ns.iter().map(|s| s.to_string()).collect();
        }
    }
}
