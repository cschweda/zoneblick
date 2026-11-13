//! Consistency checks, `CON-01` to `CON-05`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use super::{Evidence, Finding, ServerRef, Severity, Variant, group_by, servers};
use crate::observe::{QType, Transport, ZoneObservation};

/// Servers grouped by the record data they served.
type ServersByValue = BTreeMap<Vec<String>, Vec<ServerRef>>;

/// The UDP payload size zoneblick advertises in EDNS queries.
const EDNS_PAYLOAD: usize = 1232;
/// The largest UDP response allowed without EDNS.
const PLAIN_UDP_LIMIT: usize = 512;

/// CON-01: authoritative servers serve different SOA serials.
pub fn con_01_soa_serial(obs: &ZoneObservation) -> Vec<Finding> {
    let all = servers(obs);
    let serials = group_by(&all, |s| {
        s.authoritative(QType::Soa)?
            .soa
            .as_ref()
            .map(|soa| soa.serial)
    });
    if serials.len() < 2 {
        return Vec::new();
    }
    let list: Vec<String> = serials.iter().map(|v| v.value.to_string()).collect();
    vec![Finding::new(
        "CON-01",
        Severity::Warning,
        &obs.zone,
        format!(
            "Nameservers serve different SOA serials: {}",
            list.join(", ")
        ),
        Evidence::SerialMismatch { serials },
    )]
}

/// CON-02: an RRset differs across authoritative servers.
///
/// Phase 0 only queries the apex, so this compares the apex NS set, and the
/// SOA fields other than the serial (the serial is CON-01).
pub fn con_02_rrset(obs: &ZoneObservation) -> Vec<Finding> {
    let all = servers(obs);
    let mut findings = Vec::new();

    let ns = group_by(&all, |s| s.authoritative(QType::Ns).map(|r| r.ns.clone()));
    let soa = group_by(&all, |s| {
        let soa = s.authoritative(QType::Soa)?.soa.as_ref()?;
        Some(vec![
            format!("mname={}", soa.mname),
            format!("rname={}", soa.rname),
            format!("refresh={}", soa.refresh),
            format!("retry={}", soa.retry),
            format!("expire={}", soa.expire),
            format!("minimum={}", soa.minimum),
        ])
    });
    for (rrtype, variants) in [("NS", ns), ("SOA", soa)] {
        if variants.len() < 2 {
            continue;
        }
        findings.push(Finding::new(
            "CON-02",
            Severity::Warning,
            &obs.zone,
            format!(
                "Nameservers serve {} different versions of the {rrtype} record set",
                variants.len()
            ),
            Evidence::RrsetMismatch {
                rrtype: rrtype.to_string(),
                variants,
            },
        ));
    }

    // Record sets collected by `run`, for every name and type. The apex SOA
    // and NS sets are covered above.
    let mut by_set: BTreeMap<(&str, QType), ServersByValue> = BTreeMap::new();
    for rec in &obs.records {
        if rec.name == obs.zone && matches!(rec.qtype, QType::Soa | QType::Ns) {
            continue;
        }
        let Some(answer) = rec.outcome.answer() else {
            continue;
        };
        if !answer.authoritative {
            continue;
        }
        let value = match answer.rcode.as_str() {
            "NOERROR" => answer.rdata.clone(),
            "NXDOMAIN" => vec!["NXDOMAIN".to_string()],
            _ => continue,
        };
        by_set
            .entry((&rec.name, rec.qtype))
            .or_default()
            .entry(value)
            .or_default()
            .push(ServerRef {
                ns_name: rec.ns_name.clone(),
                address: rec.address,
            });
    }
    for ((name, qtype), sets) in by_set {
        if sets.len() < 2 {
            continue;
        }
        let variants: Vec<Variant<Vec<String>>> = sets
            .into_iter()
            .map(|(value, servers)| Variant { value, servers })
            .collect();
        findings.push(Finding::new(
            "CON-02",
            Severity::Warning,
            name,
            format!(
                "Nameservers serve {} different versions of the {} record set for {name}",
                variants.len(),
                qtype.as_str()
            ),
            Evidence::RrsetMismatch {
                rrtype: qtype.as_str().to_string(),
                variants,
            },
        ));
    }
    findings
}

/// CON-03: a server answers over UDP but not over TCP.
pub fn con_03_tcp(obs: &ZoneObservation) -> Vec<Finding> {
    let mut findings = Vec::new();
    for server in servers(obs) {
        let answers = |transport: Transport| {
            server
                .probes
                .iter()
                .any(|p| p.transport == transport && p.outcome.response().is_some())
        };
        let has_tcp_probe = server.probes.iter().any(|p| p.transport == Transport::Tcp);
        if answers(Transport::Udp) && has_tcp_probe && !answers(Transport::Tcp) {
            findings.push(Finding::new(
                "CON-03",
                Severity::Warning,
                &server.host.name,
                format!(
                    "Nameserver {} ({}) answers over UDP but not over TCP",
                    server.host.name, server.address
                ),
                Evidence::NoTcp {
                    ns_name: server.host.name.clone(),
                    address: server.address,
                    probes: server.summaries(),
                },
            ));
        }
    }
    findings
}

/// CON-04: a nameserver publishes an IPv6 address that does not answer,
/// while the same nameserver answers over IPv4.
///
/// When IPv6 does not work at all from the machine running the check, the
/// test cannot be made; one `info` finding says so instead.
pub fn con_04_ipv6(obs: &ZoneObservation) -> Vec<Finding> {
    if !obs.vantage.ipv6 {
        let addresses: Vec<IpAddr> = obs
            .ns_hosts
            .iter()
            .flat_map(|h| h.addresses())
            .filter(|a| a.is_ipv6())
            .collect();
        if addresses.is_empty() {
            return Vec::new();
        }
        return vec![Finding::new(
            "CON-04",
            Severity::Info,
            &obs.zone,
            format!(
                "IPv6 does not work from this host; {} IPv6 nameserver address(es) were not tested",
                addresses.len()
            ),
            Evidence::Ipv6NotTested { addresses },
        )];
    }
    let all = servers(obs);
    let mut findings = Vec::new();
    for server in all.iter().filter(|s| s.address.is_ipv6() && !s.responded()) {
        let v4_answers = all.iter().any(|other| {
            other.host.name == server.host.name && other.address.is_ipv4() && other.responded()
        });
        if !v4_answers {
            continue;
        }
        findings.push(Finding::new(
            "CON-04",
            Severity::Notice,
            &server.host.name,
            format!(
                "Nameserver {} does not answer on its IPv6 address {}",
                server.host.name, server.address
            ),
            Evidence::Ipv6Unreachable {
                ns_name: server.host.name.clone(),
                address: server.address,
                probes: server.summaries(),
            },
        ));
    }
    findings
}

/// CON-05: a server mishandles EDNS or truncation.
///
/// Only servers that are authoritative for the zone are judged. Reported
/// when the server:
///
/// - answers an EDNS query with FORMERR, NOTIMP or BADVERS
/// - leaves the OPT record out of its reply to an EDNS query
/// - sends a UDP response larger than the size the query allowed
/// - sets TC over UDP but gives no answer to the same question over TCP
pub fn con_05_edns(obs: &ZoneObservation) -> Vec<Finding> {
    let mut findings = Vec::new();
    for server in servers(obs) {
        if server.authoritative(QType::Soa).is_none() {
            continue;
        }
        let mut problems = Vec::new();
        for probe in server
            .probes
            .iter()
            .filter(|p| p.transport == Transport::Udp)
        {
            let Some(r) = probe.outcome.response() else {
                continue;
            };
            let what = format!("{} query", probe.qtype.as_str());
            if probe.edns {
                if matches!(r.rcode.as_str(), "FORMERR" | "NOTIMP" | "BADVERS") {
                    problems.push(format!("answers an EDNS {what} with {}", r.rcode));
                } else if !r.opt_present {
                    problems.push(format!("no OPT record in the reply to an EDNS {what}"));
                }
            }
            let limit = if probe.edns {
                EDNS_PAYLOAD
            } else {
                PLAIN_UDP_LIMIT
            };
            if r.size > limit {
                problems.push(format!(
                    "UDP response to a {what} is {} bytes, over the {limit}-byte limit",
                    r.size
                ));
            }
            if r.truncated
                && server
                    .responses(probe.qtype, Transport::Tcp)
                    .next()
                    .is_none()
            {
                problems.push(format!(
                    "{what} is truncated over UDP and gets no answer over TCP"
                ));
            }
        }
        problems.sort();
        problems.dedup();
        if problems.is_empty() {
            continue;
        }
        findings.push(Finding::new(
            "CON-05",
            Severity::Notice,
            &server.host.name,
            format!(
                "Nameserver {} ({}) mishandles EDNS or truncation",
                server.host.name, server.address
            ),
            Evidence::EdnsProblem {
                ns_name: server.host.name.clone(),
                address: server.address,
                problems,
            },
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::*;
    use crate::observe::Outcome;

    #[test]
    fn healthy_zone_has_no_consistency_findings() {
        for obs in [healthy(), healthy_dual_stack()] {
            assert!(con_01_soa_serial(&obs).is_empty());
            assert!(con_02_rrset(&obs).is_empty());
            assert!(con_03_tcp(&obs).is_empty());
            assert!(con_04_ipv6(&obs).is_empty());
            assert!(con_05_edns(&obs).is_empty());
        }
    }

    #[test]
    fn con_01_serial_mismatch_names_each_server() {
        let mut obs = healthy();
        set_serial(&mut obs, V4_B, 43);
        let findings = con_01_soa_serial(&obs);
        assert_eq!(findings.len(), 1);
        match &findings[0].evidence {
            Evidence::SerialMismatch { serials } => {
                assert_eq!(serials.len(), 2);
                assert_eq!(serials[0].value, 42);
                assert_eq!(serials[0].servers[0].address, ip(V4_A));
                assert_eq!(serials[1].value, 43);
                assert_eq!(serials[1].servers[0].address, ip(V4_B));
            }
            other => panic!("unexpected evidence: {other:?}"),
        }
        // A serial difference alone is not an RRset difference.
        assert!(con_02_rrset(&obs).is_empty());
    }

    #[test]
    fn con_01_ignores_non_authoritative_servers() {
        let mut obs = healthy();
        set_outcomes(&mut obs, V4_B, |_| response("REFUSED", false, None, &[]));
        assert!(con_01_soa_serial(&obs).is_empty());
    }

    #[test]
    fn con_02_ns_set_differs() {
        let mut obs = healthy();
        set_outcomes(&mut obs, V4_B, |p| match p.qtype {
            QType::Ns => response("NOERROR", true, None, &["ns1.example.test."]),
            _ => p.outcome.clone(),
        });
        let findings = con_02_rrset(&obs);
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            &findings[0].evidence,
            Evidence::RrsetMismatch { rrtype, variants } if rrtype == "NS" && variants.len() == 2
        ));
    }

    #[test]
    fn con_02_soa_fields_differ() {
        let mut obs = healthy();
        for probe in obs.probes.iter_mut().filter(|p| p.address == ip(V4_B)) {
            if let Outcome::Response(r) = &mut probe.outcome
                && let Some(soa) = &mut r.soa
            {
                soa.refresh = 1;
            }
        }
        let findings = con_02_rrset(&obs);
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            &findings[0].evidence,
            Evidence::RrsetMismatch { rrtype, .. } if rrtype == "SOA"
        ));
    }

    #[test]
    fn con_02_covers_collected_record_sets() {
        use crate::observe::{RecordAnswer, RecordObservation, RecordOutcome};
        let mut obs = healthy();
        let rec = |server: &str, rcode: &str, rdata: &[&str]| RecordObservation {
            name: "www.example.test.".to_string(),
            qtype: QType::A,
            ns_name: "ns.example.test.".to_string(),
            address: ip(server),
            transport: Transport::Udp,
            outcome: RecordOutcome::Answer(RecordAnswer {
                rcode: rcode.to_string(),
                authoritative: true,
                ttl: Some(300),
                rdata: rdata.iter().map(|s| s.to_string()).collect(),
            }),
        };
        obs.records = vec![
            rec(V4_A, "NOERROR", &["192.0.2.10"]),
            rec(V4_B, "NOERROR", &["192.0.2.10"]),
        ];
        assert!(con_02_rrset(&obs).is_empty());

        obs.records[1] = rec(V4_B, "NOERROR", &["192.0.2.99"]);
        let findings = con_02_rrset(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].name, "www.example.test.");
        assert!(matches!(
            &findings[0].evidence,
            Evidence::RrsetMismatch { rrtype, variants } if rrtype == "A" && variants.len() == 2
        ));

        // One server says the name does not exist at all.
        obs.records[1] = rec(V4_B, "NXDOMAIN", &[]);
        assert_eq!(con_02_rrset(&obs).len(), 1);
    }

    #[test]
    fn con_03_no_tcp() {
        let mut obs = healthy();
        set_outcomes(&mut obs, V4_A, |p| match p.transport {
            Transport::Tcp => Outcome::NetError {
                message: "connection refused".to_string(),
            },
            Transport::Udp => p.outcome.clone(),
        });
        let findings = con_03_tcp(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].name, "ns1.example.test.");
        // A server that is down entirely is not a TCP finding.
        set_outcomes(&mut obs, V4_A, |_| Outcome::Timeout);
        assert!(con_03_tcp(&obs).is_empty());
    }

    #[test]
    fn con_04_silent_ipv6() {
        let mut obs = healthy_dual_stack();
        set_outcomes(&mut obs, V6_B, |_| Outcome::Timeout);
        let findings = con_04_ipv6(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Notice);
        assert_eq!(findings[0].name, "ns2.example.test.");
    }

    #[test]
    fn con_04_without_local_ipv6_is_one_info() {
        let mut obs = healthy_dual_stack();
        obs.vantage.ipv6 = false;
        obs.probes.retain(|p| p.address.is_ipv4());
        let findings = con_04_ipv6(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(matches!(
            &findings[0].evidence,
            Evidence::Ipv6NotTested { addresses } if addresses.len() == 2
        ));
        // And nothing else trips over the untested addresses.
        assert_eq!(crate::checks::run_all(&obs).len(), 1);
    }

    #[test]
    fn con_05_formerr_on_edns() {
        let mut obs = healthy();
        set_outcomes(&mut obs, V4_A, |p| {
            if p.edns && p.transport == Transport::Udp {
                response("FORMERR", false, None, &[])
            } else {
                p.outcome.clone()
            }
        });
        let findings = con_05_edns(&obs);
        assert_eq!(findings.len(), 1);
        match &findings[0].evidence {
            Evidence::EdnsProblem { problems, .. } => {
                assert!(
                    problems.iter().all(|p| p.contains("FORMERR")),
                    "{problems:?}"
                );
            }
            other => panic!("unexpected evidence: {other:?}"),
        }
    }

    #[test]
    fn con_05_missing_opt_and_oversize() {
        let mut obs = healthy();
        for probe in obs.probes.iter_mut().filter(|p| p.address == ip(V4_A)) {
            if let Outcome::Response(r) = &mut probe.outcome {
                if probe.edns && probe.qtype == QType::Soa {
                    r.opt_present = false;
                }
                if !probe.edns {
                    r.size = 900;
                }
            }
        }
        let findings = con_05_edns(&obs);
        assert_eq!(findings.len(), 1);
        match &findings[0].evidence {
            Evidence::EdnsProblem { problems, .. } => {
                assert_eq!(problems.len(), 2, "{problems:?}");
            }
            other => panic!("unexpected evidence: {other:?}"),
        }
    }

    #[test]
    fn con_05_truncation_without_tcp() {
        let mut obs = healthy();
        for probe in obs.probes.iter_mut().filter(|p| p.address == ip(V4_A)) {
            if probe.qtype != QType::Ns {
                continue;
            }
            match probe.transport {
                Transport::Udp => {
                    if let Outcome::Response(r) = &mut probe.outcome {
                        r.truncated = true;
                    }
                }
                Transport::Tcp => probe.outcome = Outcome::Timeout,
            }
        }
        let findings = con_05_edns(&obs);
        assert_eq!(findings.len(), 1);
    }
}
