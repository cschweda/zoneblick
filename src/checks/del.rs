//! Delegation checks, `DEL-01` to `DEL-06`.

use std::collections::BTreeSet;
use std::net::IpAddr;

use super::{Evidence, Finding, LameReason, Severity, servers};
use crate::observe::{QType, ZoneObservation};

/// DEL-01: the parent's NS set differs from the NS set the zone serves.
///
/// The child side is the union of the NS sets from every authoritative
/// server; disagreement between those servers is CON-02.
pub fn del_01_parent_child_ns(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(parent) = obs.parent() else {
        return Vec::new();
    };
    let child_sets: Vec<&Vec<String>> = servers(obs)
        .iter()
        .filter_map(|s| s.authoritative(QType::Ns))
        .map(|r| &r.ns)
        .collect();
    if child_sets.is_empty() {
        return Vec::new();
    }
    let parent_set: BTreeSet<&String> = parent.ns.iter().collect();
    let child_set: BTreeSet<&String> = child_sets.into_iter().flatten().collect();
    if parent_set == child_set {
        return Vec::new();
    }
    let owned = |set: Vec<&&String>| set.into_iter().map(|s| s.to_string()).collect::<Vec<_>>();
    vec![Finding::new(
        "DEL-01",
        Severity::Warning,
        &obs.zone,
        format!(
            "The parent zone {} and the zone itself list different nameservers",
            parent.from_zone
        ),
        Evidence::NsSetMismatch {
            parent: owned(parent_set.iter().collect()),
            child: owned(child_set.iter().collect()),
            only_in_parent: owned(parent_set.difference(&child_set).collect()),
            only_in_child: owned(child_set.difference(&parent_set).collect()),
        },
    )]
}

/// DEL-02: a listed nameserver is not authoritative for the zone.
///
/// Three cases, told apart in the evidence: the server answers but not
/// authoritatively, the server answers nothing at all, or the nameserver's
/// name has no address. An IPv6 address that is silent while the same host
/// answers over IPv4 is CON-04, not this check.
pub fn del_02_lame(obs: &ZoneObservation) -> Vec<Finding> {
    let all = servers(obs);
    let mut findings = Vec::new();
    for host in &obs.ns_hosts {
        if host.addresses().is_empty() {
            findings.push(Finding::new(
                "DEL-02",
                Severity::Critical,
                &host.name,
                format!(
                    "Nameserver {} has no address{}",
                    host.name,
                    host.resolve_error
                        .as_ref()
                        .map(|e| format!(" ({e})"))
                        .unwrap_or_default()
                ),
                Evidence::LameServer {
                    ns_name: host.name.clone(),
                    address: None,
                    reason: LameReason::Unresolvable,
                    probes: Vec::new(),
                },
            ));
        }
    }
    for server in &all {
        let authoritative = server
            .probes
            .iter()
            .filter(|p| p.qtype == QType::Soa)
            .filter_map(|p| p.outcome.response())
            .any(|r| r.is_authoritative_answer());
        if authoritative {
            continue;
        }
        let (reason, summary) = if server.responded() {
            (
                LameReason::NotAuthoritative,
                format!(
                    "Nameserver {} ({}) is not authoritative for {}",
                    server.host.name, server.address, obs.zone
                ),
            )
        } else {
            let v4_sibling_answers = all.iter().any(|other| {
                other.host.name == server.host.name && other.address.is_ipv4() && other.responded()
            });
            if server.address.is_ipv6() && v4_sibling_answers {
                continue;
            }
            (
                LameReason::NoResponse,
                format!(
                    "Nameserver {} ({}) did not answer any query",
                    server.host.name, server.address
                ),
            )
        };
        findings.push(Finding::new(
            "DEL-02",
            Severity::Critical,
            &server.host.name,
            summary,
            Evidence::LameServer {
                ns_name: server.host.name.clone(),
                address: Some(server.address),
                reason,
                probes: server.summaries(),
            },
        ));
    }
    findings
}

/// DEL-03: glue at the parent differs from the addresses the nameserver's
/// name resolves to.
///
/// Compared per address family, and only for families the glue covers: a
/// parent that holds only IPv4 glue for a dual-stack nameserver is common and
/// is not reported.
pub fn del_03_glue(obs: &ZoneObservation) -> Vec<Finding> {
    let mut findings = Vec::new();
    for host in &obs.ns_hosts {
        if host.glue.is_empty() || host.resolved.is_empty() {
            continue;
        }
        let differs = [false, true].into_iter().any(|v6| {
            let pick = |addrs: &[IpAddr]| -> BTreeSet<IpAddr> {
                addrs
                    .iter()
                    .copied()
                    .filter(|a| a.is_ipv6() == v6)
                    .collect()
            };
            let glue = pick(&host.glue);
            !glue.is_empty() && glue != pick(&host.resolved)
        });
        if differs {
            findings.push(Finding::new(
                "DEL-03",
                Severity::Warning,
                &host.name,
                format!(
                    "Glue for {} at the parent does not match its address records",
                    host.name
                ),
                Evidence::GlueMismatch {
                    ns_name: host.name.clone(),
                    glue: host.glue.clone(),
                    resolved: host.resolved.clone(),
                },
            ));
        }
    }
    findings
}

/// DEL-04: fewer than two nameservers, or all of them in one network.
///
/// The network test runs per address family: all IPv4 addresses in one /24,
/// or all IPv6 addresses in one /48.
pub fn del_04_redundancy(obs: &ZoneObservation) -> Vec<Finding> {
    let names: Vec<String> = obs.ns_hosts.iter().map(|h| h.name.clone()).collect();
    if names.len() < 2 {
        return vec![Finding::new(
            "DEL-04",
            Severity::Notice,
            &obs.zone,
            format!(
                "The zone has {} nameserver; at least two are expected",
                names.len()
            ),
            Evidence::TooFewNameservers { nameservers: names },
        )];
    }
    let addresses: BTreeSet<IpAddr> = obs.ns_hosts.iter().flat_map(|h| h.addresses()).collect();
    let mut findings = Vec::new();
    for v6 in [false, true] {
        let family: Vec<IpAddr> = addresses
            .iter()
            .copied()
            .filter(|a| a.is_ipv6() == v6)
            .collect();
        let prefixes: BTreeSet<String> = family.iter().map(network_prefix).collect();
        if prefixes.len() == 1 {
            let prefix = prefixes.into_iter().next().expect("one prefix");
            findings.push(Finding::new(
                "DEL-04",
                Severity::Notice,
                &obs.zone,
                format!(
                    "All {} nameserver addresses are in one network, {prefix}",
                    if v6 { "IPv6" } else { "IPv4" }
                ),
                Evidence::SingleNetwork {
                    prefix,
                    addresses: family,
                },
            ));
        }
    }
    findings
}

/// The /24 (IPv4) or /48 (IPv6) network an address is in.
fn network_prefix(addr: &IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let net = std::net::Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0);
            format!("{net}/48")
        }
    }
}

/// DEL-05: a nameserver name is an alias (CNAME), which RFC 2181 forbids.
pub fn del_05_ns_cname(obs: &ZoneObservation) -> Vec<Finding> {
    obs.ns_hosts
        .iter()
        .filter_map(|host| {
            let target = host.cname.as_ref()?;
            Some(Finding::new(
                "DEL-05",
                Severity::Warning,
                &host.name,
                format!("Nameserver {} is a CNAME to {target}", host.name),
                Evidence::NsIsCname {
                    ns_name: host.name.clone(),
                    target: target.clone(),
                },
            ))
        })
        .collect()
}

/// DEL-06: the nameserver hostname's own domain is unregistered or expired.
///
/// Not implemented in Phase 0. Deciding whether a domain is registered needs
/// registry data (RDAP or WHOIS), which is outside the DNS observations a
/// check may read. This stub keeps the check ID reserved and returns nothing.
pub fn del_06_ns_domain_registration(_obs: &ZoneObservation) -> Vec<Finding> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::*;
    use crate::observe::Outcome;

    #[test]
    fn healthy_zone_has_no_delegation_findings() {
        let obs = healthy();
        assert!(del_01_parent_child_ns(&obs).is_empty());
        assert!(del_02_lame(&obs).is_empty());
        assert!(del_03_glue(&obs).is_empty());
        assert!(del_04_redundancy(&obs).is_empty());
        assert!(del_05_ns_cname(&obs).is_empty());
        assert!(del_06_ns_domain_registration(&obs).is_empty());
    }

    #[test]
    fn del_01_reports_both_directions() {
        let mut obs = healthy();
        // The zone itself lists ns3 instead of ns2.
        set_child_ns(&mut obs, &["ns1.example.test.", "ns3.example.test."]);
        let findings = del_01_parent_child_ns(&obs);
        assert_eq!(findings.len(), 1);
        match &findings[0].evidence {
            Evidence::NsSetMismatch {
                only_in_parent,
                only_in_child,
                ..
            } => {
                assert_eq!(only_in_parent, &["ns2.example.test."]);
                assert_eq!(only_in_child, &["ns3.example.test."]);
            }
            other => panic!("unexpected evidence: {other:?}"),
        }
    }

    #[test]
    fn del_01_needs_a_parent_view() {
        let mut obs = healthy();
        set_child_ns(&mut obs, &["ns1.example.test."]);
        obs.delegation_path.pop();
        assert!(del_01_parent_child_ns(&obs).is_empty());
    }

    #[test]
    fn del_02_not_authoritative() {
        let mut obs = healthy();
        set_outcomes(&mut obs, V4_B, |_| response("REFUSED", false, None, &[]));
        let findings = del_02_lame(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].name, "ns2.example.test.");
        assert!(matches!(
            findings[0].evidence,
            Evidence::LameServer {
                reason: LameReason::NotAuthoritative,
                ..
            }
        ));
    }

    #[test]
    fn del_02_no_response() {
        let mut obs = healthy();
        set_outcomes(&mut obs, V4_B, |_| Outcome::Timeout);
        let findings = del_02_lame(&obs);
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence,
            Evidence::LameServer {
                reason: LameReason::NoResponse,
                ..
            }
        ));
    }

    #[test]
    fn del_02_unresolvable_nameserver() {
        let mut obs = healthy();
        let host = &mut obs.ns_hosts[1];
        host.glue.clear();
        host.resolved.clear();
        host.resolve_error = Some("NXDOMAIN".to_string());
        obs.probes.retain(|p| p.address != ip(V4_B));
        let findings = del_02_lame(&obs);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].summary.contains("NXDOMAIN"));
        assert!(matches!(
            findings[0].evidence,
            Evidence::LameServer {
                reason: LameReason::Unresolvable,
                address: None,
                ..
            }
        ));
    }

    #[test]
    fn del_02_leaves_silent_ipv6_to_con_04() {
        let mut obs = healthy_dual_stack();
        set_outcomes(&mut obs, V6_A, |_| Outcome::Timeout);
        assert!(del_02_lame(&obs).is_empty());
        // With IPv4 silent too, the host is simply down.
        set_outcomes(&mut obs, V4_A, |_| Outcome::Timeout);
        assert_eq!(del_02_lame(&obs).len(), 2);
    }

    #[test]
    fn del_03_glue_mismatch() {
        let mut obs = healthy();
        obs.ns_hosts[0].resolved = vec![ip("192.0.2.99")];
        let findings = del_03_glue(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].name, "ns1.example.test.");
    }

    #[test]
    fn del_03_ignores_families_without_glue() {
        let mut obs = healthy();
        // IPv4 glue only; the name also has an AAAA record.
        obs.ns_hosts[0].resolved.push(ip(V6_A));
        assert!(del_03_glue(&obs).is_empty());
        // No glue at all (out-of-zone nameserver): nothing to compare.
        obs.ns_hosts[0].glue.clear();
        assert!(del_03_glue(&obs).is_empty());
    }

    #[test]
    fn del_04_single_nameserver() {
        let mut obs = healthy();
        obs.ns_hosts.truncate(1);
        let findings = del_04_redundancy(&obs);
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence,
            Evidence::TooFewNameservers { .. }
        ));
    }

    #[test]
    fn del_04_one_network_per_family() {
        let mut obs = healthy_dual_stack();
        assert!(del_04_redundancy(&obs).is_empty());
        // Move ns2's IPv4 address into ns1's /24.
        obs.ns_hosts[1].glue = vec![ip("192.0.2.200"), ip(V6_B)];
        obs.ns_hosts[1].resolved = obs.ns_hosts[1].glue.clone();
        let findings = del_04_redundancy(&obs);
        assert_eq!(findings.len(), 1);
        match &findings[0].evidence {
            Evidence::SingleNetwork { prefix, .. } => assert_eq!(prefix, "192.0.2.0/24"),
            other => panic!("unexpected evidence: {other:?}"),
        }
    }

    #[test]
    fn del_04_ipv6_prefix_is_a_48() {
        assert_eq!(network_prefix(&ip("2001:db8:1:2::53")), "2001:db8:1::/48");
    }

    #[test]
    fn del_05_cname() {
        let mut obs = healthy();
        obs.ns_hosts[1].cname = Some("real.example.net.".to_string());
        let findings = del_05_ns_cname(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
    }
}
