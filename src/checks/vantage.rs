//! The vantage checks (`VAN`): this run compared with what other
//! zoneblick daemons, elsewhere on the network, last saw. They give
//! nothing unless vantage points are configured.

use std::collections::{BTreeMap, BTreeSet};

use super::{Evidence, Finding, Severity};
use crate::observe::ZoneObservation;
use crate::output::utc;
use crate::resolver::iterate::printable;
use crate::vantage::{servers_of, sets_of};

/// At most this many values of a vantage point's record set are quoted
/// in a finding, each cut to this many characters.
const MAX_VALUES: usize = 20;
const MAX_VALUE_CHARS: usize = 200;

/// A vantage point's run older than this, compared with this run, is
/// called stale and not compared.
const STALE_SECS: u64 = 86_400;

fn fresh(obs: &ZoneObservation) -> impl Iterator<Item = (&str, &crate::vantage::VantageReport)> {
    obs.vantages.iter().filter_map(|v| {
        let report = v.report.as_ref()?;
        (obs.started_at_unix.abs_diff(report.run_started_unix) <= STALE_SECS)
            .then_some((v.name.as_str(), report))
    })
}

/// VAN-01: a record set looks different from another vantage point.
pub fn van_01_records_differ(obs: &ZoneObservation) -> Vec<Finding> {
    let here: BTreeMap<(String, String), Vec<String>> = sets_of(&obs.records)
        .into_iter()
        .map(|s| ((s.name, s.rtype), s.rdata))
        .collect();
    // Per record set: what each vantage point that disagrees saw.
    let mut differing: BTreeMap<(&str, &str), Vec<String>> = BTreeMap::new();
    for (vantage, report) in fresh(obs) {
        for set in &report.sets {
            let Some((key, local)) = here.get_key_value(&(set.name.clone(), set.rtype.clone()))
            else {
                continue;
            };
            let theirs: BTreeSet<&String> = set.rdata.iter().collect();
            if theirs != local.iter().collect() {
                // A vantage point is another machine; what it sends is
                // quoted in part, never in bulk.
                let mut shown: Vec<String> = set
                    .rdata
                    .iter()
                    .take(MAX_VALUES)
                    .map(|r| {
                        let safe = printable(r);
                        match safe.char_indices().nth(MAX_VALUE_CHARS) {
                            Some((at, _)) => format!("{}...", &safe[..at]),
                            None => safe,
                        }
                    })
                    .collect();
                if set.rdata.len() > MAX_VALUES {
                    shown.push(format!("and {} more", set.rdata.len() - MAX_VALUES));
                }
                differing
                    .entry((key.0.as_str(), key.1.as_str()))
                    .or_default()
                    .push(format!(
                        "from {}: {}",
                        printable(vantage),
                        if shown.is_empty() {
                            "(nothing)".to_string()
                        } else {
                            shown.join(", ")
                        }
                    ));
            }
        }
    }
    differing
        .into_iter()
        .map(|((name, rtype), mut details)| {
            let local = &here[&(name.to_string(), rtype.to_string())];
            details.insert(
                0,
                format!(
                    "from here: {}",
                    if local.is_empty() {
                        "(nothing)".to_string()
                    } else {
                        local.join(", ")
                    }
                ),
            );
            Finding::new(
                "VAN-01",
                Severity::Warning,
                name,
                format!("{name} {rtype} is answered differently from another vantage point"),
                Evidence::RecordDetail {
                    rtype: rtype.to_string(),
                    details,
                },
            )
        })
        .collect()
}

/// VAN-02: a nameserver address answers from one place and not another.
pub fn van_02_reachability(obs: &ZoneObservation) -> Vec<Finding> {
    let here: BTreeMap<std::net::IpAddr, (String, bool)> = servers_of(&obs.probes)
        .into_iter()
        .map(|s| (s.address, (s.ns_name, s.answered)))
        .collect();
    let mut findings = Vec::new();
    for (address, (ns_name, answered_here)) in &here {
        let mut details = Vec::new();
        for (vantage, report) in fresh(obs) {
            if let Some(there) = report.servers.iter().find(|s| s.address == *address)
                && there.answered != *answered_here
            {
                details.push(format!(
                    "from {}: {}",
                    printable(vantage),
                    if there.answered {
                        "answers"
                    } else {
                        "no answer"
                    }
                ));
            }
        }
        if details.is_empty() {
            continue;
        }
        details.insert(
            0,
            format!(
                "from here: {}",
                if *answered_here {
                    "answers"
                } else {
                    "no answer"
                }
            ),
        );
        findings.push(Finding::new(
            "VAN-02",
            Severity::Warning,
            ns_name,
            format!("{ns_name} ({address}) answers from some vantage points and not from others"),
            Evidence::ServerBehaviour {
                ns_name: ns_name.clone(),
                address: *address,
                details,
            },
        ));
    }
    findings
}

/// VAN-03: a vantage point gave no report, or an old one, so nothing was
/// compared with it.
pub fn van_03_unavailable(obs: &ZoneObservation) -> Vec<Finding> {
    let mut details = Vec::new();
    for v in &obs.vantages {
        match (&v.report, &v.error) {
            (_, Some(error)) => {
                details.push(format!("{}: {}", printable(&v.name), printable(error)))
            }
            (Some(r), None) if obs.started_at_unix.abs_diff(r.run_started_unix) > STALE_SECS => {
                details.push(format!(
                    "{}: its latest run of the zone is from {}",
                    printable(&v.name),
                    utc(r.run_started_unix)
                ));
            }
            _ => {}
        }
    }
    if details.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "VAN-03",
        Severity::Notice,
        &obs.zone,
        format!(
            "{} of {} vantage points gave nothing to compare {} with",
            details.len(),
            obs.vantages.len(),
            obs.zone
        ),
        Evidence::ZoneDetail { details },
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::*;
    use crate::observe::{QType, RecordAnswer, RecordObservation, RecordOutcome, Transport};
    use crate::vantage::{VantageReport, VantageServer, VantageSet, VantageView};

    const NOW: u64 = 1_700_000_000;

    fn record(name: &str, qtype: QType, rdata: &[&str]) -> RecordObservation {
        RecordObservation {
            name: name.to_string(),
            qtype,
            ns_name: "ns1.example.test.".to_string(),
            address: V4_A.parse().unwrap(),
            transport: Transport::Udp,
            outcome: RecordOutcome::Answer(RecordAnswer {
                rcode: "NOERROR".to_string(),
                authoritative: true,
                ttl: Some(300),
                rdata: rdata.iter().map(|r| r.to_string()).collect(),
            }),
        }
    }

    fn here() -> ZoneObservation {
        let mut obs = healthy();
        obs.started_at_unix = NOW;
        obs.records = vec![
            record("www.example.test.", QType::A, &["192.0.2.10"]),
            record("example.test.", QType::Txt, &["\"v=spf1 -all\""]),
        ];
        obs
    }

    fn same_view(obs: &ZoneObservation, name: &str) -> VantageView {
        VantageView {
            name: name.to_string(),
            report: Some(VantageReport {
                zone: obs.zone.clone(),
                run_started_unix: NOW - 600,
                sets: sets_of(&obs.records),
                servers: servers_of(&obs.probes),
            }),
            error: None,
        }
    }

    fn all(obs: &ZoneObservation) -> Vec<(String, String)> {
        [
            van_01_records_differ(obs),
            van_02_reachability(obs),
            van_03_unavailable(obs),
        ]
        .into_iter()
        .flatten()
        .map(|f| (f.check_id, f.name))
        .collect()
    }

    #[test]
    fn agreeing_vantage_points_are_silent() {
        let mut obs = here();
        assert_eq!(all(&obs), [], "no vantage points configured");
        obs.vantages = vec![same_view(&obs, "fra"), same_view(&obs, "sin")];
        assert_eq!(all(&obs), []);
    }

    #[test]
    fn differences_between_vantage_points_are_reported() {
        let mut obs = here();
        let mut fra = same_view(&obs, "fra");
        let report = fra.report.as_mut().unwrap();
        // Frankfurt sees an old address for www, a name this run did not
        // check, and one nameserver address that does not answer there.
        report.sets[1] = VantageSet {
            name: "www.example.test.".to_string(),
            rtype: "A".to_string(),
            rdata: vec!["192.0.2.99".to_string()],
        };
        report.sets.push(VantageSet {
            name: "other.example.test.".to_string(),
            rtype: "A".to_string(),
            rdata: vec!["192.0.2.1".to_string()],
        });
        let lost: VantageServer = report.servers[0].clone();
        report.servers[0].answered = false;
        let mut old = same_view(&obs, "old");
        old.report.as_mut().unwrap().run_started_unix = NOW - 3 * 86_400;
        old.report.as_mut().unwrap().sets.clear();
        let down = VantageView {
            name: "down".to_string(),
            report: None,
            error: Some("the vantage point answered HTTP 502".to_string()),
        };
        obs.vantages = vec![fra, old, down];

        let v1 = van_01_records_differ(&obs);
        assert_eq!(v1.len(), 1);
        assert_eq!(v1[0].name, "www.example.test.");
        assert_eq!(
            serde_json::to_value(&v1[0].evidence).unwrap()["details"],
            serde_json::json!(["from here: 192.0.2.10", "from fra: 192.0.2.99"])
        );
        let v2 = van_02_reachability(&obs);
        assert_eq!(v2.len(), 1);
        assert_eq!(v2[0].name, lost.ns_name);
        let v3 = van_03_unavailable(&obs);
        assert_eq!(v3.len(), 1);
        assert!(
            v3[0].summary.starts_with("2 of 3 vantage points"),
            "{}",
            v3[0].summary
        );
    }
}
