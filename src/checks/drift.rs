//! The drift checks (`DRF`): what the nameservers serve against what a
//! declared zone file says they should. They give nothing unless the run
//! was handed a zone file.

use std::collections::{BTreeMap, BTreeSet};

use super::{Evidence, Finding, Severity};
use crate::observe::{ZoneObservation, is_ancestor_or_equal, parent_name};
use crate::zonefile::{COMPARED, Declared, comparable};

/// What the servers hold for each name and type the run asked about, in
/// comparison form: the union over the servers that answered with
/// authority. `None` for a name and type no server answered for.
fn served(obs: &ZoneObservation) -> BTreeMap<(String, String), BTreeSet<String>> {
    let mut out: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for rec in &obs.records {
        let rtype = rec.qtype.as_str();
        if !COMPARED.contains(&rtype) {
            continue;
        }
        let Some(answer) = rec.outcome.answer().filter(|a| a.authoritative) else {
            continue;
        };
        let set = out
            .entry((rec.name.clone(), rtype.to_string()))
            .or_default();
        set.extend(answer.rdata.iter().map(|r| comparable(rtype, r)));
    }
    out
}

/// True when a declared wildcard stands in for `name`: the name has no
/// records of its own in the file and some `*.<ancestor>` is declared.
fn covered_by_wildcard(declared: &Declared, zone: &str, name: &str) -> bool {
    if declared.sets.iter().any(|s| s.name == name) {
        return false;
    }
    let mut ancestor = parent_name(name);
    loop {
        let wildcard = format!("*.{ancestor}");
        if declared.sets.iter().any(|s| s.name == wildcard) {
            return true;
        }
        if ancestor == zone || ancestor == "." || !is_ancestor_or_equal(zone, ancestor) {
            return false;
        }
        ancestor = parent_name(ancestor);
    }
}

fn finding(
    check_id: &str,
    name: &str,
    rtype: &str,
    summary: String,
    declared: &[String],
    served: &BTreeSet<String>,
    source: &str,
) -> Finding {
    Finding::new(
        check_id,
        Severity::Warning,
        name,
        summary,
        Evidence::Drift {
            rtype: rtype.to_string(),
            declared: declared.to_vec(),
            served: served.iter().cloned().collect(),
            source: source.to_string(),
        },
    )
}

/// DRF-01: a record set the file declares is missing, or holds other data.
pub fn drf_01_declared_differs(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(declared) = &obs.declared else {
        return Vec::new();
    };
    let served = served(obs);
    let mut findings = Vec::new();
    for set in &declared.sets {
        let Some(live) = served.get(&(set.name.clone(), set.rtype.clone())) else {
            // Not asked in this run (a wildcard, or NS below the apex).
            continue;
        };
        if live.iter().eq(set.rdata.iter()) {
            continue;
        }
        let summary = if live.is_empty() {
            format!(
                "{} {} is in the zone file but the nameservers do not serve it",
                set.name, set.rtype
            )
        } else {
            format!("{} {} differs from the zone file", set.name, set.rtype)
        };
        findings.push(finding(
            "DRF-01",
            &set.name,
            &set.rtype,
            summary,
            &set.rdata,
            live,
            &declared.source,
        ));
    }
    findings
}

/// DRF-02: the nameservers serve a record set the file does not declare.
pub fn drf_02_undeclared(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(declared) = &obs.declared else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for ((name, rtype), live) in served(obs) {
        if live.is_empty()
            || declared
                .sets
                .iter()
                .any(|s| s.name == name && s.rtype == rtype)
        {
            continue;
        }
        // The apex NS set is the host's business unless the file states it.
        if rtype == "NS" || covered_by_wildcard(declared, &obs.zone, &name) {
            continue;
        }
        findings.push(finding(
            "DRF-02",
            &name,
            &rtype,
            format!("{name} {rtype} is served but is not in the zone file"),
            &[],
            &live,
            &declared.source,
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::*;
    use crate::observe::{QType, RecordAnswer, RecordObservation, RecordOutcome, Transport};
    use crate::zonefile::parse;

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

    fn observed(file: &str) -> ZoneObservation {
        let mut obs = healthy();
        obs.records = vec![
            record("example.test.", QType::Txt, &[r#""v=spf1 " "-all""#]),
            record("example.test.", QType::Mx, &[]),
            record("www.example.test.", QType::A, &["192.0.2.10", "192.0.2.11"]),
            record("www.example.test.", QType::Aaaa, &[]),
            record("old.example.test.", QType::Cname, &["gone.example.net."]),
            record("x.dev.example.test.", QType::A, &["192.0.2.50"]),
        ];
        obs.declared = Some(Declared {
            source: "zone.txt".to_string(),
            sets: parse("example.test.", file).unwrap(),
        });
        obs
    }

    fn all(obs: &ZoneObservation) -> Vec<(String, String, String)> {
        let mut f = drf_01_declared_differs(obs);
        f.extend(drf_02_undeclared(obs));
        f.into_iter()
            .map(|f| (f.check_id, f.name, f.summary))
            .collect()
    }

    #[test]
    fn a_matching_file_is_silent() {
        let obs = observed(
            "@ TXT \"v=spf1 -all\"\nwww A 192.0.2.11\nwww A 192.0.2.10\nold CNAME gone.example.net.\n*.dev A 192.0.2.50\n",
        );
        assert_eq!(all(&obs), []);
        let mut none = obs.clone();
        none.declared = None;
        assert_eq!(all(&none), []);
    }

    #[test]
    fn differences_are_reported_both_ways() {
        let obs = observed(
            "@ TXT \"v=spf1 -all\"\n@ MX 10 mail\nwww A 192.0.2.10\nwww AAAA 2001:db8::1\n",
        );
        let found = all(&obs);
        let ids: Vec<(&str, &str)> = found
            .iter()
            .map(|(id, name, _)| (id.as_str(), name.as_str()))
            .collect();
        assert_eq!(
            ids,
            [
                ("DRF-01", "example.test."),
                ("DRF-01", "www.example.test."),
                ("DRF-01", "www.example.test."),
                ("DRF-02", "old.example.test."),
                ("DRF-02", "x.dev.example.test."),
            ]
        );
        assert!(
            found[0].2.contains("MX is in the zone file but"),
            "{}",
            found[0].2
        );
        assert!(
            found[1].2.ends_with("A differs from the zone file"),
            "{}",
            found[1].2
        );
        let evidence = &drf_01_declared_differs(&obs)[1].evidence;
        assert_eq!(
            serde_json::to_value(evidence).unwrap(),
            serde_json::json!({
                "kind": "drift", "rtype": "A", "declared": ["192.0.2.10"],
                "served": ["192.0.2.10", "192.0.2.11"], "source": "zone.txt",
            })
        );
    }
}
