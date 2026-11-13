//! The mail-policy and takeover checks, end to end and offline.

mod common;

use common::*;
use zoneblick::checks::{Evidence, Severity, run_all};

fn ids(findings: &[zoneblick::checks::Finding]) -> Vec<(&str, Severity, &str)> {
    findings
        .iter()
        .map(|f| (f.check_id.as_str(), f.severity, f.name.as_str()))
        .collect()
}

#[tokio::test]
async fn policy_data_is_collected_through_the_resolver() {
    let obs = policy_world().observe(POLICY_ZONE).await.unwrap();
    let p = obs.policy.as_ref().unwrap();
    assert_eq!(p.mx.rdata, ["10 mx.policy.example."]);
    assert_eq!(p.caa.status, "nodata");
    assert_eq!(p.dmarc.status, "answer");

    let spf = p.spf.as_ref().unwrap();
    assert_eq!(spf.records.len(), 1);
    let chain: Vec<(&str, &str, usize)> = spf
        .lookups
        .iter()
        .map(|l| (l.mechanism.as_str(), l.domain.as_str(), l.depth))
        .collect();
    assert_eq!(
        chain,
        [
            ("mx", "policy.example.", 0),
            ("include", "_spf.esp.example.", 0),
            ("include", "_spf.gone-esp.example.", 0),
        ]
    );
    assert_eq!(spf.lookups[1].target.as_ref().unwrap().status, "answer");
    let gone = spf.lookups[2].target.as_ref().unwrap();
    assert_eq!(
        (gone.status.as_str(), gone.enclosing.as_deref()),
        ("nxdomain", Some("example."))
    );

    let sts = p.mta_sts.as_ref().unwrap();
    assert_eq!(sts.http_status, Some(200));
    assert_eq!(
        (sts.mode.as_deref(), sts.mx_patterns.as_slice()),
        (Some("enforce"), &["mail.elsewhere.example".to_string()][..])
    );

    assert_eq!(p.targets.len(), 1);
    assert_eq!(p.targets[0].lookup.rdata, ["192.0.2.25"]);
}

#[tokio::test]
async fn a_check_reports_the_policy_problems() {
    let obs = policy_world().observe(POLICY_ZONE).await.unwrap();
    let findings = run_all(&obs);
    assert_eq!(
        ids(&findings),
        [
            ("TKO-04", Severity::Critical, "policy.example."),
            ("POL-04", Severity::Warning, "policy.example."),
            ("POL-02", Severity::Notice, "_dmarc.policy.example."),
            ("POL-03", Severity::Notice, "policy.example."),
        ]
    );
    match &findings[0].evidence {
        Evidence::DanglingTarget {
            target,
            unregistered_domain,
            ..
        } => {
            assert_eq!(target, "_spf.gone-esp.example.");
            assert_eq!(unregistered_domain.as_deref(), Some("gone-esp.example."));
        }
        other => panic!("unexpected evidence: {other:?}"),
    }
    assert!(matches!(
        &findings[1].evidence,
        Evidence::MtaStsProblem { problems, .. } if problems.len() == 1 && problems[0].contains("mx.policy.example.")
    ));
}

#[tokio::test]
async fn a_run_also_follows_aliases() {
    let obs = policy_world()
        .observe_records(POLICY_ZONE, &["app.policy.example."])
        .await
        .unwrap();
    let findings = run_all(&obs);
    let takeover: Vec<_> = findings.iter().filter(|f| f.check_id == "TKO-03").collect();
    assert_eq!(takeover.len(), 1);
    assert_eq!(takeover[0].severity, Severity::Critical);
    assert_eq!(takeover[0].name, "app.policy.example.");
    assert!(
        takeover[0]
            .summary
            .contains("gone-host.example. is not registered")
    );
    // Unregistered beats merely dangling: no TKO-01 for the same alias.
    assert!(!findings.iter().any(|f| f.check_id == "TKO-01"));
    assert_eq!(findings.len(), 5);
}
