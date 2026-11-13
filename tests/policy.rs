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
            .contains("gone-host.example., which is not registered")
    );
    // Unregistered beats merely dangling: no TKO-01 for the same alias.
    assert!(!findings.iter().any(|f| f.check_id == "TKO-01"));
    assert_eq!(findings.len(), 5);
}

#[tokio::test]
async fn a_wildcard_alias_and_an_unregistered_nameserver_domain() {
    let obs = exposed_world().observe(POLICY_ZONE).await.unwrap();
    let findings = run_all(&obs);
    let found: Vec<_> = ids(&findings)
        .into_iter()
        .filter(|(id, ..)| matches!(*id, "DEL-06" | "TKO-05" | "TKO-03"))
        .collect();
    // The nameserver is DEL-06 only, not TKO-03 as well.
    assert_eq!(
        found,
        [
            ("DEL-06", Severity::Critical, "ns.gone-dns.example."),
            ("TKO-05", Severity::Notice, "*.policy.example."),
        ]
    );
    let del = findings.iter().find(|f| f.check_id == "DEL-06").unwrap();
    assert!(
        del.summary
            .contains("gone-dns.example., which is not registered")
    );
    assert!(matches!(
        &findings.iter().find(|f| f.check_id == "TKO-05").unwrap().evidence,
        Evidence::WildcardAlias { target, .. } if target == "sites.host.example."
    ));

    // Without them, neither check fires.
    let plain = run_all(&policy_world().observe(POLICY_ZONE).await.unwrap());
    assert!(
        !plain
            .iter()
            .any(|f| matches!(f.check_id.as_str(), "DEL-06" | "TKO-05"))
    );
}

#[tokio::test]
async fn a_run_can_discover_names_from_certificate_logs() {
    use zoneblick::cli::{RunArgs, SourceArgs, run};

    let mut world = policy_world();
    world.http(
        &zoneblick::discover::ct_url(POLICY_ZONE),
        200,
        r#"[{"common_name":"app.policy.example","name_value":"app.policy.example\n*.policy.example\nmx.policy.example\nelsewhere.example"}]"#,
    );
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let fixture = dir.join("discover.fixture.json");
    std::fs::write(
        &fixture,
        serde_json::to_string(&world.fixture(POLICY_ZONE)).unwrap(),
    )
    .unwrap();
    let db = dir.join("discover.sqlite");
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", db.display()));
    }
    let args = |discover: &[&str]| RunArgs {
        zone: POLICY_ZONE.to_string(),
        names: vec![],
        forget_names: vec![],
        discover: discover.iter().map(|s| s.to_string()).collect(),
        db: db.clone(),
        json: true,
        deep: false,
        source: SourceArgs {
            record: None,
            replay: Some(fixture.clone()),
        },
    };

    let out = run(&args(&["ct"]), false).await;
    assert!(
        out.stderr
            .contains("name 2 hosts in policy.example., 2 of them new"),
        "{}",
        out.stderr
    );
    let doc: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(
        doc["run"]["names"],
        serde_json::json!(["app.policy.example.", "mx.policy.example."])
    );
    // The alias that discovery found is followed: its target is unregistered.
    assert!(out.stdout.contains("TKO-03"));

    // Found names are remembered without asking again.
    let again = run(&args(&[]), false).await;
    assert!(again.stderr.is_empty(), "{}", again.stderr);
    let doc: serde_json::Value = serde_json::from_str(&again.stdout).unwrap();
    assert_eq!(doc["run"]["names"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn an_alias_of_an_unclaimed_hosted_site_is_critical() {
    let world = exposed_world();
    let obs = world
        .observe_records(POLICY_ZONE, &["docs.policy.example."])
        .await
        .unwrap();
    let probes = &obs.policy.as_ref().unwrap().services;
    assert_eq!(probes.len(), 1);
    assert_eq!(
        (
            probes[0].service.as_str(),
            probes[0].status,
            probes[0].unclaimed
        ),
        ("GitHub Pages", Some(404), true)
    );
    let findings = run_all(&obs);
    let found: Vec<_> = findings.iter().filter(|f| f.check_id == "TKO-02").collect();
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].severity, found[0].name.as_str()),
        (Severity::Critical, "docs.policy.example.")
    );
    assert!(
        found[0]
            .summary
            .contains("policy-docs.github.io. (GitHub Pages)")
    );

    // A site that is there gives no finding.
    let mut claimed = exposed_world();
    claimed.http("http://docs.policy.example/", 200, "<h1>Our docs</h1>");
    let obs = claimed
        .observe_records(POLICY_ZONE, &["docs.policy.example."])
        .await
        .unwrap();
    assert!(!run_all(&obs).iter().any(|f| f.check_id == "TKO-02"));
    // And a plain check, which collects no aliases, fetches nothing.
    let obs = exposed_world().observe(POLICY_ZONE).await.unwrap();
    assert!(obs.policy.unwrap().services.is_empty());
}
