//! End-to-end, offline: replay recorded exchanges through the real resolver
//! and run the real checks on what it observed.

mod common;

use std::path::PathBuf;

use common::*;
use zoneblick::checks::{Evidence, LameReason, Severity, run_all};
use zoneblick::resolver::Fixture;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn load(name: &str) -> Fixture {
    let text = std::fs::read_to_string(fixture_path(name)).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// The hand-built fixtures on disk are generated from `tests/common`.
/// Regenerate them with `ZONEBLICK_REGEN=1 cargo test --test fixtures`.
#[test]
fn hand_built_fixtures_are_current() {
    let worlds = [
        (
            "broken.example.json",
            broken_world().fixture("broken.example."),
        ),
        ("good.example.json", good_world().fixture("good.example.")),
        (
            "drift.example.before.json",
            drift_world(false).fixture_at(DRIFT_ZONE, STARTED_AT),
        ),
        (
            "drift.example.after.json",
            drift_world(true).fixture_at(DRIFT_ZONE, STARTED_AT + 3600),
        ),
    ];
    for (file, fixture) in worlds {
        let expected = serde_json::to_string_pretty(&fixture).unwrap() + "\n";
        if std::env::var_os("ZONEBLICK_REGEN").is_some() {
            std::fs::write(fixture_path(file), &expected).unwrap();
        }
        let on_disk = std::fs::read_to_string(fixture_path(file)).unwrap_or_default();
        assert!(
            on_disk == expected,
            "{file} is stale; run ZONEBLICK_REGEN=1 cargo test --test fixtures"
        );
    }
}

#[tokio::test]
async fn broken_zone_produces_the_expected_findings() {
    let obs = observe_fixture(&load("broken.example.json")).await.unwrap();
    let findings = run_all(&obs);
    let ids: Vec<(&str, Severity, &str)> = findings
        .iter()
        .map(|f| (f.check_id.as_str(), f.severity, f.name.as_str()))
        .collect();
    assert_eq!(
        ids,
        [
            ("DEL-02", Severity::Critical, "ns3.broken.example."),
            ("CON-01", Severity::Warning, "broken.example."),
        ]
    );

    match &findings[0].evidence {
        Evidence::LameServer {
            address,
            reason,
            probes,
            ..
        } => {
            assert_eq!(address.unwrap().to_string(), NS3);
            assert_eq!(*reason, LameReason::NotAuthoritative);
            assert_eq!(probes.len(), 5);
            assert!(probes.iter().all(|p| p.result == "REFUSED"));
        }
        other => panic!("unexpected evidence: {other:?}"),
    }
    match &findings[1].evidence {
        Evidence::SerialMismatch { serials } => {
            let seen: Vec<(u32, String)> = serials
                .iter()
                .map(|v| (v.value, v.servers[0].address.to_string()))
                .collect();
            assert_eq!(
                seen,
                [(2024111301, NS1.to_string()), (2024111302, NS2.to_string())]
            );
        }
        other => panic!("unexpected evidence: {other:?}"),
    }
}

#[tokio::test]
async fn good_zone_is_clean() {
    let obs = observe_fixture(&load("good.example.json")).await.unwrap();
    assert_eq!(run_all(&obs), []);
}

#[tokio::test]
async fn replay_is_deterministic() {
    let fixture = load("broken.example.json");
    let first = observe_fixture(&fixture).await.unwrap();
    let second = observe_fixture(&fixture).await.unwrap();
    assert_eq!(first, second);
    assert_eq!(first.started_at_unix, STARTED_AT);
}
