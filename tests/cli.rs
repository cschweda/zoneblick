//! The `check` command, run offline from fixtures.

use std::path::PathBuf;

use serde_json::Value;
use zoneblick::cli::{CheckArgs, check};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn args(zone: &str, replay: &str, json: bool) -> CheckArgs {
    CheckArgs {
        zone: zone.to_string(),
        json,
        record: None,
        replay: Some(fixture(replay)),
    }
}

#[tokio::test]
async fn broken_zone_text_output_and_exit_code() {
    let out = check(&args("broken.example", "broken.example.json", false), false).await;
    assert_eq!(out.exit_code, 2);
    assert!(out.stderr.is_empty());
    let text = &out.stdout;
    // Delegation path summary, then findings grouped by severity.
    assert!(text.contains("example. -> broken.example."), "{text}");
    let critical = text.find("CRITICAL (1)").expect("critical group");
    let warning = text.find("WARNING (1)").expect("warning group");
    assert!(critical < warning);
    assert!(text.contains("DEL-02  ns3.broken.example."));
    assert!(text.contains("CON-01  broken.example."));
    assert!(text.contains("serial 2024111302: ns2.broken.example. (198.51.100.2)"));
    assert!(!text.contains('\x1b'), "no colour codes unless asked");
}

/// The JSON document for the broken zone is pinned byte for byte.
/// Regenerate with `ZONEBLICK_REGEN=1 cargo test --test cli` after an
/// intended change, and bump `SCHEMA_VERSION` if a field changed meaning.
#[tokio::test]
async fn broken_zone_json_matches_the_golden_file() {
    let out = check(&args("broken.example", "broken.example.json", true), false).await;
    assert_eq!(out.exit_code, 2);
    let golden = fixture("broken.example.report.json");
    if std::env::var_os("ZONEBLICK_REGEN").is_some() {
        std::fs::write(&golden, &out.stdout).unwrap();
    }
    let expected = std::fs::read_to_string(&golden).unwrap_or_default();
    assert!(
        out.stdout == expected,
        "JSON output changed; see the comment on this test"
    );

    let doc: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(doc["schema_version"], 1);
    assert_eq!(doc["zone"], "broken.example.");
    assert_eq!(doc["exit_code"], 2);
    assert_eq!(doc["summary"]["critical"], 1);
    assert_eq!(doc["summary"]["warning"], 1);
    assert_eq!(doc["findings"][0]["check_id"], "DEL-02");
    assert_eq!(doc["findings"][0]["severity"], "critical");
    assert_eq!(doc["findings"][0]["evidence"]["kind"], "lame_server");
    assert_eq!(
        doc["findings"][0]["evidence"]["reason"],
        "not_authoritative"
    );
    assert_eq!(doc["findings"][1]["evidence"]["kind"], "serial_mismatch");
}

#[tokio::test]
async fn good_zone_exits_zero() {
    let out = check(&args("good.example", "good.example.json", false), false).await;
    assert_eq!(out.exit_code, 0);
    assert!(
        out.stdout
            .contains("None. All delegation and consistency checks passed.")
    );
}

/// A real run against example.com, recorded with `--record` and replayed.
#[tokio::test]
async fn recorded_real_zone_replays() {
    let out = check(&args("example.com", "example.com.json", true), false).await;
    let doc: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(doc["zone"], "example.com.");
    let path = doc["delegation_path"].as_array().unwrap();
    assert_eq!(path.len(), 2);
    assert_eq!(path[0]["to_zone"], "com.");
    assert_eq!(path[1]["to_zone"], "example.com.");
    assert!(!doc["nameservers"].as_array().unwrap().is_empty());
    assert_eq!(doc["summary"]["critical"], 0);
    assert_eq!(out.exit_code, doc["exit_code"]);

    let again = check(&args("example.com", "example.com.json", true), false).await;
    assert_eq!(out, again, "a replay is deterministic");
}

#[tokio::test]
async fn record_then_replay_gives_the_same_report() {
    let recorded = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("rerecorded.json");
    let mut first_args = args("broken.example", "broken.example.json", true);
    first_args.replay = None;
    // `record` and `replay` are exclusive on the command line; here the
    // recording is made from a replay to stay offline.
    let first_args = CheckArgs {
        replay: Some(fixture("broken.example.json")),
        record: Some(recorded.clone()),
        ..first_args
    };
    let first = check(&first_args, false).await;
    let second_args = CheckArgs {
        zone: "broken.example".to_string(),
        json: true,
        record: None,
        replay: Some(recorded),
    };
    let second = check(&second_args, false).await;
    assert_eq!(first, second);
}

#[tokio::test]
async fn run_failures_exit_three() {
    // The zone does not exist in this fixture's world.
    let out = check(&args("good.example", "broken.example.json", true), false).await;
    assert_eq!(out.exit_code, 3);
    let doc: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(doc["error"]["kind"], "fixture_error");
    assert_eq!(doc["exit_code"], 3);

    let out = check(&args("not a name!", "broken.example.json", false), false).await;
    assert_eq!(out.exit_code, 3);
    assert!(out.stdout.is_empty());
    assert!(out.stderr.starts_with("zoneblick: "));
}

/// Needs the network. Run with `cargo test -- --ignored`.
#[tokio::test]
#[ignore = "uses the live network"]
async fn live_check_of_example_com() {
    let live = CheckArgs {
        zone: "example.com".to_string(),
        json: true,
        record: None,
        replay: None,
    };
    let out = check(&live, false).await;
    assert_ne!(out.exit_code, 3, "{}", out.stdout);
    let doc: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(doc["delegation_path"][0]["from_zone"], ".");
}
