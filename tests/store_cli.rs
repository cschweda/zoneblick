//! `run`, `diff` and `zones list`, offline: two recorded states of a zone are
//! stored in a real SQLite file and compared.

use std::path::{Path, PathBuf};

use serde_json::Value;
use zoneblick::cli::{
    BaselineAction, BaselineArgs, DiffArgs, ExportArgs, FindingsAction, FindingsListArgs,
    FindingsMuteArgs, PruneArgs, RunArgs, SourceArgs, ZonesAction, ZonesEditArgs, ZonesListArgs,
    baseline, diff, export, findings, prune, run, zones_edit, zones_list,
};

const ZONE: &str = "drift.example";
const NAMES: [&str; 4] = ["www", "api", "shop", "staging"];

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A fresh database file for one test.
fn db(test: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{test}.sqlite"));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    path
}

fn run_args(db: &Path, state: &str, names: &[&str], json: bool) -> RunArgs {
    RunArgs {
        zone: ZONE.to_string(),
        names: names.iter().map(|s| s.to_string()).collect(),
        forget_names: vec![],
        discover: vec![],
        db: db.to_path_buf(),
        json,
        deep: false,
        source: SourceArgs {
            record: None,
            replay: Some(fixture(&format!("drift.example.{state}.json"))),
        },
    }
}

fn diff_args(db: &Path, json: bool) -> DiffArgs {
    DiffArgs {
        zone: ZONE.to_string(),
        from: None,
        to: None,
        baseline: false,
        ignore: vec![],
        db: db.to_path_buf(),
        json,
    }
}

/// Store the "before" state, then the "after" state.
async fn two_runs(db: &Path) {
    let first = run(&run_args(db, "before", &NAMES, false), false).await;
    assert_eq!(first.exit_code, 0, "{}{}", first.stdout, first.stderr);
    // The second run is given no names: they are remembered.
    let second = run(&run_args(db, "after", &[], false), false).await;
    assert_eq!(second.exit_code, 1, "{}{}", second.stdout, second.stderr);
}

#[tokio::test]
async fn first_run_stores_and_reports_records() {
    let db = db("first_run");
    let out = run(&run_args(&db, "before", &NAMES, false), false).await;
    assert_eq!(out.exit_code, 0, "{}{}", out.stdout, out.stderr);
    // Column widths aside, each record line reads name, type, data.
    let text = out.stdout.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        text.contains("api.drift.example. CNAME app.hosting.example."),
        "{text}"
    );
    assert!(
        text.contains("drift.example. MX 10 mail.drift.example."),
        "{text}"
    );
    assert!(
        text.contains("drift.example. TXT \"v=spf1 mx -all\""),
        "{text}"
    );
    assert!(text.starts_with("zoneblick run drift.example."), "{text}");
    assert!(text.contains("Stored: run #1 in"));
    assert!(text.contains("4 names besides the apex"));
    assert!(text.contains("first stored run of the zone"));
}

#[tokio::test]
async fn second_run_shows_what_changed() {
    let db = db("second_run");
    let first = run(&run_args(&db, "before", &NAMES, false), false).await;
    assert_eq!(first.exit_code, 0);
    let out = run(&run_args(&db, "after", &[], false), false).await;
    // The servers now disagree about `shop`, which is a warning.
    assert_eq!(out.exit_code, 1);
    let text = &out.stdout;
    assert!(text.contains("CON-02  shop.drift.example."), "{text}");
    assert!(text.contains("Stored: run #2 in"));
    assert!(
        text.contains("Changes since run #1 (2023-11-14 22:13 UTC)"),
        "{text}"
    );
    assert!(text.contains("- app.hosting.example."));
    assert!(text.contains("+ new-app.hosting.example."));
    assert!(text.contains("SOA serial 2026111301 -> 2026111302"));
}

/// The diff JSON for the two drift states is pinned byte for byte.
/// Regenerate with `ZONEBLICK_REGEN=1 cargo test` after an intended change.
#[tokio::test]
async fn diff_json_matches_the_golden_file() {
    let db = db("diff_json");
    two_runs(&db).await;
    let out = diff(&diff_args(&db, true), false);
    assert_eq!(out.exit_code, 1, "changes exit with 1");
    let golden = fixture("drift.example.diff.json");
    if std::env::var_os("ZONEBLICK_REGEN").is_some() {
        std::fs::write(&golden, &out.stdout).unwrap();
    }
    let expected = std::fs::read_to_string(&golden).unwrap_or_default();
    assert!(out.stdout == expected, "diff JSON changed:\n{}", out.stdout);

    let doc: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(doc["zone"], "drift.example.");
    assert_eq!(
        (doc["from"]["id"].as_i64(), doc["to"]["id"].as_i64()),
        (Some(1), Some(2))
    );
    let kinds: Vec<(String, String, String)> = doc["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["name"].as_str().unwrap().to_string(),
                c["rtype"].as_str().unwrap().to_string(),
                c["kind"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let expect = |n: &str, t: &str, k: &str| (n.to_string(), t.to_string(), k.to_string());
    assert_eq!(
        kinds,
        [
            expect("api.drift.example.", "CNAME", "modified"),
            expect("drift.example.", "TXT", "removed"),
            expect("shop.drift.example.", "A", "modified"),
            expect("staging.drift.example.", "A", "added"),
        ]
    );
    // `api` changed everywhere; `shop` on one server only.
    assert_eq!(doc["changes"][0]["all_servers"], true);
    assert_eq!(doc["changes"][2]["all_servers"], false);
    assert_eq!(doc["changes"][2]["servers"].as_array().unwrap().len(), 1);
    assert_eq!(doc["changes"][2]["servers"][0]["address"], "198.51.100.1");
    assert_eq!(doc["soa_serial"]["after"][0], 2026111302u32);
    assert_eq!(doc["findings_opened"][0]["check_id"], "CON-02");
    assert_eq!(doc["changed"], true);
}

#[tokio::test]
async fn diff_text_and_ignore_patterns() {
    let db = db("diff_text");
    two_runs(&db).await;
    let out = diff(&diff_args(&db, false), false);
    let text = &out.stdout;
    assert!(
        text.starts_with("zoneblick diff drift.example.\nrun #1 ("),
        "{text}"
    );
    assert!(
        text.contains("MODIFIED  api.drift.example. CNAME"),
        "{text}"
    );
    assert!(text.contains("on every nameserver"));
    assert!(text.contains("REMOVED   drift.example. TXT"));
    assert!(text.contains("ADDED     staging.drift.example. A"));
    assert!(text.contains("ns1.drift.example. (198.51.100.1): 192.0.2.20 -> 192.0.2.99"));
    assert!(text.contains("OPENED  "));
    assert!(text.contains(
        "Changes: 1 added, 1 removed, 2 modified, 0 TTL; findings: 1 opened, 0 resolved"
    ));
    assert!(
        !text.contains("www.drift.example."),
        "unchanged names stay out"
    );

    let mut args = diff_args(&db, true);
    args.ignore = vec!["api.*".to_string(), "staging.drift.example".to_string()];
    let doc: Value = serde_json::from_str(&diff(&args, false).stdout).unwrap();
    assert_eq!(doc["changes"].as_array().unwrap().len(), 2);
    assert_eq!(doc["summary"]["added"], 0);
}

#[tokio::test]
async fn diff_of_identical_runs_exits_zero() {
    let db = db("diff_same");
    for _ in 0..2 {
        let out = run(&run_args(&db, "before", &NAMES, false), false).await;
        assert_eq!(out.exit_code, 0);
    }
    let out = diff(&diff_args(&db, false), false);
    assert_eq!(out.exit_code, 0);
    assert!(out.stdout.contains("No changes."));
}

#[tokio::test]
async fn run_json_document() {
    let db = db("run_json");
    let first = run(&run_args(&db, "before", &NAMES, true), false).await;
    let doc: Value = serde_json::from_str(&first.stdout).unwrap();
    assert_eq!(doc["run"]["id"], 1);
    assert_eq!(doc["run"]["names"].as_array().unwrap().len(), 4);
    assert!(doc["diff"].is_null());
    assert_eq!(doc["report"]["zone"], "drift.example.");
    assert!(!doc["report"]["records"].as_array().unwrap().is_empty());

    let second = run(&run_args(&db, "after", &[], true), false).await;
    let doc: Value = serde_json::from_str(&second.stdout).unwrap();
    assert_eq!(doc["run"]["id"], 2);
    assert_eq!(doc["diff"]["summary"]["modified"], 2);
    assert_eq!(doc["report"]["exit_code"], 1);
}

#[tokio::test]
async fn names_can_be_forgotten() {
    let db = db("forget");
    run(&run_args(&db, "before", &NAMES, false), false).await;
    let mut args = run_args(&db, "before", &[], true);
    args.forget_names = vec!["staging".to_string(), "shop.drift.example.".to_string()];
    let doc: Value = serde_json::from_str(&run(&args, false).await.stdout).unwrap();
    let names: Vec<&str> = doc["run"]["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    assert_eq!(names, ["api.drift.example.", "www.drift.example."]);
}

#[tokio::test]
async fn zones_list_and_failures() {
    let db = db("zones");
    // No database yet.
    let out = diff(&diff_args(&db, true), false);
    assert_eq!(out.exit_code, 3);
    let doc: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(doc["error"]["kind"], "no_database");

    run(&run_args(&db, "before", &NAMES, false), false).await;
    // One run is not enough to diff.
    let out = diff(&diff_args(&db, true), false);
    assert_eq!(out.exit_code, 3);
    let doc: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(doc["error"]["kind"], "not_enough_runs");

    run(&run_args(&db, "after", &[], false), false).await;
    let mut args = diff_args(&db, false);
    args.from = Some(7);
    let out = diff(&args, false);
    assert_eq!(out.exit_code, 3);
    assert!(
        out.stderr.contains("has no run #7; its runs are #1, #2"),
        "{}",
        out.stderr
    );

    let list = zones_list(
        &ZonesListArgs {
            db: db.clone(),
            json: true,
        },
        false,
    );
    assert_eq!(list.exit_code, 0);
    let doc: Value = serde_json::from_str(&list.stdout).unwrap();
    assert_eq!(doc["zones"][0]["zone"], "drift.example.");
    assert_eq!(doc["zones"][0]["runs"], 2);
    assert_eq!(doc["zones"][0]["names"], 4);
    assert_eq!(doc["zones"][0]["open_findings"], 1);

    // A name outside the zone is refused before anything is queried.
    let mut bad = run_args(&db, "before", &["www.other.example."], false);
    bad.zone = ZONE.to_string();
    let out = run(&bad, false).await;
    assert_eq!(out.exit_code, 3);
    assert!(
        out.stderr.contains("is not inside the zone"),
        "{}",
        out.stderr
    );
}

fn baseline_args(db: &Path, run: Option<i64>) -> BaselineArgs {
    BaselineArgs {
        zone: ZONE.to_string(),
        run,
        db: db.to_path_buf(),
    }
}

#[tokio::test]
async fn a_diff_against_the_pinned_baseline() {
    let db = db("baseline");
    two_runs(&db).await;

    // No baseline yet: the diff says how to pin one.
    let mut args = diff_args(&db, false);
    args.baseline = true;
    let out = diff(&args, false);
    assert_eq!(out.exit_code, 3);
    assert!(
        out.stderr.contains("zoneblick baseline pin"),
        "{}",
        out.stderr
    );

    let out = baseline(&BaselineAction::Pin(baseline_args(&db, Some(1))));
    assert_eq!(out.exit_code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("is now run #1"), "{}", out.stdout);
    let out = baseline(&BaselineAction::Show(baseline_args(&db, None)));
    assert!(out.stdout.contains("is run #1"), "{}", out.stdout);

    // A third run, identical to the second: nothing new since the run
    // before, but still different from the baseline.
    let third = run(&run_args(&db, "after", &[], false), false).await;
    assert_eq!(third.exit_code, 1, "{}{}", third.stdout, third.stderr);
    assert_eq!(diff(&diff_args(&db, false), false).exit_code, 0);
    let out = diff(&args, false);
    assert_eq!(out.exit_code, 1, "{}{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("run #1") && out.stdout.contains("run #3"));

    let out = baseline(&BaselineAction::Clear(baseline_args(&db, None)));
    assert!(out.stdout.contains("removed"), "{}", out.stdout);
    assert_eq!(diff(&args, false).exit_code, 3);
}

#[tokio::test]
async fn prune_reports_what_it_deleted() {
    let db = db("prune");
    two_runs(&db).await;
    let args = |keep_all: &str, keep_daily: &str| PruneArgs {
        keep_all: keep_all.to_string(),
        keep_daily: keep_daily.to_string(),
        db: db.clone(),
    };
    // The fixtures are dated 2024: past a year old, so only the latest stays.
    let out = prune(&args("30d", "365d"));
    assert_eq!(out.exit_code, 0, "{}", out.stderr);
    assert!(out.stdout.starts_with("Deleted 1 runs"), "{}", out.stdout);
    let bad = prune(&args("30d", "7d"));
    assert_eq!(bad.exit_code, 3);
    assert!(
        bad.stderr.contains("keep_daily must not be shorter"),
        "{}",
        bad.stderr
    );
}

#[tokio::test]
async fn findings_are_listed_muted_and_exported() {
    let db = db("findings");
    two_runs(&db).await;
    let list = |state: Option<&str>, json: bool| {
        findings(&FindingsAction::List(FindingsListArgs {
            zone: Some(ZONE.to_string()),
            state: state.map(str::to_string),
            db: db.clone(),
            json,
        }))
    };
    let doc: Value = serde_json::from_str(&list(Some("open"), true).stdout).unwrap();
    let open = doc["findings"].as_array().unwrap();
    assert!(!open.is_empty());
    let id = open[0]["fingerprint"].as_str().unwrap().to_string();
    let text = list(None, false).stdout;
    assert!(text.contains(&id[..10]) && text.contains("open"), "{text}");

    let mute = |id: &str, muting: bool| {
        let args = FindingsMuteArgs {
            zone: ZONE.to_string(),
            id: id.to_string(),
            db: db.clone(),
        };
        findings(&if muting {
            FindingsAction::Mute(args)
        } else {
            FindingsAction::Unmute(args)
        })
    };
    let out = mute(&id[..10], true);
    assert_eq!(out.exit_code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("is now muted"), "{}", out.stdout);
    assert_eq!(mute("nothing-like-this", true).exit_code, 3);

    // The next run leaves the muted finding out and says so.
    let doc_before = open.len();
    let third = run(&run_args(&db, "after", &[], true), false).await;
    assert!(
        third.stderr.contains("1 muted findings are not shown"),
        "{}",
        third.stderr
    );
    let doc: Value = serde_json::from_str(&third.stdout).unwrap();
    assert_eq!(
        doc["report"]["findings"].as_array().unwrap().len(),
        doc_before - 1
    );

    // The export holds every finding with its state; the CSV has one row each.
    let export_as = |format: &str| {
        export(&ExportArgs {
            zone: Some(ZONE.to_string()),
            format: format.to_string(),
            db: db.clone(),
        })
    };
    let doc: Value = serde_json::from_str(&export_as("json").stdout).unwrap();
    let all = doc["findings"].as_array().unwrap();
    assert!(all.iter().any(|f| f["state"] == "muted"));
    assert_eq!(doc["zones"][0]["zone"], "drift.example.");
    let csv = export_as("csv").stdout;
    assert!(csv.starts_with("zone,state,severity,check_id,name,summary,"));
    assert_eq!(csv.lines().count(), all.len() + 1);

    assert!(mute(&id, false).stdout.contains("is now open"));
}

#[tokio::test]
async fn a_zone_is_added_with_names_and_removed() {
    let db = db("zones_edit");
    let edit = |names: &[&str]| ZonesEditArgs {
        zone: ZONE.to_string(),
        names: names.iter().map(|s| s.to_string()).collect(),
        db: db.clone(),
    };
    let out = zones_edit(&ZonesAction::Add(edit(&NAMES)));
    assert_eq!(out.exit_code, 0, "{}", out.stderr);
    assert!(
        out.stdout
            .starts_with("Added drift.example., 4 names added"),
        "{}",
        out.stdout
    );
    // The first run needs no names: they were added with the zone.
    let first = run(&run_args(&db, "before", &[], true), false).await;
    let doc: Value = serde_json::from_str(&first.stdout).unwrap();
    assert_eq!(doc["run"]["names"].as_array().unwrap().len(), 4);

    let out = zones_edit(&ZonesAction::Remove(edit(&[])));
    assert_eq!(out.stdout, "Removed drift.example. and its 1 runs.\n");
    assert_eq!(zones_edit(&ZonesAction::Remove(edit(&[]))).exit_code, 3);
}
