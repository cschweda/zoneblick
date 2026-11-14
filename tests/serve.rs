//! The daemon, offline: scheduled runs replay recorded DNS, the API and UI
//! are served on a loopback port, and alerts go to a local receiver.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use zoneblick::config::Config;
use zoneblick::resolver::{Client, Fixture};
use zoneblick::serve::{AppState, ClientFactory, router, run_zone, run_zone_level, token_hash};
use zoneblick::store::Store;

fn fixture(name: &str) -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A client factory that replays "before" for the first run and "after"
/// for every later one.
fn drifting() -> ClientFactory {
    let runs = AtomicUsize::new(0);
    let before = fixture("drift.example.before.json");
    let after = fixture("drift.example.after.json");
    Arc::new(move |_zone| {
        let n = runs.fetch_add(1, Ordering::SeqCst);
        Arc::new(Client::replay(if n == 0 { &before } else { &after }))
    })
}

/// The token every test daemon is given, unless the test sets its own.
const TOKEN: &str = "test-token-0123456789";

fn config(extra: &str) -> Config {
    // The token goes into the [server] section: the test's own, when it
    // has one, or one added here.
    let token_line = format!("token_sha256 = \"{}\"\n", token_hash(TOKEN));
    let extra = if extra.contains("token_sha256") {
        extra.to_string()
    } else if extra.contains("[server]\n") {
        extra.replacen("[server]\n", &format!("[server]\n{token_line}"), 1)
    } else {
        format!("[server]\n{token_line}{extra}")
    };
    Config::parse(&format!(
        r#"
[[zone]]
name = "drift.example"
seeds = ["www", "api", "shop", "staging"]
{extra}"#
    ))
    .unwrap()
}

/// Serve a router on a free loopback port; returns its base URL.
async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// An HTTP client that sends the test token unless a request sets its own.
fn client() -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {TOKEN}").parse().unwrap(),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}

/// A file holding the test token, for a `[[vantage]]` block.
fn token_file() -> String {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("vantage-token");
    std::fs::write(&path, TOKEN).unwrap();
    // Forward slashes: the path goes into a TOML string, where a Windows
    // backslash would start an escape.
    path.display().to_string().replace('\\', "/")
}

async fn get(url: &str) -> (u16, Value) {
    let r = client().get(url).send().await.unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn runs_are_stored_and_served_by_the_api() {
    let state = AppState::with_store(config(""), Store::open_in_memory().unwrap(), drifting());
    let zone = state.config.zones[0].clone();
    assert_eq!(run_zone(&state, &zone, "test").await, Ok(1));
    assert_eq!(run_zone(&state, &zone, "test").await, Ok(2));
    let base = serve(router(state)).await;

    let (status, health) = get(&format!("{base}/api/v1/health")).await;
    assert_eq!(status, 200);
    assert_eq!(health["status"], "ok");
    // Health is open to anyone who can reach the port, so it names no zones.
    assert_eq!(health.as_object().unwrap().len(), 2);

    let (_, zones) = get(&format!("{base}/api/v1/zones")).await;
    assert_eq!(zones["zones"][0]["zone"], "drift.example.");
    assert_eq!(zones["zones"][0]["runs"], 2);
    assert_eq!(zones["zones"][0]["open_findings"], 1);

    let (status, detail) = get(&format!("{base}/api/v1/zones/drift.example")).await;
    assert_eq!(status, 200);
    assert_eq!(detail["runs"].as_array().unwrap().len(), 2);
    assert_eq!(
        detail["last_run"]["nameservers"].as_array().unwrap().len(),
        2
    );
    assert_eq!(detail["names"].as_array().unwrap().len(), 4);
    assert_eq!(detail["findings"][0]["check_id"], "CON-02");
    assert_eq!(detail["findings"][0]["evidence"]["kind"], "rrset_mismatch");

    let (_, findings) = get(&format!("{base}/api/v1/findings?state=open")).await;
    assert_eq!(findings["findings"].as_array().unwrap().len(), 1);
    let (_, none) = get(&format!("{base}/api/v1/findings?state=resolved")).await;
    assert_eq!(none["findings"].as_array().unwrap().len(), 0);

    let (status, diff) = get(&format!("{base}/api/v1/diff?zone=drift.example")).await;
    assert_eq!(status, 200);
    assert_eq!(diff["changes"].as_array().unwrap().len(), 4);
    assert_eq!(
        (diff["from"]["id"].as_i64(), diff["to"]["id"].as_i64()),
        (Some(1), Some(2))
    );

    let (_, runs) = get(&format!("{base}/api/v1/runs?zone=drift.example")).await;
    assert_eq!(runs["runs"].as_array().unwrap().len(), 2);

    // Errors are JSON with a kind and a sensible status.
    let (status, err) = get(&format!("{base}/api/v1/diff?zone=unknown.example")).await;
    assert_eq!(
        (status, err["error"]["kind"].as_str()),
        (404, Some("unknown_zone"))
    );
    let (status, err) = get(&format!("{base}/api/v1/runs")).await;
    assert_eq!(
        (status, err["error"]["kind"].as_str()),
        (400, Some("missing_zone"))
    );
    let (status, err) = get(&format!("{base}/api/v1/findings?state=odd")).await;
    assert_eq!(
        (status, err["error"]["kind"].as_str()),
        (400, Some("invalid_state"))
    );
    let (status, err) = get(&format!("{base}/nothing-here")).await;
    assert_eq!(
        (status, err["error"]["kind"].as_str()),
        (404, Some("not_found"))
    );
}

#[tokio::test]
async fn the_ui_document_and_page() {
    let state = AppState::with_store(config(""), Store::open_in_memory().unwrap(), drifting());
    let zone = state.config.zones[0].clone();
    let base = serve(router(state.clone())).await;

    // Before any run: the zone is listed as pending.
    let (_, ui) = get(&format!("{base}/api/v1/ui")).await;
    assert_eq!(ui["zones"][0]["name"], "drift.example.");
    assert!(ui["zones"][0]["last_run_id"].is_null());
    assert_eq!(ui["zones"][0]["names"], 5);

    run_zone(&state, &zone, "test").await.unwrap();
    run_zone(&state, &zone, "test").await.unwrap();
    let (_, ui) = get(&format!("{base}/api/v1/ui")).await;
    let z = &ui["zones"][0];
    assert_eq!(z["last_run_id"], 2);
    assert_eq!(z["dnssec"], "Not signed");
    assert_eq!(
        z["path"],
        serde_json::json!([".", "example.", "drift.example."])
    );
    let ns = z["ns"].as_array().unwrap();
    assert_eq!(ns.len(), 2);
    assert_eq!(ns[0]["serial"], "2026111302");
    assert_eq!(
        (
            ns[0]["auth"].as_bool(),
            ns[0]["udp"].as_str(),
            ns[0]["v6"].as_str()
        ),
        (Some(true), Some("ok"), Some("none"))
    );
    assert_eq!(z["findings"][0]["id"], "CON-02");
    assert_eq!(z["findings"][0]["sev"], "warn");
    assert_eq!(z["findings"][0]["since"], "run 2");
    assert!(
        z["findings"][0]["ev"]
            .as_str()
            .unwrap()
            .contains("192.0.2.99")
    );
    let history = z["history"].as_array().unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(
        (history[0]["id"].as_i64(), history[0]["prev"].as_i64()),
        (Some(2), Some(1))
    );
    let changes: Vec<String> = history[0]["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| format!("{}{}", c[0].as_str().unwrap(), c[1].as_str().unwrap()))
        .collect();
    assert!(
        changes
            .iter()
            .any(|c| c.starts_with("-api") && c.contains("app.hosting.example.")),
        "{changes:?}"
    );
    assert!(
        changes
            .iter()
            .any(|c| c.starts_with("+staging") && c.contains("192.0.2.50")),
        "{changes:?}"
    );
    assert!(
        changes
            .iter()
            .any(|c| c.contains("only on ns1.drift.example.")),
        "{changes:?}"
    );
    assert!(history[1]["changes"].as_array().unwrap().is_empty());

    // The page itself is one self-contained document.
    let page = client().get(&base).send().await.unwrap();
    assert_eq!(page.status(), 200);
    assert!(
        page.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'self'")
    );
    let html = page.text().await.unwrap();
    assert!(html.contains("<title>zoneblick</title>"));
    assert!(html.contains("api/v1/"));
    assert!(
        !html.contains("fonts.googleapis.com"),
        "the UI makes no outside requests"
    );
}

#[tokio::test]
async fn a_triggered_run_happens_in_the_background() {
    let state = AppState::with_store(config(""), Store::open_in_memory().unwrap(), drifting());
    let base = serve(router(state)).await;
    let http = client();

    let r = http
        .post(format!("{base}/api/v1/runs"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 202);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["started"][0], "drift.example.");

    let mut stored = 0;
    for _ in 0..100 {
        let (_, zones) = get(&format!("{base}/api/v1/zones")).await;
        stored = zones["zones"][0]["runs"].as_i64().unwrap_or(0);
        if stored == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(stored, 1);

    let r = http
        .post(format!("{base}/api/v1/runs"))
        .json(&serde_json::json!({ "zone": "not-configured.example" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn the_api_token_is_enforced() {
    let token = "a-long-and-random-test-token";
    let extra = format!("[server]\ntoken_sha256 = \"{}\"", token_hash(token));
    let state = AppState::with_store(config(&extra), Store::open_in_memory().unwrap(), drifting());
    let base = serve(router(state)).await;
    let http = client();

    let (status, err) = get(&format!("{base}/api/v1/zones")).await;
    assert_eq!(
        (status, err["error"]["kind"].as_str()),
        (401, Some("unauthorized"))
    );
    let wrong = http
        .get(format!("{base}/api/v1/zones"))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);
    let post = http
        .post(format!("{base}/api/v1/runs"))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 401);
    let right = http
        .get(format!("{base}/api/v1/zones"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(right.status(), 200);

    // Health and the page itself need no token.
    assert_eq!(get(&format!("{base}/api/v1/health")).await.0, 200);
    assert_eq!(http.get(&base).send().await.unwrap().status(), 200);
}

#[tokio::test]
async fn alerts_go_to_the_webhook_on_changes_only() {
    // A local receiver that keeps what it is sent.
    let received: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = received.clone();
    let receiver = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap().push(body);
                "ok"
            }
        }),
    );
    let hook = serve(receiver).await;

    let extra = format!("[alerts.webhook]\nurl = \"{hook}/hook\"");
    let state = AppState::with_store(config(&extra), Store::open_in_memory().unwrap(), drifting());
    let zone = state.config.zones[0].clone();

    // First run: clean, so nothing is sent.
    run_zone(&state, &zone, "test").await.unwrap();
    assert!(received.lock().unwrap().is_empty());

    // Second run: records changed and a finding opened.
    run_zone(&state, &zone, "test").await.unwrap();
    {
        let got = received.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["zone"], "drift.example.");
        assert_eq!(got[0]["run"], 2);
        assert_eq!(got[0]["severity"], "warning");
        assert_eq!(
            got[0]["title"],
            "zoneblick: drift.example. 1 new finding, 4 changes"
        );
        assert!(got[0]["text"].as_str().unwrap().contains("OPENED CON-02"));
        assert_eq!(got[0]["changes"].as_array().unwrap().len(), 4);
    }

    // Third run: the same state again, so nothing new.
    run_zone(&state, &zone, "test").await.unwrap();
    assert_eq!(received.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_failed_run_is_reported_not_stored() {
    let broken: ClientFactory = Arc::new(|_| {
        Arc::new(Client::replay(&Fixture {
            version: Fixture::VERSION,
            zone: "drift.example.".to_string(),
            started_at_unix: 1,
            exchanges: vec![],
            http: vec![],
        }))
    });
    let state = AppState::with_store(config(""), Store::open_in_memory().unwrap(), broken);
    let zone = state.config.zones[0].clone();
    let err = run_zone(&state, &zone, "test").await.unwrap_err();
    assert!(err.contains("no root server answered"), "{err}");
    let base = serve(router(state)).await;
    let (_, ui) = get(&format!("{base}/api/v1/ui")).await;
    assert!(
        ui["zones"][0]["error"]
            .as_str()
            .unwrap()
            .contains("no root server answered")
    );
    assert!(ui["zones"][0]["last_run_id"].is_null());
}

#[tokio::test]
async fn findings_are_muted_through_the_api() {
    let state = AppState::with_store(config(""), Store::open_in_memory().unwrap(), drifting());
    let zone = state.config.zones[0].clone();
    run_zone(&state, &zone, "test").await.unwrap();
    run_zone(&state, &zone, "test").await.unwrap();
    let base = serve(router(state)).await;
    let http = client();

    let (_, ui) = get(&format!("{base}/api/v1/ui")).await;
    let finding = &ui["zones"][0]["findings"][0];
    assert_eq!(finding["muted"], false);
    let key = finding["key"].as_str().unwrap().to_string();

    let post = |path: &'static str, body: Value| {
        let (http, base) = (http.clone(), base.clone());
        async move {
            let r = http
                .post(format!("{base}/api/v1/findings/{path}"))
                .json(&body)
                .send()
                .await
                .unwrap();
            (
                r.status().as_u16(),
                r.json::<Value>().await.unwrap_or(Value::Null),
            )
        }
    };
    let body = serde_json::json!({ "zone": "drift.example", "id": &key[..12] });
    let (status, out) = post("mute", body.clone()).await;
    assert_eq!(status, 200);
    assert_eq!(out["finding"]["state"], "muted");
    let (_, zones) = get(&format!("{base}/api/v1/zones")).await;
    assert_eq!(zones["zones"][0]["open_findings"], 0);
    let (_, ui) = get(&format!("{base}/api/v1/ui")).await;
    assert_eq!(ui["zones"][0]["findings"][0]["muted"], true);

    let (status, out) = post("unmute", body).await;
    assert_eq!(
        (status, &out["finding"]["state"]),
        (200, &Value::from("open"))
    );
    let (status, out) = post(
        "mute",
        serde_json::json!({ "zone": "drift.example", "id": "no-such-finding" }),
    )
    .await;
    assert_eq!(
        (status, &out["error"]["kind"]),
        (404, &Value::from("unknown_finding"))
    );
}

#[tokio::test]
async fn a_deep_run_is_made_when_asked_or_due() {
    // Not configured, not asked for: light runs only.
    let db = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("serve_deep.sqlite");
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", db.display()));
    }
    let state = AppState::with_store(config(""), Store::open(&db).unwrap(), drifting());
    let zone = state.config.zones[0].clone();
    run_zone(&state, &zone, "test").await.unwrap();
    run_zone_level(&state, &zone, "test", true).await.unwrap();
    run_zone(&state, &zone, "test").await.unwrap();

    // With deep = "1h": the first run is deep, the next ones are not yet due.
    let scheduled = AppState::with_store(
        Config::parse(
            "[schedule]\ndeep = \"1h\"\n[[zone]]\nname = \"drift.example\"\nseeds = [\"www\"]\n",
        )
        .unwrap(),
        Store::open(&db).unwrap(),
        drifting(),
    );
    let zone = scheduled.config.zones[0].clone();
    run_zone(&scheduled, &zone, "test").await.unwrap();
    run_zone(&scheduled, &zone, "test").await.unwrap();
    drop((state, scheduled));

    let conn = rusqlite::Connection::open(&db).unwrap();
    let levels: Vec<String> = conn
        .prepare("SELECT level FROM runs ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(levels, ["light", "deep", "light", "deep", "light"]);
    assert!(Config::parse("[schedule]\ndeep = \"sometimes\"\n").is_err());
    assert!(Config::parse("[schedule]\ndeep = \"off\"\n").is_ok());
}

#[tokio::test]
async fn metrics_are_served_in_the_prometheus_text_format() {
    let state = AppState::with_store(config(""), Store::open_in_memory().unwrap(), drifting());
    let zone = state.config.zones[0].clone();
    assert_eq!(run_zone(&state, &zone, "test").await, Ok(1));
    assert_eq!(run_zone(&state, &zone, "test").await, Ok(2));
    let base = serve(router(state)).await;

    let r = client()
        .get(format!("{base}/api/v1/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert!(
        r.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let text = r.text().await.unwrap();
    for line in [
        "# TYPE zoneblick_open_findings gauge",
        "zoneblick_open_findings{zone=\"drift.example.\",severity=\"warning\"} 1",
        "zoneblick_open_findings{zone=\"drift.example.\",severity=\"critical\"} 0",
        "zoneblick_stored_runs{zone=\"drift.example.\"} 2",
        "zoneblick_names{zone=\"drift.example.\"} 4",
        "zoneblick_last_run_failed{zone=\"drift.example.\"} 0",
    ] {
        assert!(
            text.lines().any(|l| l == line),
            "missing {line} in:\n{text}"
        );
    }
    assert!(text.contains("zoneblick_last_run_timestamp_seconds{zone=\"drift.example.\"} "));
    assert!(text.starts_with("# HELP zoneblick_info "));
}

#[tokio::test]
async fn metrics_need_the_token_when_one_is_set() {
    let hash = token_hash("s3cret-token");
    let state = AppState::with_store(
        config(&format!("[server]\ntoken_sha256 = \"{hash}\"")),
        Store::open_in_memory().unwrap(),
        drifting(),
    );
    let base = serve(router(state)).await;
    let url = format!("{base}/api/v1/metrics");
    let http = client();
    assert_eq!(http.get(&url).send().await.unwrap().status().as_u16(), 401);
    let ok = http
        .get(&url)
        .bearer_auth("s3cret-token")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status().as_u16(), 200);
}

#[tokio::test]
async fn the_ui_gets_a_timeline_and_can_compare_any_two_runs() {
    let state = AppState::with_store(config(""), Store::open_in_memory().unwrap(), drifting());
    let zone = state.config.zones[0].clone();
    for run in 1..=3 {
        assert_eq!(run_zone(&state, &zone, "test").await, Ok(run));
    }
    let base = serve(router(state)).await;

    let (_, ui) = get(&format!("{base}/api/v1/ui")).await;
    let timeline = ui["zones"][0]["timeline"].as_array().unwrap();
    let ticks: Vec<(i64, u64, u64)> = timeline
        .iter()
        .map(|t| {
            (
                t["id"].as_i64().unwrap(),
                t["warn"].as_u64().unwrap(),
                t["crit"].as_u64().unwrap(),
            )
        })
        .collect();
    // Clean before the drift, one warning after it; oldest first.
    assert_eq!(ticks, [(1, 0, 0), (2, 1, 0), (3, 1, 0)]);

    // Runs 1 and 3, in either order, give the changes of the drift.
    let (status, d) = get(&format!(
        "{base}/api/v1/ui/diff?zone=drift.example&from=3&to=1"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!((d["from"].as_i64(), d["to"].as_i64()), (Some(1), Some(3)));
    let changes = d["changes"].as_array().unwrap();
    assert!(changes.iter().any(|c| c[0] == "+"), "{changes:?}");
    assert!(changes.iter().any(|c| c[0] == "-"), "{changes:?}");
    // Runs 2 and 3 hold the same data.
    let (_, same) = get(&format!("{base}/api/v1/ui/diff?zone=drift.example&to=3")).await;
    assert_eq!(same["from"], 2);
    assert_eq!(same["changes"].as_array().unwrap().len(), 0);
    // The first run has nothing before it.
    let (status, err) = get(&format!("{base}/api/v1/ui/diff?zone=drift.example&to=1")).await;
    assert_eq!(status, 409, "{err}");
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("needs two"),
        "{err}"
    );
}

#[tokio::test]
async fn every_response_carries_the_hardening_headers() {
    let state = AppState::with_store(config(""), Store::open_in_memory().unwrap(), drifting());
    let base = serve(router(state)).await;
    let http = client();
    for path in [
        "/",
        "/api/v1/health",
        "/api/v1/zones",
        "/api/v1/metrics",
        "/nope",
    ] {
        let r = http.get(format!("{base}{path}")).send().await.unwrap();
        let h = r.headers();
        assert_eq!(h["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(h["x-frame-options"], "DENY", "{path}");
        assert_eq!(h["referrer-policy"], "no-referrer", "{path}");
        // The page itself may be revalidated; API answers are never stored.
        let cache = h["cache-control"].to_str().unwrap();
        assert_eq!(
            cache,
            if path == "/" { "no-cache" } else { "no-store" },
            "{path}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_run_that_does_not_finish_is_stopped_and_alerted_once() {
    let received: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = received.clone();
    let receiver = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap().push(body);
                "ok"
            }
        }),
    );
    let hook = serve(receiver).await;

    // The first two runs hang (as a tarpit nameserver would make them),
    // the third answers.
    let runs = AtomicUsize::new(0);
    let good = fixture("drift.example.before.json");
    let factory: ClientFactory = Arc::new(move |_zone| {
        if runs.fetch_add(1, Ordering::SeqCst) < 2 {
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
        Arc::new(Client::replay(&good))
    });
    let extra =
        format!("[schedule]\nrun_timeout = \"1s\"\n[alerts.webhook]\nurl = \"{hook}/hook\"");
    let state = AppState::with_store(config(&extra), Store::open_in_memory().unwrap(), factory);
    let zone = state.config.zones[0].clone();

    let err = run_zone(&state, &zone, "test").await.unwrap_err();
    assert!(err.contains("did not finish within 1s"), "{err}");
    {
        let got = received.lock().unwrap();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0]["kind"], "run_failed");
        assert_eq!(got[0]["severity"], "critical");
        assert_eq!(
            got[0]["title"],
            "zoneblick: drift.example. could not be checked"
        );
    }
    // Still failing: no second alert.
    assert!(run_zone(&state, &zone, "test").await.is_err());
    assert_eq!(received.lock().unwrap().len(), 1);

    // The zone is not stuck in "running", and metrics show the failure.
    let base = serve(router(state.clone())).await;
    let (_, ui) = get(&format!("{base}/api/v1/ui")).await;
    assert_eq!(ui["zones"][0]["running"], false);
    assert!(
        ui["zones"][0]["error"]
            .as_str()
            .unwrap()
            .contains("did not finish")
    );

    // Let the stalled runs' threads end, then a good run clears the error.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert!(run_zone(&state, &zone, "test").await.is_ok());
    let (_, ui) = get(&format!("{base}/api/v1/ui")).await;
    assert_eq!(ui["zones"][0]["error"], Value::Null);
    assert!(ui["zones"][0]["last_run_id"].as_i64().unwrap() >= 1);
}

#[tokio::test]
async fn a_run_is_compared_with_another_vantage_point() {
    // The vantage point: a daemon that has only seen the zone's old state.
    let old = fixture("drift.example.before.json");
    let far = AppState::with_store(
        config(""),
        Store::open_in_memory().unwrap(),
        Arc::new(move |_| Arc::new(Client::replay(&old))),
    );
    let zone = far.config.zones[0].clone();
    run_zone(&far, &zone, "test").await.unwrap();
    let far_url = serve(router(far)).await;

    let (status, report) = get(&format!("{far_url}/api/v1/vantage?zone=drift.example")).await;
    assert_eq!(status, 200);
    assert_eq!(report["zone"], "drift.example.");
    assert!(report["sets"].as_array().unwrap().len() > 3);
    assert_eq!(report["servers"].as_array().unwrap().len(), 2);

    // Here: the zone's new state, plus one vantage point that is down.
    let new = fixture("drift.example.after.json");
    let extra = format!(
        "[[vantage]]\nname = \"far\"\nurl = \"{far_url}\"\ntoken_file = \"{}\"\n[[vantage]]\nname = \"gone\"\nurl = \"http://127.0.0.1:9\"\n",
        token_file()
    );
    let here = AppState::with_store(
        config(&extra),
        Store::open_in_memory().unwrap(),
        Arc::new(move |_| Arc::new(Client::replay(&new))),
    );
    run_zone(&here, &zone, "test").await.unwrap();
    let base = serve(router(here)).await;
    let (_, findings) = get(&format!("{base}/api/v1/findings?state=open")).await;
    let mut got: Vec<(String, String)> = findings["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["check_id"].as_str().unwrap().starts_with("VAN"))
        .map(|f| {
            (
                f["check_id"].as_str().unwrap().to_string(),
                f["name"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    got.sort();
    let expect = |id: &str, name: &str| (id.to_string(), name.to_string());
    assert_eq!(
        got,
        [
            expect("VAN-01", "api.drift.example."),
            expect("VAN-01", "drift.example."),
            expect("VAN-01", "shop.drift.example."),
            expect("VAN-01", "staging.drift.example."),
            expect("VAN-03", "drift.example."),
        ],
        "{findings}"
    );
}

#[tokio::test]
async fn a_hostile_vantage_point_cannot_inject_or_redirect() {
    // Three stand-ins for a compromised vantage daemon: one that answers
    // with escape sequences in its data, one that redirects (to carry the
    // request, and its token, elsewhere), and one that never stops sending.
    let seen_elsewhere = Arc::new(AtomicUsize::new(0));
    let counter = seen_elsewhere.clone();
    let elsewhere = serve(axum::Router::new().fallback(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        async { "caught" }
    }))
    .await;
    let evil_report = serde_json::json!({
        "zone": "drift.example.",
        "run_started_unix": u64::MAX,
        "sets": [
            {"name": "www.drift.example.", "rtype": "A", "rdata": ["\u{1b}[2J\u{1b}]0;owned\u{7}", "x\n::error::y"]},
            {"name": "\u{1b}[31mevil", "rtype": "\n", "rdata": []}
        ],
        "servers": [{"ns_name": "\u{1b}[2Jns", "address": "198.51.100.1", "answered": false}]
    })
    .to_string();
    let target = format!("{elsewhere}/steal");
    let hostile = serve(
        axum::Router::new()
            .route(
                "/evil/api/v1/vantage",
                axum::routing::get(move || {
                    let body = evil_report.clone();
                    async move {
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            body,
                        )
                    }
                }),
            )
            .route(
                "/redirect/api/v1/vantage",
                axum::routing::get(move || {
                    let target = target.clone();
                    async move { axum::response::Redirect::temporary(&target) }
                }),
            )
            .route(
                "/flood/api/v1/vantage",
                axum::routing::get(|| async { "x".repeat(9 * 1024 * 1024) }),
            ),
    )
    .await;

    let extra = format!(
        "[[vantage]]\nname = \"evil\"\nurl = \"{hostile}/evil\"\n[[vantage]]\nname = \"redirect\"\nurl = \"{hostile}/redirect\"\n[[vantage]]\nname = \"flood\"\nurl = \"{hostile}/flood\"\n"
    );
    let state = AppState::with_store(config(&extra), Store::open_in_memory().unwrap(), drifting());
    let zone = state.config.zones[0].clone();
    run_zone(&state, &zone, "test").await.unwrap();
    assert_eq!(
        seen_elsewhere.load(Ordering::SeqCst),
        0,
        "the redirect was followed"
    );

    let base = serve(router(state)).await;
    let r = client()
        .get(format!("{base}/api/v1/findings?state=open"))
        .send()
        .await
        .unwrap();
    let text = r.text().await.unwrap();
    let findings: Value = serde_json::from_str(&text).unwrap();
    let van: Vec<&Value> = findings["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["check_id"].as_str().unwrap().starts_with("VAN"))
        .collect();
    // The evil report's run time is absurd, so it is stale: not compared.
    // All three end up as "gave nothing to compare with".
    assert_eq!(van.len(), 1, "{van:?}");
    assert_eq!(van[0]["check_id"], "VAN-03");
    let details = van[0]["evidence"]["details"].to_string();
    assert!(
        details.contains("redirect: the vantage point answered HTTP 307"),
        "{details}"
    );
    assert!(
        details.contains("flood: the report is too large"),
        "{details}"
    );
    // Nothing from the hostile side reaches stored findings unescaped.
    let stored = serde_json::to_string(&findings).unwrap();
    assert!(
        !stored.contains("\\u001b") && !stored.contains("owned"),
        "{stored}"
    );
}

#[tokio::test]
async fn data_from_a_vantage_point_is_escaped_in_findings() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let report = serde_json::json!({
        "zone": "drift.example.",
        "run_started_unix": now,
        "sets": [{"name": "www.drift.example.", "rtype": "A",
                  "rdata": ["\u{1b}[2J\u{1b}]0;owned\u{7}", "x\n::error::y"]}],
        "servers": [{"ns_name": "\u{1b}[2Jns", "address": "198.51.100.1", "answered": false}]
    })
    .to_string();
    let hostile = serve(axum::Router::new().route(
        "/api/v1/vantage",
        axum::routing::get(move || {
            let body = report.clone();
            async move {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    body,
                )
            }
        }),
    ))
    .await;
    let extra = format!("[[vantage]]\nname = \"evil\"\nurl = \"{hostile}\"\n");
    let state = AppState::with_store(config(&extra), Store::open_in_memory().unwrap(), drifting());
    let zone = state.config.zones[0].clone();
    run_zone(&state, &zone, "test").await.unwrap();
    let base = serve(router(state)).await;
    let text = client()
        .get(format!("{base}/api/v1/findings?state=open"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let findings: Value = serde_json::from_str(&text).unwrap();
    let ids: Vec<&str> = findings["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["check_id"].as_str().unwrap())
        .filter(|id| id.starts_with("VAN"))
        .collect();
    // The differences are reported...
    assert!(
        ids.contains(&"VAN-01") && ids.contains(&"VAN-02"),
        "{ids:?}"
    );
    // ...with the control characters written out, not passed on.
    assert!(
        !text.contains("\\u001b") && !text.contains("\\u0007"),
        "{text}"
    );
    assert!(text.contains("\\\\027[2J"), "{text}");
    assert!(!text.contains("x\\n::error"), "{text}");
}

#[cfg(unix)]
#[tokio::test]
async fn the_socket_file_is_only_made_where_it_is_safe() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("sock");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let start = |path: &std::path::Path| {
        let extra = format!("[server]\nbind = \"unix:{}\"\n", path.display());
        let state =
            AppState::with_store(config(&extra), Store::open_in_memory().unwrap(), drifting());
        zoneblick::serve::serve(state, async {})
    };

    // A file that is not a socket is never replaced.
    let precious = dir.join("precious.sqlite");
    std::fs::write(&precious, "data").unwrap();
    let err = start(&precious).await.unwrap_err().to_string();
    assert!(err.contains("not a socket"), "{err}");
    assert_eq!(std::fs::read_to_string(&precious).unwrap(), "data");

    // A directory other users can write to is refused.
    let shared = dir.join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = start(&shared.join("z.sock")).await.unwrap_err().to_string();
    assert!(err.contains("can be written to by other users"), "{err}");
    assert!(
        std::fs::read_dir(&shared).unwrap().next().is_none(),
        "nothing was left behind"
    );
}

#[tokio::test]
async fn the_api_needs_the_token_however_local_a_request_looks() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // No token in the config: the daemon has one all the same, and
    // nothing that makes a request look local replaces it.
    let state = AppState::with_store(
        Config::parse("[[zone]]\nname = \"drift.example\"\n").unwrap(),
        Store::open_in_memory().unwrap(),
        drifting(),
    );
    let base = serve(router(state)).await;
    let addr = base.trim_start_matches("http://").to_string();
    let bare = reqwest::Client::builder().build().unwrap();
    for path in [
        "/api/v1/zones",
        "/api/v1/ui",
        "/api/v1/metrics",
        "/api/v1/vantage?zone=drift.example",
    ] {
        let r = bare.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(r.status().as_u16(), 401, "{path}");
    }
    // As a reverse proxy on this machine would send it, in each of the
    // ways the earlier heuristics looked for and the one they missed.
    for request in [
        format!("GET /api/v1/zones HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
        format!("GET /api/v1/zones HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
        "GET /api/v1/zones HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.9\r\nConnection: close\r\n\r\n".to_string(),
    ] {
        let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        assert!(answer.contains(" 401 "), "{answer}");
    }
    let r = bare
        .post(format!("{base}/api/v1/runs"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    // Health says only that the daemon is up, and stays open.
    let r = bare
        .get(format!("{base}/api/v1/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    // With the token, a request from another site is still refused.
    let state = AppState::with_store(config(""), Store::open_in_memory().unwrap(), drifting());
    let base = serve(router(state)).await;
    let r = client()
        .post(format!("{base}/api/v1/runs"))
        .header("Origin", "https://evil.example")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403);
}

#[test]
fn a_token_is_made_once_and_kept_private() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("token-dir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("api-token");
    let first = zoneblick::serve::load_or_make_token(&path).unwrap();
    assert_eq!(first.len(), 64);
    assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
    // The next start reads the same token.
    assert_eq!(zoneblick::serve::load_or_make_token(&path).unwrap(), first);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
    }
    // A file that holds no real token is not silently accepted.
    std::fs::write(&path, "short\n").unwrap();
    assert!(zoneblick::serve::load_or_make_token(&path).is_err());
}
