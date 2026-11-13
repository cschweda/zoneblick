//! The daemon, offline: scheduled runs replay recorded DNS, the API and UI
//! are served on a loopback port, and alerts go to a local receiver.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use zoneblick::config::Config;
use zoneblick::resolver::{Client, Fixture};
use zoneblick::serve::{AppState, ClientFactory, router, run_zone, token_hash};
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

fn config(extra: &str) -> Config {
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

async fn get(url: &str) -> (u16, Value) {
    let r = reqwest::Client::new().get(url).send().await.unwrap();
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
    assert_eq!(health["zones"], 1);

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
    let page = reqwest::Client::new().get(&base).send().await.unwrap();
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
    let http = reqwest::Client::new();

    let r = http
        .post(format!("{base}/api/v1/runs"))
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
    let http = reqwest::Client::new();

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
