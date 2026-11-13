//! The daemon: a scheduler that checks every configured zone on an
//! interval, a JSON API under `/api/v1`, and the embedded web UI.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::alerts;
use crate::checks::{CATALOG, Severity};
use crate::config::{Config, ZoneConfig};
use crate::diff::{ChangeKind, DiffReport, RunRef};
use crate::observe::{Outcome, QType, ServerProbe, Transport};
use crate::output::{human, utc};
use crate::resolver::{Client, NetConfig, normalise_zone, observe_zone_records};
use crate::runner::store_observation;
use crate::store::{RunView, Store, StoreError};

/// The web UI, compiled into the binary.
const UI_HTML: &str = include_str!("ui/index.html");

/// How many runs the UI's history tab shows per zone.
const HISTORY_RUNS: usize = 10;

/// Makes the DNS client for one run. Tests swap in a replaying client.
pub type ClientFactory = Arc<dyn Fn(&str) -> Arc<Client> + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("cannot create the data directory {path}: {source}")]
    DataDir {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("cannot listen on {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("the server stopped: {0}")]
    Io(#[from] std::io::Error),
}

pub struct AppState {
    pub config: Config,
    store: Mutex<Store>,
    client_factory: ClientFactory,
    http: reqwest::Client,
    /// Zones being checked right now.
    running: Mutex<BTreeSet<String>>,
    /// The last failure of each zone's run, cleared by a good run.
    errors: Mutex<BTreeMap<String, String>>,
    next_run_unix: Mutex<Option<u64>>,
    /// When each zone's names were last looked up in certificate logs.
    discovered_at: Mutex<BTreeMap<String, u64>>,
    /// When each zone last had a deep run.
    deep_at: Mutex<BTreeMap<String, u64>>,
}

/// Certificate logs are asked at most this often per zone.
const DISCOVER_EVERY_SECS: u64 = 86_400;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn log(message: &str) {
    eprintln!("{}  {message}", utc(now_unix()));
}

impl AppState {
    /// Open the database in the configured data directory.
    pub fn new(config: Config, client_factory: ClientFactory) -> Result<Arc<Self>, ServeError> {
        std::fs::create_dir_all(&config.server.data_dir).map_err(|source| ServeError::DataDir {
            path: config.server.data_dir.clone(),
            source,
        })?;
        let store = Store::open(&config.db_path())?;
        Ok(Self::with_store(config, store, client_factory))
    }

    pub fn with_store(config: Config, store: Store, client_factory: ClientFactory) -> Arc<Self> {
        // TLS for outgoing alerts. Installing twice is harmless.
        let _ = rustls::crypto::ring::default_provider().install_default();
        Arc::new(Self {
            config,
            store: Mutex::new(store),
            client_factory,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .user_agent(concat!("zoneblick/", env!("CARGO_PKG_VERSION")))
                .build()
                .unwrap_or_default(),
            running: Mutex::new(BTreeSet::new()),
            errors: Mutex::new(BTreeMap::new()),
            next_run_unix: Mutex::new(None),
            discovered_at: Mutex::new(BTreeMap::new()),
            deep_at: Mutex::new(BTreeMap::new()),
        })
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().expect("store lock")
    }

    fn zone_config(&self, zone: &str) -> Option<&ZoneConfig> {
        self.config.zones.iter().find(|z| z.name == zone)
    }
}

/// The live DNS client the daemon uses, with the configured rate cap.
pub fn live_client_factory(config: &Config) -> ClientFactory {
    let qps = config.schedule.max_qps_per_server;
    Arc::new(move |_zone| {
        Arc::new(Client::live(NetConfig {
            qps_per_server: qps,
            ..NetConfig::default()
        }))
    })
}

/// Check one configured zone now: observe, store, and alert on changes.
/// Returns the run ID, or why the run failed.
pub async fn run_zone(
    state: &Arc<AppState>,
    zone: &ZoneConfig,
    trigger: &str,
) -> Result<i64, String> {
    run_zone_level(state, zone, trigger, false).await
}

/// [`run_zone`], with `deep` to make this run a deep one whether or not
/// one is due.
pub async fn run_zone_level(
    state: &Arc<AppState>,
    zone: &ZoneConfig,
    trigger: &str,
    deep: bool,
) -> Result<i64, String> {
    if !state
        .running
        .lock()
        .expect("lock")
        .insert(zone.name.clone())
    {
        return Err("a run of this zone is already in progress".to_string());
    }
    let result = run_zone_inner(state, zone, trigger, deep).await;
    state.running.lock().expect("lock").remove(&zone.name);
    match &result {
        Ok(id) => {
            state.errors.lock().expect("lock").remove(&zone.name);
            log(&format!("{} run #{id} stored ({trigger})", zone.name));
        }
        Err(e) => {
            state
                .errors
                .lock()
                .expect("lock")
                .insert(zone.name.clone(), e.clone());
            log(&format!("{} run failed: {e}", zone.name));
        }
    }
    result
}

async fn run_zone_inner(
    state: &Arc<AppState>,
    zone: &ZoneConfig,
    trigger: &str,
    force_deep: bool,
) -> Result<i64, String> {
    // Names: the seeds in the config plus any remembered from `zoneblick run`.
    let mut names = zone.seeds.clone();
    for name in state.store().names(&zone.name).map_err(|e| e.to_string())? {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let client = (state.client_factory)(&zone.name);
    let started = now_unix();

    // More names from certificate logs, when the zone asks for that.
    let mut discovered = Vec::new();
    let mut provided: Vec<String> = Vec::new();
    let due = state
        .discovered_at
        .lock()
        .expect("lock")
        .get(&zone.name)
        .is_none_or(|at| started >= at + DISCOVER_EVERY_SECS);
    let due = due && !zone.discover.is_empty();
    if due {
        state
            .discovered_at
            .lock()
            .expect("lock")
            .insert(zone.name.clone(), started);
    }
    if due && zone.discover.iter().any(|d| d == "ct") {
        match crate::discover::ct_names(&client, &zone.name).await {
            Ok(found) => {
                discovered = found.into_iter().filter(|n| !names.contains(n)).collect();
                if !discovered.is_empty() {
                    log(&format!(
                        "{} found {} new names in certificate logs",
                        zone.name,
                        discovered.len()
                    ));
                }
                names.extend(discovered.iter().cloned());
            }
            Err(e) => log(&format!("{} discovery failed: {e}", zone.name)),
        }
    }
    if due && zone.discover.iter().any(|d| d == "digitalocean") {
        let found = match state
            .config
            .providers
            .digitalocean
            .as_ref()
            .map(|p| p.token())
        {
            Some(Ok(token)) => {
                crate::discover::digitalocean_names(&client, &zone.name, &token).await
            }
            Some(Err(e)) => Err(e),
            None => Err("no [providers.digitalocean] section".to_string()),
        };
        match found {
            Ok(found) => {
                let new: Vec<String> = found.into_iter().filter(|n| !names.contains(n)).collect();
                if !new.is_empty() {
                    log(&format!(
                        "{} found {} new names at DigitalOcean",
                        zone.name,
                        new.len()
                    ));
                }
                names.extend(new.iter().cloned());
                provided = new;
            }
            Err(e) => log(&format!("{} discovery failed: {e}", zone.name)),
        }
    }
    names.sort();

    let mut obs = observe_zone_records(client.clone(), &zone.name, started, &names)
        .await
        .map_err(|e| e.to_string())?;
    // A deep run, when one is asked for or due for this zone.
    let deep_due = match state.config.deep_interval() {
        Ok(Some(every)) => state
            .deep_at
            .lock()
            .expect("lock")
            .get(&zone.name)
            .is_none_or(|at| started >= at + every.as_secs()),
        _ => false,
    };
    if force_deep || deep_due {
        crate::resolver::add_deep(client.clone(), &mut obs).await;
        state
            .deep_at
            .lock()
            .expect("lock")
            .insert(zone.name.clone(), started);
    }
    // A zone transfer, when the zone asks for that and a server allows it.
    // Names it finds are checked from the next run on.
    let mut transferred = Vec::new();
    if due && zone.discover.iter().any(|d| d == "axfr") && client.is_live() {
        match crate::discover::axfr_names(&zone.name, &crate::discover::servers_of(&obs)).await {
            Ok(found) => transferred = found,
            Err(e) => log(&format!("{} zone transfer not available: {e}", zone.name)),
        }
    }
    let outcome = {
        let mut store = state.store();
        let outcome = store_observation(
            &mut store,
            obs,
            names,
            client.queries_sent(),
            now_unix(),
            trigger,
            &zone.ignore,
        )
        .map_err(|e| e.to_string())?;
        store
            .set_name_source(&zone.name, &discovered, "ct")
            .map_err(|e| e.to_string())?;
        store
            .set_name_source(&zone.name, &provided, "digitalocean")
            .map_err(|e| e.to_string())?;
        let added = store
            .add_names(&zone.name, &transferred, "axfr", outcome.run_id)
            .map_err(|e| e.to_string())?;
        if added > 0 {
            log(&format!(
                "{} found {added} new names by zone transfer",
                zone.name
            ));
        }
        outcome
    };

    if let Some(alert) = alerts::compose(&outcome) {
        for (sink, result) in alerts::send(&alert, &state.config.alerts, &state.http).await {
            match result {
                Ok(()) => log(&format!("{} alert sent by {sink}", zone.name)),
                Err(e) => log(&format!("{} alert by {sink} failed: {e}", zone.name)),
            }
        }
    }
    Ok(outcome.run_id)
}

/// Check every configured zone, one after another.
pub async fn run_all_zones(state: &Arc<AppState>, trigger: &str) {
    for zone in &state.config.zones {
        let _ = run_zone(state, zone, trigger).await;
    }
}

/// Delete runs older than the configured retention allows.
fn prune(state: &Arc<AppState>) {
    let Ok((keep_all, keep_daily)) = state.config.retention.limits() else {
        return;
    };
    match state.store().prune(now_unix(), keep_all, keep_daily) {
        Ok(p) if p.runs > 0 => log(&format!("pruned {} old runs", p.runs)),
        Ok(_) => {}
        Err(e) => log(&format!("pruning failed: {e}")),
    }
}

/// The scheduler: check every zone at startup, then once per interval.
async fn scheduler(state: Arc<AppState>, every: Duration) {
    loop {
        run_all_zones(&state, "schedule").await;
        prune(&state);
        *state.next_run_unix.lock().expect("lock") = Some(now_unix() + every.as_secs());
        tokio::time::sleep(every).await;
    }
}

/// Run the daemon until `shutdown` resolves.
pub async fn serve(
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServeError> {
    let addr = state.config.bind_addr()?;
    let every = state.config.interval()?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|source| ServeError::Bind { addr, source })?;
    log(&format!(
        "zoneblick {} listening on http://{addr}, {} zones, checking every {}",
        env!("CARGO_PKG_VERSION"),
        state.config.zones.len(),
        state.config.schedule.every
    ));
    if state.config.server.token_sha256.is_none() {
        log("no API token is set; the API is open to this machine only");
    }
    let job = tokio::spawn(scheduler(state.clone(), every));
    let result = axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown)
        .await;
    job.abort();
    Ok(result?)
}

// ---------------------------------------------------------------- the API

/// An API error: a status code and a JSON body.
struct ApiError(StatusCode, &'static str, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": { "kind": self.1, "message": self.2 } });
        (self.0, Json(body)).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        let (status, kind) = match &e {
            StoreError::UnknownZone { .. } => (StatusCode::NOT_FOUND, "unknown_zone"),
            StoreError::UnknownRun { .. } => (StatusCode::NOT_FOUND, "unknown_run"),
            StoreError::NotEnoughRuns { .. } => (StatusCode::CONFLICT, "not_enough_runs"),
            StoreError::UnknownFinding { .. } => (StatusCode::NOT_FOUND, "unknown_finding"),
            StoreError::AmbiguousFinding { .. } => (StatusCode::BAD_REQUEST, "ambiguous_finding"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "store_error"),
        };
        ApiError(status, kind, e.to_string())
    }
}

fn bad_zone(input: &str) -> ApiError {
    ApiError(
        StatusCode::BAD_REQUEST,
        "invalid_name",
        format!("'{input}' is not a valid zone name"),
    )
}

/// Compare two strings without stopping at the first difference.
fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// The SHA-256 of a token, in hex, as stored in the config file.
pub fn token_hash(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The host part of a `Host` or `Origin` value, without scheme or port.
fn host_only(value: &str) -> &str {
    let value = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
        .unwrap_or(value);
    if let Some(end) = value.find(']') {
        // An IPv6 literal: keep the brackets, drop any port.
        return &value[..=end];
    }
    value.split(':').next().unwrap_or(value)
}

fn forbidden(kind: &'static str, message: &str) -> Response {
    ApiError(StatusCode::FORBIDDEN, kind, message.to_string()).into_response()
}

/// Guard the API routes.
///
/// - With a token configured, every request must carry it.
/// - Without one, the server only ever listens on loopback, and the request
///   must have been addressed to a loopback name. That stops a web page
///   from reaching the API through a hostname it has pointed at 127.0.0.1
///   (DNS rebinding).
/// - A request that changes something must not come from another site.
async fn require_token(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    let header_str = |name: header::HeaderName| headers.get(name).and_then(|v| v.to_str().ok());
    let host = header_str(header::HOST).unwrap_or("");

    if let Some(expected) = &state.config.server.token_sha256 {
        let given = header_str(header::AUTHORIZATION)
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(token_hash);
        let ok = given.is_some_and(|hash| constant_time_eq(&hash, &expected.to_ascii_lowercase()));
        if !ok {
            return ApiError(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "a valid API token is required: send it as 'Authorization: Bearer <token>'"
                    .to_string(),
            )
            .into_response();
        }
    } else if !matches!(host_only(host), "localhost" | "127.0.0.1" | "[::1]") {
        return forbidden(
            "forbidden_host",
            "without an API token, zoneblick only answers requests addressed to localhost",
        );
    }

    if !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    ) {
        let fetch_site = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok());
        if fetch_site.is_some_and(|site| !matches!(site, "same-origin" | "none")) {
            return forbidden("cross_site", "requests from other sites are not accepted");
        }
        if let Some(origin) = header_str(header::ORIGIN) {
            let origin = origin
                .strip_prefix("http://")
                .or_else(|| origin.strip_prefix("https://"))
                .unwrap_or(origin);
            if origin != host {
                return forbidden("cross_site", "requests from other sites are not accepted");
            }
        }
    }
    next.run(request).await
}

pub fn router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/zones", get(api_zones))
        .route("/zones/{zone}", get(api_zone))
        .route("/runs", get(api_runs).post(api_trigger))
        .route("/findings", get(api_findings))
        .route("/findings/mute", axum::routing::post(api_mute))
        .route("/findings/unmute", axum::routing::post(api_unmute))
        .route("/diff", get(api_diff))
        .route("/ui", get(api_ui))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token))
        // Health needs no token, so a load balancer or uptime check can use it.
        .route("/health", get(api_health));
    Router::new()
        .route("/", get(ui_page))
        .nest("/api/v1", api)
        .fallback(|| async {
            ApiError(
                StatusCode::NOT_FOUND,
                "not_found",
                "no such page".to_string(),
            )
        })
        .with_state(state)
}

async fn ui_page() -> impl IntoResponse {
    (
        [
            (header::CACHE_CONTROL, "no-cache"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Html(UI_HTML),
    )
}

/// Liveness only. It needs no token, so it says nothing about the zones.
async fn api_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn api_zones(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let zones = state.store().zones()?;
    Ok(Json(serde_json::json!({
        "zones": zones,
        "configured": state.config.zones.iter().map(|z| &z.name).collect::<Vec<_>>(),
        "errors": *state.errors.lock().expect("lock"),
    })))
}

async fn api_zone(
    State(state): State<Arc<AppState>>,
    Path(zone): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let zone = normalise_zone(&zone).map_err(|_| bad_zone(&zone))?;
    let store = state.store();
    let runs = store.runs(&zone)?;
    Ok(Json(serde_json::json!({
        "zone": zone,
        "names": store.names(&zone)?,
        "runs": runs,
        "last_run": store.latest_run_view(&zone)?,
        "findings": store.finding_rows(Some(&zone), None)?,
    })))
}

#[derive(Deserialize)]
struct ZoneQuery {
    zone: Option<String>,
    state: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
}

fn required_zone(query: &ZoneQuery) -> Result<String, ApiError> {
    let input = query.zone.as_deref().ok_or_else(|| {
        ApiError(
            StatusCode::BAD_REQUEST,
            "missing_zone",
            "the 'zone' query parameter is required".to_string(),
        )
    })?;
    normalise_zone(input).map_err(|_| bad_zone(input))
}

async fn api_runs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ZoneQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let zone = required_zone(&query)?;
    let runs = state.store().runs(&zone)?;
    Ok(Json(serde_json::json!({ "zone": zone, "runs": runs })))
}

async fn api_findings(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ZoneQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let zone = match &query.zone {
        Some(z) => Some(normalise_zone(z).map_err(|_| bad_zone(z))?),
        None => None,
    };
    if let Some(s) = &query.state
        && !matches!(s.as_str(), "open" | "resolved")
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "state must be 'open' or 'resolved'".to_string(),
        ));
    }
    let rows = state
        .store()
        .finding_rows(zone.as_deref(), query.state.as_deref())?;
    Ok(Json(serde_json::json!({ "findings": rows })))
}

async fn api_diff(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ZoneQuery>,
) -> Result<Json<DiffReport>, ApiError> {
    let zone = required_zone(&query)?;
    let ignore = state
        .zone_config(&zone)
        .map(|z| z.ignore.clone())
        .unwrap_or_default();
    let store = state.store();
    let (from, to) = store.pick_runs(&zone, query.from, query.to)?;
    let (from, to) = if from.id > to.id {
        (to, from)
    } else {
        (from, to)
    };
    Ok(Json(store.diff(&zone, from, to, &ignore)?))
}

#[derive(Deserialize, Default)]
struct TriggerBody {
    zone: Option<String>,
    /// Make it a deep run.
    #[serde(default)]
    deep: bool,
}

#[derive(Deserialize)]
struct MuteBody {
    zone: String,
    /// The finding's fingerprint, or the start of it.
    id: String,
}

async fn set_muted(
    state: &Arc<AppState>,
    body: MuteBody,
    muted: bool,
) -> Result<Json<serde_json::Value>, ApiError> {
    let zone = normalise_zone(&body.zone).map_err(|_| bad_zone(&body.zone))?;
    let row = state.store().set_muted(&zone, &body.id, muted)?;
    Ok(Json(serde_json::json!({ "finding": row })))
}

/// Mute one finding: it is still recorded, but no longer reported.
async fn api_mute(
    State(state): State<Arc<AppState>>,
    Json(body): Json<MuteBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    set_muted(&state, body, true).await
}

async fn api_unmute(
    State(state): State<Arc<AppState>>,
    Json(body): Json<MuteBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    set_muted(&state, body, false).await
}

/// Start a run of one configured zone, or of all of them. Returns at once;
/// the run carries on in the background. The body must be JSON (`{}` for
/// all zones), which a form on another site cannot send.
async fn api_trigger(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TriggerBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let wanted = body.zone;
    let zones: Vec<ZoneConfig> = match wanted {
        Some(input) => {
            let zone = normalise_zone(&input).map_err(|_| bad_zone(&input))?;
            let config = state.zone_config(&zone).ok_or_else(|| {
                ApiError(
                    StatusCode::NOT_FOUND,
                    "unknown_zone",
                    format!("{zone} is not in the configuration file"),
                )
            })?;
            vec![config.clone()]
        }
        None => state.config.zones.clone(),
    };
    let started: Vec<String> = zones.iter().map(|z| z.name.clone()).collect();
    let background = state.clone();
    let deep = body.deep;
    tokio::spawn(async move {
        for zone in zones {
            let _ = run_zone_level(&background, &zone, "manual", deep).await;
        }
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "started": started })),
    ))
}

// ------------------------------------------------------- the UI's data

/// One row of the UI's nameserver table.
#[derive(Serialize)]
struct UiNs {
    name: String,
    serial: String,
    auth: bool,
    /// `ok`, `fail`, or `none` when there is nothing to test.
    udp: &'static str,
    tcp: &'static str,
    v4: &'static str,
    v6: &'static str,
}

#[derive(Serialize)]
struct UiFinding {
    id: String,
    /// `crit`, `warn` or `note`.
    sev: &'static str,
    name: String,
    title: String,
    text: String,
    ev: String,
    since: String,
    /// The run in which the finding was first gone, when it is resolved.
    resolved: Option<i64>,
    /// The finding's fingerprint, for muting it.
    key: String,
    muted: bool,
}

#[derive(Serialize)]
struct UiRun {
    id: i64,
    when_unix: u64,
    prev: Option<i64>,
    /// Lines of the change list: a sign (`+`, `-` or space) and text.
    changes: Vec<(String, String)>,
}

#[derive(Serialize)]
struct UiZone {
    name: String,
    names: usize,
    ns: Vec<UiNs>,
    path: Vec<String>,
    dnssec: String,
    findings: Vec<UiFinding>,
    history: Vec<UiRun>,
    last_run_id: Option<i64>,
    last_run_unix: Option<u64>,
    running: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct UiModel {
    version: &'static str,
    now_unix: u64,
    next_run_unix: Option<u64>,
    every: String,
    zones: Vec<UiZone>,
}

fn tri(tested: bool, ok: bool) -> &'static str {
    match (tested, ok) {
        (false, _) => "none",
        (true, true) => "ok",
        (true, false) => "fail",
    }
}

fn ui_nameservers(view: &RunView) -> Vec<UiNs> {
    view.nameservers
        .iter()
        .map(|host| {
            let addresses = host.addresses();
            let probes: Vec<&ServerProbe> = view
                .probes
                .iter()
                .filter(|p| addresses.contains(&p.address))
                .collect();
            // Of the probes that `pick` selects: was there one, and did any get a response?
            let status = |pick: fn(&ServerProbe) -> bool| {
                let chosen: Vec<&&ServerProbe> = probes.iter().filter(|p| pick(p)).collect();
                tri(
                    !chosen.is_empty(),
                    chosen
                        .iter()
                        .any(|p| matches!(p.outcome, Outcome::Response(_))),
                )
            };
            let soa = probes
                .iter()
                .filter(|p| p.qtype == QType::Soa)
                .filter_map(|p| p.outcome.response())
                .filter(|r| r.is_authoritative_answer())
                .find_map(|r| r.soa.as_ref());
            UiNs {
                name: host.name.clone(),
                serial: soa
                    .map(|s| s.serial.to_string())
                    .unwrap_or_else(|| "—".to_string()),
                auth: soa.is_some(),
                udp: status(|p| p.transport == Transport::Udp),
                tcp: status(|p| p.transport == Transport::Tcp),
                v4: status(|p| p.address.is_ipv4()),
                v6: status(|p| p.address.is_ipv6()),
            }
        })
        .collect()
}

fn ui_dnssec(zone: &str, view: &RunView) -> String {
    let Some(d) = &view.dnssec else {
        return "DNSSEC not checked in this run".to_string();
    };
    let signed = d
        .servers
        .iter()
        .any(|s| s.dnskeys.as_ref().is_some_and(|k| !k.is_empty()));
    let ds = d.parent_ds.as_ref().and_then(|p| p.records.as_ref());
    match (signed, ds) {
        (false, Some(ds)) if !ds.is_empty() => "DS at parent, but no keys in the zone".to_string(),
        (false, _) => "Not signed".to_string(),
        (true, Some(ds)) if ds.is_empty() => "Signed, no DS at parent".to_string(),
        (true, Some(ds)) => {
            let matched = d.servers.iter().all(|s| match &s.dnskeys {
                Some(keys) => keys
                    .iter()
                    .any(|k| ds.iter().any(|r| crate::dnssec::ds_matches(zone, r, k))),
                None => true,
            });
            if matched {
                "Signed, DS matches a key".to_string()
            } else {
                "Signed, DS does not match".to_string()
            }
        }
        (true, None) => "Signed".to_string(),
    }
}

/// A name as the UI shows it: relative to the zone, `@` for the apex.
fn short_name(zone: &str, name: &str) -> String {
    if name == zone {
        "@".to_string()
    } else {
        name.strip_suffix(zone)
            .map(|rest| rest.trim_end_matches('.').to_string())
            .unwrap_or_else(|| name.to_string())
    }
}

fn ui_changes(zone: &str, d: &DiffReport) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    let line = |sign: &str, text: String| (sign.to_string(), text);
    for c in d.changes.iter().filter(|c| !c.rotation) {
        let label = format!("{:<12} {:<6}", short_name(zone, &c.name), c.rtype.as_str());
        if c.kind == ChangeKind::Ttl {
            let join = |v: &[u32]| v.iter().map(u32::to_string).collect::<Vec<_>>().join(", ");
            lines.push(line(
                " ",
                format!(
                    "{label} ttl {} → {}",
                    join(&c.ttl_before),
                    join(&c.ttl_after)
                ),
            ));
            continue;
        }
        let scope = if c.all_servers {
            String::new()
        } else {
            let on: Vec<&str> = c.servers.iter().map(|s| s.ns_name.as_str()).collect();
            format!("   (only on {})", on.join(", "))
        };
        for v in &c.removed {
            lines.push(line("-", format!("{label} {v}{scope}")));
        }
        for v in &c.added {
            lines.push(line("+", format!("{label} {v}{scope}")));
        }
    }
    if let Some(del) = &d.delegation {
        for ns in &del.ns_removed {
            lines.push(line("-", format!("parent NS    {ns}")));
        }
        for ns in &del.ns_added {
            lines.push(line("+", format!("parent NS    {ns}")));
        }
    }
    if let Some(s) = &d.soa_serial {
        let join = |v: &[u32]| v.iter().map(u32::to_string).collect::<Vec<_>>().join(", ");
        lines.push(line(
            " ",
            format!("SOA serial {} → {}", join(&s.before), join(&s.after)),
        ));
    }
    for f in &d.findings_opened {
        lines.push(line(
            "+",
            format!("finding {} opened: {}", f.check_id, f.summary),
        ));
    }
    for f in &d.findings_resolved {
        lines.push(line(
            "-",
            format!("finding {} resolved: {}", f.check_id, f.summary),
        ));
    }
    lines
}

fn ui_zone(state: &AppState, store: &Store, zone: &str) -> Result<UiZone, StoreError> {
    let runs: Vec<RunRef> = match store.runs(zone) {
        Ok(runs) => runs,
        Err(StoreError::UnknownZone { .. }) => Vec::new(),
        Err(e) => return Err(e),
    };
    let view = if runs.is_empty() {
        None
    } else {
        store.latest_run_view(zone)?
    };
    let ignore = state
        .zone_config(zone)
        .map(|z| z.ignore.clone())
        .unwrap_or_default();

    let mut findings = Vec::new();
    if !runs.is_empty() {
        let latest = runs.last().map(|r| r.id).unwrap_or(0);
        for row in store.finding_rows(Some(zone), None)? {
            let resolved = if row.state == "resolved" {
                runs.iter().map(|r| r.id).find(|id| *id > row.last_seen_run)
            } else {
                None
            };
            // Keep resolved findings on screen for a few runs, then drop them.
            if let Some(gone) = resolved
                && runs.iter().filter(|r| r.id > gone).count() >= HISTORY_RUNS
            {
                continue;
            }
            if row.state == "resolved" && resolved.is_none() && row.last_seen_run != latest {
                continue;
            }
            let title = CATALOG
                .iter()
                .find(|c| c.id == row.check_id)
                .map(|c| c.title.to_string())
                .unwrap_or_else(|| row.check_id.clone());
            findings.push(UiFinding {
                id: row.check_id,
                sev: match row.severity {
                    Severity::Critical => "crit",
                    Severity::Warning => "warn",
                    _ => "note",
                },
                name: row.name,
                title,
                text: row.summary,
                ev: human::evidence_lines(&row.evidence).join("\n"),
                since: format!("run {}", row.first_seen_run),
                resolved,
                muted: row.state == "muted",
                key: row.fingerprint,
            });
        }
    }

    let mut history = Vec::new();
    let recent: Vec<&RunRef> = runs.iter().rev().take(HISTORY_RUNS).collect();
    for run in recent {
        let prev = runs.iter().rev().find(|r| r.id < run.id).copied();
        let changes = match prev {
            Some(prev) => ui_changes(zone, &store.diff(zone, prev, *run, &ignore)?),
            None => Vec::new(),
        };
        history.push(UiRun {
            id: run.id,
            when_unix: run.started_at_unix,
            prev: prev.map(|p| p.id),
            changes,
        });
    }

    let seeds = state.zone_config(zone).map(|z| z.seeds.len()).unwrap_or(0);
    let stored_names = if runs.is_empty() {
        0
    } else {
        store.names(zone)?.len()
    };
    Ok(UiZone {
        name: zone.to_string(),
        names: stored_names.max(seeds) + 1,
        ns: view.as_ref().map(ui_nameservers).unwrap_or_default(),
        path: view
            .as_ref()
            .map(|v| {
                let mut path: Vec<String> = v
                    .delegation_path
                    .iter()
                    .map(|s| s.from_zone.clone())
                    .collect();
                path.push(zone.to_string());
                path.dedup();
                path
            })
            .unwrap_or_default(),
        dnssec: view
            .as_ref()
            .map(|v| ui_dnssec(zone, v))
            .unwrap_or_else(|| "Not checked yet".to_string()),
        findings,
        history,
        last_run_id: runs.last().map(|r| r.id),
        last_run_unix: runs.last().map(|r| r.started_at_unix),
        running: state.running.lock().expect("lock").contains(zone),
        error: state.errors.lock().expect("lock").get(zone).cloned(),
    })
}

/// Everything the web UI shows, in one document.
async fn api_ui(State(state): State<Arc<AppState>>) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store();
    // Configured zones first, then any others already in the database.
    let mut names: Vec<String> = state.config.zones.iter().map(|z| z.name.clone()).collect();
    for z in store.zones()? {
        if !names.contains(&z.zone) {
            names.push(z.zone);
        }
    }
    let mut zones = Vec::new();
    for name in &names {
        zones.push(ui_zone(&state, &store, name)?);
    }
    let model = UiModel {
        version: env!("CARGO_PKG_VERSION"),
        now_unix: now_unix(),
        next_run_unix: *state.next_run_unix.lock().expect("lock"),
        every: state.config.schedule.every.clone(),
        zones,
    };
    Ok(Json(serde_json::to_value(model).map_err(|e| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "store_error",
            e.to_string(),
        )
    })?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hashing() {
        // SHA-256 of "abc", a standard test vector.
        assert_eq!(
            token_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }

    #[test]
    fn hosts_are_read_without_port_or_scheme() {
        assert_eq!(host_only("127.0.0.1:8053"), "127.0.0.1");
        assert_eq!(host_only("localhost"), "localhost");
        assert_eq!(host_only("[::1]:8053"), "[::1]");
        assert_eq!(host_only("http://evil.example:8053"), "evil.example");
    }

    #[test]
    fn names_are_shown_relative_to_the_zone() {
        assert_eq!(short_name("example.org.", "example.org."), "@");
        assert_eq!(short_name("example.org.", "www.example.org."), "www");
        assert_eq!(short_name("example.org.", "a.b.example.org."), "a.b");
        assert_eq!(short_name("example.org.", "other.net."), "other.net.");
    }
}
