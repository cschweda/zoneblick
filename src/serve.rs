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

/// How many runs the UI's timeline shows per zone.
const TIMELINE_RUNS: usize = 200;

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
    #[error("cannot listen on the socket file {path}: {source}")]
    Socket {
        path: std::path::PathBuf,
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
    /// Counts everything that changes what the UI shows: a run starting
    /// or ending, a finding muted.
    generation: std::sync::atomic::AtomicU64,
    /// Zones whose name list is over the limit, so that is said only once.
    capped: Mutex<BTreeSet<String>>,
    /// The zones part of the UI's data, for one generation.
    ui_cache: Mutex<Option<(u64, serde_json::Value)>>,
}

/// At most this many names of one zone are checked in a run. Discovery
/// can add names every day; without a limit, so would an attacker who can
/// get certificates under the zone.
pub const MAX_NAMES_PER_ZONE: usize = 1000;

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
            generation: std::sync::atomic::AtomicU64::new(0),
            capped: Mutex::new(BTreeSet::new()),
            ui_cache: Mutex::new(None),
        })
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        // A panic while the lock was held must not take the API down
        // with it: every write is a transaction, so the store is intact.
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn changed(&self) {
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn zone_config(&self, zone: &str) -> Option<&ZoneConfig> {
        self.config.zones.iter().find(|z| z.name == zone)
    }
}

/// Cut a zone's names to [`MAX_NAMES_PER_ZONE`], keeping every name in
/// `wanted` and filling the rest in name order. Returns how many were
/// dropped. The result is sorted.
pub fn cap_names(names: &mut Vec<String>, wanted: &BTreeSet<String>) -> usize {
    names.sort();
    names.dedup();
    if names.len() <= MAX_NAMES_PER_ZONE {
        return 0;
    }
    let before = names.len();
    let kept_wanted = names.iter().filter(|n| wanted.contains(*n)).count();
    let room = MAX_NAMES_PER_ZONE.saturating_sub(kept_wanted);
    let mut extras = 0;
    names.retain(|n| {
        if wanted.contains(n) {
            true
        } else {
            extras += 1;
            extras <= room
        }
    });
    before - names.len()
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
    state.changed();
    // The run gets its own task and a deadline. Whoever serves the zone
    // decides how long its answers take, and a run that never ends would
    // never report anything; a crash in it must not stop the others.
    let limit = state
        .config
        .run_timeout()
        .unwrap_or(Duration::from_secs(900));
    let task = tokio::spawn({
        let (state, zone, trigger) = (state.clone(), zone.clone(), trigger.to_string());
        async move { run_zone_inner(&state, &zone, &trigger, deep).await }
    });
    let stop = task.abort_handle();
    let result = match tokio::time::timeout(limit, task).await {
        Ok(Ok(result)) => result,
        Ok(Err(crash)) => Err(format!("the run stopped unexpectedly: {crash}")),
        Err(_) => {
            stop.abort();
            Err(format!(
                "the run did not finish within {} and was stopped",
                state.config.schedule.run_timeout
            ))
        }
    };
    state.running.lock().expect("lock").remove(&zone.name);
    state.changed();
    match &result {
        Ok(id) => {
            state.errors.lock().expect("lock").remove(&zone.name);
            log(&format!("{} run #{id} stored ({trigger})", zone.name));
        }
        Err(e) => {
            let first = state
                .errors
                .lock()
                .expect("lock")
                .insert(zone.name.clone(), e.clone())
                .is_none();
            log(&format!("{} run failed: {e}", zone.name));
            // A zone that cannot be checked is itself news: a hijacked
            // delegation can look exactly like this. Say so once, when the
            // failures start.
            if first {
                let title = format!("zoneblick: {} could not be checked", zone.name);
                let text = format!(
                    "{} run failed ({trigger})\n{e}\nNo findings or changes can be reported for this zone until a run succeeds.",
                    zone.name
                );
                let out = alerts::Outgoing {
                    severity: Severity::Critical,
                    title: &title,
                    text: &text,
                    json: serde_json::json!({
                        "kind": "run_failed",
                        "zone": zone.name,
                        "severity": "critical",
                        "title": title,
                        "text": text,
                        "error": e,
                    }),
                };
                for (sink, sent) in
                    alerts::send_outgoing(&out, &state.config.alerts, &state.http).await
                {
                    match sent {
                        Ok(()) => log(&format!("{} failure alert sent by {sink}", zone.name)),
                        Err(e) => log(&format!(
                            "{} failure alert by {sink} failed: {e}",
                            zone.name
                        )),
                    }
                }
            }
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
    // The zone file to compare with is read again for every run, so an
    // edit to it takes effect without a restart.
    let declared = match &zone.expect {
        Some(path) => match crate::zonefile::load(&zone.name, path) {
            Ok(declared) => Some(declared),
            Err(e) => {
                log(&format!("{} zone file not used: {e}", zone.name));
                None
            }
        },
        None => None,
    };
    for name in declared.iter().flat_map(|d| d.names(&zone.name)) {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let client = (state.client_factory)(&zone.name);
    let started = now_unix();

    // More names from certificate logs, when the zone asks for that.
    let mut discovered = Vec::new();
    let mut certificates = None;
    let mut provided: Vec<(&str, Vec<String>)> = Vec::new();
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
        match crate::discover::ct_fetch(&client, &zone.name).await {
            Ok(found) => {
                certificates = found.certificates;
                discovered = found
                    .names
                    .into_iter()
                    .filter(|n| !names.contains(n))
                    .collect();
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
    for provider in crate::providers::PROVIDERS {
        if !due || !zone.discover.iter().any(|d| d == provider) {
            continue;
        }
        let who = crate::providers::label(provider);
        let found = match state.config.providers.credential(provider) {
            Some(Ok(credential)) => {
                crate::providers::names(&client, provider, &zone.name, &credential).await
            }
            Some(Err(e)) => Err(e),
            None => Err(format!("no [providers.{provider}] section")),
        };
        match found {
            Ok(found) => {
                let new: Vec<String> = found.into_iter().filter(|n| !names.contains(n)).collect();
                if !new.is_empty() {
                    log(&format!(
                        "{} found {} new names at {who}",
                        zone.name,
                        new.len()
                    ));
                }
                names.extend(new.iter().cloned());
                provided.push((provider, new));
            }
            Err(e) => log(&format!("{} discovery failed: {e}", zone.name)),
        }
    }
    // The cap must never push out a name the user asked for: the seeds
    // and the names of the zone file stay, and only the extras found by
    // discovery or remembered from earlier runs are cut.
    let wanted: BTreeSet<String> = zone
        .seeds
        .iter()
        .cloned()
        .chain(declared.iter().flat_map(|d| d.names(&zone.name)))
        .collect();
    let dropped = cap_names(&mut names, &wanted);
    if dropped > 0 {
        log(&format!(
            "{} has {dropped} more names than the limit of {MAX_NAMES_PER_ZONE}; they are not checked",
            zone.name
        ));
        // Say so once through the alert sinks too: names that go
        // unchecked are a gap someone should know about.
        if state.capped.lock().expect("lock").insert(zone.name.clone()) {
            let title = format!(
                "zoneblick: {dropped} names of {} are not checked",
                zone.name
            );
            let text = format!(
                "{} has more than {MAX_NAMES_PER_ZONE} names. The names in the config and the zone file are all checked; {dropped} others, found by discovery, are not. Remove names you do not need with: zoneblick run {} --forget-name NAME",
                zone.name, zone.name
            );
            let out = alerts::Outgoing {
                severity: Severity::Warning,
                title: &title,
                text: &text,
                json: serde_json::json!({
                    "kind": "names_capped", "zone": zone.name, "severity": "warning",
                    "title": title, "text": text, "not_checked": dropped,
                }),
            };
            for (sink, sent) in alerts::send_outgoing(&out, &state.config.alerts, &state.http).await
            {
                if let Err(e) = sent {
                    log(&format!("{} alert by {sink} failed: {e}", zone.name));
                }
            }
        }
    } else {
        state.capped.lock().expect("lock").remove(&zone.name);
    }

    let mut obs = observe_zone_records(client.clone(), &zone.name, started, &names)
        .await
        .map_err(|e| e.to_string())?;
    obs.declared = declared;
    obs.certificates = certificates;
    for v in &state.config.vantages {
        let view = match v.token() {
            Ok(token) => {
                crate::vantage::fetch(&state.http, &v.name, &v.url, token.as_deref(), &zone.name)
                    .await
            }
            Err(e) => crate::vantage::VantageView {
                name: v.name.clone(),
                report: None,
                error: Some(e),
            },
        };
        obs.vantages.push(view);
    }
    crate::resolver::add_dkim_selectors(client.clone(), &mut obs, &zone.dkim_selectors).await;
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
        for (provider, found) in &provided {
            store
                .set_name_source(&zone.name, found, provider)
                .map_err(|e| e.to_string())?;
        }
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

/// Where the store keeps the time the last digest went out.
const DIGEST_KEY: &str = "digest_sent_at";

/// Send the digest when one is due. The first time the daemon runs with
/// the digest switched on, the clock starts; nothing is sent yet.
async fn digest(state: &Arc<AppState>) {
    let Ok(Some(every)) = state.config.digest_interval() else {
        return;
    };
    let now = now_unix();
    let composed = {
        let store = state.store();
        let last = store
            .meta(DIGEST_KEY)
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok());
        match last {
            None => {
                let _ = store.set_meta(DIGEST_KEY, &now.to_string());
                return;
            }
            Some(last) if now < last + every.as_secs() => return,
            Some(last) => {
                let _ = store.set_meta(DIGEST_KEY, &now.to_string());
                crate::digest::compose(&store, last, now)
            }
        }
    };
    let digest = match composed {
        Ok(digest) => digest,
        Err(e) => return log(&format!("the digest could not be written: {e}")),
    };
    let out = alerts::Outgoing {
        severity: digest.severity,
        title: &digest.title,
        text: &digest.text,
        json: serde_json::to_value(&digest).unwrap_or_default(),
    };
    for (sink, result) in alerts::send_outgoing(&out, &state.config.alerts, &state.http).await {
        match result {
            Ok(()) => log(&format!("digest sent by {sink}")),
            Err(e) => log(&format!("digest by {sink} failed: {e}")),
        }
    }
}

/// The scheduler: check every zone at startup, then once per interval.
async fn scheduler(state: Arc<AppState>, every: Duration) {
    loop {
        run_all_zones(&state, "schedule").await;
        prune(&state);
        digest(&state).await;
        *state.next_run_unix.lock().expect("lock") = Some(now_unix() + every.as_secs());
        tokio::time::sleep(every).await;
    }
}

/// Run the daemon until `shutdown` resolves.
pub async fn serve(
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServeError> {
    let every = state.config.interval()?;
    let started = |place: &str| {
        log(&format!(
            "zoneblick {} listening on {place}, {} zones, checking every {}",
            env!("CARGO_PKG_VERSION"),
            state.config.zones.len(),
            state.config.schedule.every
        ));
    };
    #[cfg(unix)]
    if let Some(path) = state.config.socket_path() {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let failed = |source| ServeError::Socket {
            path: path.clone(),
            source,
        };
        // A socket file left by an earlier run is in the way; anything
        // else at that path is not ours to remove.
        if let Ok(meta) = std::fs::symlink_metadata(&path)
            && meta.file_type().is_socket()
        {
            std::fs::remove_file(&path).map_err(failed)?;
        }
        // The socket is made inside a directory only this user can enter,
        // given its permissions there, and then moved into place. That
        // way it is never reachable with the wider permissions a new
        // socket file starts out with.
        use std::os::unix::fs::DirBuilderExt;
        let nursery = path.with_extension(format!("new-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&nursery);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&nursery)
            .map_err(failed)?;
        let made = nursery.join("s");
        let listener = tokio::net::UnixListener::bind(&made).map_err(failed);
        // The owner and the group may connect; nobody else. This is what
        // keeps other local users out, with or without a token.
        let placed = listener.and_then(|listener| {
            std::fs::set_permissions(&made, std::fs::Permissions::from_mode(0o660))
                .and_then(|()| std::fs::rename(&made, &path))
                .map_err(failed)
                .map(|()| listener)
        });
        let _ = std::fs::remove_dir_all(&nursery);
        let listener = placed?;
        started(&format!("the socket file {}", path.display()));
        if state.config.server.token_sha256.is_none() {
            log("no API token is set; the API is open to users who may open the socket file");
        }
        let job = tokio::spawn(scheduler(state.clone(), every));
        let result = axum::serve(listener, router(state))
            .with_graceful_shutdown(shutdown)
            .await;
        job.abort();
        let _ = std::fs::remove_file(&path);
        return Ok(result?);
    }
    let addr = state.config.bind_addr()?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|source| ServeError::Bind { addr, source })?;
    started(&format!("http://{addr}"));
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
    } else if [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-real-ip",
        "via",
    ]
    .iter()
    .any(|name| headers.contains_key(*name))
    {
        // A reverse proxy on this machine makes every visitor look local.
        return forbidden(
            "forbidden_proxy",
            "this request came through a proxy; set an API token (zoneblick token) before putting zoneblick behind one",
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
        .route("/ui/diff", get(api_ui_diff))
        .route("/metrics", get(api_metrics))
        .route("/vantage", get(api_vantage))
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
        .layer(middleware::from_fn(harden))
        .with_state(state)
}

/// Headers every response carries: browsers must not guess content types,
/// must not show the page in a frame, must not send its address along to
/// other sites, and must not keep API answers, which list what is wrong
/// with the zones, in a cache.
async fn harden(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let set =
        |headers: &mut axum::http::HeaderMap, name: header::HeaderName, value: &'static str| {
            headers
                .entry(name)
                .or_insert(axum::http::HeaderValue::from_static(value));
        };
    set(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(headers, header::X_FRAME_OPTIONS, "DENY");
    set(headers, header::REFERRER_POLICY, "no-referrer");
    set(headers, header::CACHE_CONTROL, "no-store");
    response
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

/// A label value in the Prometheus text format.
fn label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// The state of every zone in the Prometheus text format.
pub fn metrics_text(state: &AppState) -> Result<String, StoreError> {
    let store = state.store();
    let mut out = String::new();
    let mut family = |name: &str, kind: &str, help: &str, rows: Vec<(String, String)>| {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
        for (labels, value) in rows {
            out.push_str(&format!("{name}{labels} {value}\n"));
        }
    };
    family(
        "zoneblick_info",
        "gauge",
        "The running version.",
        vec![(
            format!("{{version=\"{}\"}}", env!("CARGO_PKG_VERSION")),
            "1".to_string(),
        )],
    );
    let zones = store.zones()?;
    let errors = state.errors.lock().expect("lock").clone();
    let mut findings = Vec::new();
    let mut last_run = Vec::new();
    let mut runs = Vec::new();
    let mut names = Vec::new();
    let mut failed = Vec::new();
    for z in &zones {
        let zone = format!("zone=\"{}\"", label(&z.zone));
        let rows = store.finding_rows(Some(&z.zone), Some("open"))?;
        for severity in Severity::ALL {
            let n = rows.iter().filter(|r| r.severity == severity).count();
            findings.push((
                format!("{{{zone},severity=\"{}\"}}", severity.as_str()),
                n.to_string(),
            ));
        }
        if let Some(run) = z.last_run {
            last_run.push((format!("{{{zone}}}"), run.started_at_unix.to_string()));
        }
        runs.push((format!("{{{zone}}}"), z.runs.to_string()));
        names.push((format!("{{{zone}}}"), z.names.to_string()));
        failed.push((
            format!("{{{zone}}}"),
            u8::from(errors.contains_key(&z.zone)).to_string(),
        ));
    }
    // A configured zone whose every run has failed is not in the store.
    for z in &state.config.zones {
        if !zones.iter().any(|s| s.zone == z.name) {
            failed.push((
                format!("{{zone=\"{}\"}}", label(&z.name)),
                u8::from(errors.contains_key(&z.name)).to_string(),
            ));
        }
    }
    family(
        "zoneblick_open_findings",
        "gauge",
        "Open findings by zone and severity; muted findings are not counted.",
        findings,
    );
    family(
        "zoneblick_last_run_timestamp_seconds",
        "gauge",
        "When the latest stored run of the zone started.",
        last_run,
    );
    family(
        "zoneblick_stored_runs",
        "gauge",
        "Runs of the zone kept in the database.",
        runs,
    );
    family(
        "zoneblick_names",
        "gauge",
        "Names checked in the zone besides the apex.",
        names,
    );
    family(
        "zoneblick_last_run_failed",
        "gauge",
        "1 when the zone's most recent run failed, 0 otherwise.",
        failed,
    );
    Ok(out)
}

async fn api_metrics(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let text = metrics_text(&state)?;
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        text,
    )
        .into_response())
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

/// This daemon's latest run of a zone, in the short form another
/// zoneblick daemon compares its own run with.
async fn api_vantage(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ZoneQuery>,
) -> Result<Json<crate::vantage::VantageReport>, ApiError> {
    let zone = required_zone(&query)?;
    let store = state.store();
    let run = store.runs(&zone)?.pop().ok_or_else(|| {
        ApiError(
            StatusCode::NOT_FOUND,
            "unknown_run",
            format!("{zone} has no stored run"),
        )
    })?;
    let data = store.load_run(&zone, run)?;
    let view = store.latest_run_view(&zone)?;
    Ok(Json(crate::vantage::VantageReport {
        zone,
        run_started_unix: run.started_at_unix,
        sets: crate::vantage::sets_of(&data.records),
        servers: view
            .map(|v| crate::vantage::servers_of(&v.probes))
            .unwrap_or_default(),
    }))
}

/// The change list between any two runs of a zone, as the UI shows it.
/// Without `from`, the run before `to`.
async fn api_ui_diff(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ZoneQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
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
    let changes = ui_changes(&zone, &store.diff(&zone, from, to, &ignore)?);
    Ok(Json(serde_json::json!({
        "zone": zone,
        "from": from.id,
        "to": to.id,
        "from_unix": from.started_at_unix,
        "to_unix": to.started_at_unix,
        "changes": changes,
    })))
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
    state.changed();
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

/// One run on the UI's timeline: findings by severity.
#[derive(Serialize)]
struct UiTick {
    id: i64,
    when_unix: u64,
    crit: usize,
    warn: usize,
    note: usize,
}

#[derive(Serialize)]
struct UiZone {
    /// The latest runs, oldest first.
    timeline: Vec<UiTick>,
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
    let timeline = if runs.is_empty() {
        Vec::new()
    } else {
        store
            .run_timeline(zone, TIMELINE_RUNS)?
            .into_iter()
            .map(|(run, [crit, warn, note])| UiTick {
                id: run.id,
                when_unix: run.started_at_unix,
                crit,
                warn,
                note,
            })
            .collect()
    };
    Ok(UiZone {
        timeline,
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
/// The zones part of the UI's data. It costs ten diffs per zone, so it
/// is worked out once per change (a run starting or ending, a mute) and
/// off the threads that serve requests.
fn ui_zones(state: &AppState) -> Result<serde_json::Value, ApiError> {
    let failed = |e: String| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "store_error", e);
    // The run counter of the database is part of the key, so a run stored
    // by `zoneblick run` on the same file is seen too.
    let generation = state
        .generation
        .load(std::sync::atomic::Ordering::SeqCst)
        .wrapping_mul(1_000_003)
        .wrapping_add(state.store().latest_run_id()? as u64);
    // Holding this lock while computing lets one request do the work and
    // the others wait for its result.
    let mut cache = state.ui_cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, zones)) = cache.as_ref()
        && *at == generation
    {
        return Ok(zones.clone());
    }
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
        zones.push(ui_zone(state, &store, name)?);
    }
    let zones = serde_json::to_value(zones).map_err(|e| failed(e.to_string()))?;
    *cache = Some((generation, zones.clone()));
    Ok(zones)
}

async fn api_ui(State(state): State<Arc<AppState>>) -> Result<Json<serde_json::Value>, ApiError> {
    let worker = state.clone();
    let zones = tokio::task::spawn_blocking(move || ui_zones(&worker))
        .await
        .map_err(|e| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                e.to_string(),
            )
        })??;
    Ok(Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "now_unix": now_unix(),
        "next_run_unix": *state.next_run_unix.lock().expect("lock"),
        "every": state.config.schedule.every,
        "zones": zones,
    })))
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
