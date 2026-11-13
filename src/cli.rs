//! Command-line interface: argument parsing and the commands.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};

use crate::checks::run_all;
use crate::diff::DiffReport;
use crate::output::{
    FailureReport, Report, RunDocument, SCHEMA_VERSION, StoredRun, ZonesDocument, exit, human, json,
};
use crate::resolver::{
    Client, Fixture, NetConfig, ResolveError, name_in_zone, normalise_zone, observe_zone,
    observe_zone_records,
};
use crate::store::{RunMeta, Store, StoreError};

/// The database file used when `--db` is not given.
pub const DEFAULT_DB: &str = "zoneblick.sqlite";

#[derive(Debug, Parser)]
#[command(name = "zoneblick", version, about = "A self-hosted DNS zone watchdog")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check one zone once: resolve it from the root, ask every
    /// authoritative nameserver directly, and report what is wrong.
    ///
    /// Nothing is stored. Exit codes: 0 clean, 1 notices or warnings, 2 at
    /// least one critical finding, 3 the run itself failed.
    Check(CheckArgs),

    /// Check a zone and its names, and store the result as a snapshot.
    ///
    /// Does everything `check` does, then asks every nameserver for the
    /// records of each name, stores the run in the database, and shows what
    /// changed since the previous stored run. Exit codes are those of `check`.
    Run(RunArgs),

    /// Show what changed between two stored runs of a zone.
    ///
    /// Compares the latest run with the one before it unless told otherwise.
    /// Exit codes: 0 no changes, 1 changes, 3 the command failed.
    Diff(DiffArgs),

    /// Work with the zones in the database.
    Zones {
        #[command(subcommand)]
        action: ZonesAction,
    },

    /// Pin, show or clear a zone's baseline: the stored run that counts
    /// as correct. `zoneblick diff <zone> --baseline` compares against it.
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },

    /// Delete old runs from the database.
    ///
    /// Runs younger than `--keep-all` stay. Older runs are thinned to the
    /// last one of each day, and deleted once older than `--keep-daily`.
    /// A zone's latest run and its baseline are never deleted. The daemon
    /// does this by itself after every round of checks.
    Prune(PruneArgs),

    /// Run the daemon: check every zone in the config file on a schedule,
    /// send alerts when something changes, and serve the API and web UI.
    Serve(ServeArgs),

    /// Print the hash of an API token, for `token_sha256` in the config file.
    ///
    /// Give the token as an argument, or leave it out to type it on standard
    /// input. A good token is long and random, for example the output of
    /// `openssl rand -hex 32`.
    Token(TokenArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// The configuration file.
    #[arg(long, value_name = "FILE", default_value = "zoneblick.toml")]
    pub config: PathBuf,
}

#[derive(Debug, Args)]
pub struct TokenArgs {
    /// The token to hash. Read from standard input when left out.
    pub token: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum BaselineAction {
    /// Pin a run as the baseline. Default: the latest run.
    Pin(BaselineArgs),
    /// Show which run is pinned.
    Show(BaselineArgs),
    /// Remove the baseline.
    Clear(BaselineArgs),
}

#[derive(Debug, Args)]
pub struct BaselineArgs {
    /// The zone.
    pub zone: String,

    /// For `pin`: the run to pin. Default: the latest run.
    #[arg(long, value_name = "RUN")]
    pub run: Option<i64>,

    /// The database file.
    #[arg(long, value_name = "FILE", default_value = DEFAULT_DB)]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct PruneArgs {
    /// Keep every run younger than this, for example 30d.
    #[arg(long, value_name = "TIME", default_value = "30d")]
    pub keep_all: String,

    /// Keep one run per day until this age, for example 365d.
    #[arg(long, value_name = "TIME", default_value = "365d")]
    pub keep_daily: String,

    /// The database file.
    #[arg(long, value_name = "FILE", default_value = DEFAULT_DB)]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum ZonesAction {
    /// List the stored zones.
    List(ZonesListArgs),
}

/// Where DNS answers come from, for `check` and `run`.
#[derive(Debug, Args, Default, Clone)]
pub struct SourceArgs {
    /// Save every DNS exchange of this run to a fixture file.
    #[arg(long, value_name = "FILE", conflicts_with = "replay")]
    pub record: Option<PathBuf>,

    /// Answer from a fixture file instead of the network.
    #[arg(long, value_name = "FILE")]
    pub replay: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// The zone to check, for example example.org. Check only zones you control.
    pub zone: String,

    /// Print one JSON document instead of text.
    #[arg(long)]
    pub json: bool,

    #[command(flatten)]
    pub source: SourceArgs,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// The zone to check, for example example.org. Check only zones you control.
    pub zone: String,

    /// A name in the zone to check as well, such as www or mail. Repeat for
    /// more. Names are remembered: later runs check them without being told.
    #[arg(long = "name", value_name = "NAME")]
    pub names: Vec<String>,

    /// Stop checking a remembered name. Repeat for more.
    #[arg(long = "forget-name", value_name = "NAME")]
    pub forget_names: Vec<String>,

    /// Look for more names of the zone and check those too. The one source
    /// is `ct`: Certificate Transparency logs, read through crt.sh, which
    /// is told the zone's name. Found names are remembered.
    #[arg(long, value_name = "SOURCE", value_parser = ["ct"])]
    pub discover: Vec<String>,

    /// The database file. Created when it does not exist.
    #[arg(long, value_name = "FILE", default_value = DEFAULT_DB)]
    pub db: PathBuf,

    /// Print one JSON document instead of text.
    #[arg(long)]
    pub json: bool,

    #[command(flatten)]
    pub source: SourceArgs,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// The zone to compare runs of.
    pub zone: String,

    /// The older run. Default: the run before `--to`.
    #[arg(long, value_name = "RUN")]
    pub from: Option<i64>,

    /// The newer run. Default: the latest run.
    #[arg(long, value_name = "RUN")]
    pub to: Option<i64>,

    /// Compare against the zone's pinned baseline instead of the run before.
    #[arg(long, conflicts_with = "from")]
    pub baseline: bool,

    /// Leave out names matching this pattern, for example
    /// "_acme-challenge.*". `*` matches anything. Repeat for more.
    #[arg(long = "ignore", value_name = "PATTERN")]
    pub ignore: Vec<String>,

    /// The database file.
    #[arg(long, value_name = "FILE", default_value = DEFAULT_DB)]
    pub db: PathBuf,

    /// Print one JSON document instead of text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ZonesListArgs {
    /// The database file.
    #[arg(long, value_name = "FILE", default_value = DEFAULT_DB)]
    pub db: PathBuf,

    /// Print one JSON document instead of text.
    #[arg(long)]
    pub json: bool,
}

/// What a command produced: text for each stream and the exit code.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: u8,
}

/// A failure of the command itself, as opposed to a finding.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("there is no database at {path}; store a run first with: zoneblick run <zone>")]
    NoDatabase { path: PathBuf },
    #[error("zone {zone} has no baseline; pin one with: zoneblick baseline pin {zone}")]
    NoBaseline { zone: String },
    #[error("{0}")]
    Usage(String),
    #[error("cannot read fixture {path}: {source}")]
    ReadFixture {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot parse fixture {path}: {source}")]
    ParseFixture {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("cannot write fixture {path}: {source}")]
    WriteFixture {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("fixture {path} was recorded for {recorded}, not {asked}")]
    FixtureZone {
        path: PathBuf,
        recorded: String,
        asked: String,
    },
}

impl CliError {
    /// A stable identifier for the JSON failure document.
    pub fn kind(&self) -> &'static str {
        match self {
            CliError::Resolve(e) => match e {
                ResolveError::InvalidName(_) => "invalid_name",
                ResolveError::NoNetwork => "no_network",
                ResolveError::ZoneNotFound { .. } => "zone_not_found",
                ResolveError::NotAZone { .. } => "not_a_zone",
                ResolveError::ServersFailed { .. } => "servers_failed",
                ResolveError::TooManyReferrals { .. } => "too_many_referrals",
                ResolveError::NameOutsideZone { .. } => "name_outside_zone",
                ResolveError::NoServerReachable { .. } => "no_server_reachable",
            },
            CliError::Store(e) => match e {
                StoreError::UnknownZone { .. } => "unknown_zone",
                StoreError::UnknownRun { .. } => "unknown_run",
                StoreError::NotEnoughRuns { .. } => "not_enough_runs",
                _ => "store_error",
            },
            CliError::NoDatabase { .. } => "no_database",
            CliError::NoBaseline { .. } => "no_baseline",
            CliError::Usage(_) => "usage",
            _ => "fixture_error",
        }
    }
}

/// Turn a command failure into output: a JSON document or a line on stderr.
fn failed(zone: &str, json: bool, e: &CliError) -> CommandOutput {
    let mut output = CommandOutput {
        exit_code: exit::RUN_FAILED,
        ..Default::default()
    };
    if json {
        let zone = normalise_zone(zone).unwrap_or_else(|_| zone.to_string());
        let doc = FailureReport::new(&zone, e.kind(), e.to_string());
        output.stdout = json::render(&doc);
    } else {
        output.stderr = format!("zoneblick: {e}\n");
    }
    output
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A client for the chosen source, and whether it replays a fixture. With a
/// fixture, the start time comes from the fixture so replays are stable.
fn make_client(source: &SourceArgs, zone: &str) -> Result<(Arc<Client>, u64, bool), CliError> {
    let (client, started_at, replaying) = match &source.replay {
        Some(path) => {
            let fixture = read_fixture(path)?;
            if fixture.zone != zone {
                return Err(CliError::FixtureZone {
                    path: path.clone(),
                    recorded: fixture.zone,
                    asked: zone.to_string(),
                });
            }
            (Client::replay(&fixture), fixture.started_at_unix, true)
        }
        None => (Client::live(NetConfig::default()), now_unix(), false),
    };
    let client = if source.record.is_some() {
        client.with_recording()
    } else {
        client
    };
    Ok((Arc::new(client), started_at, replaying))
}

/// Save the recording, when one was asked for. This runs even after a failed
/// run: a failing run is exactly what one wants to replay.
fn save_recording(
    source: &SourceArgs,
    client: &Client,
    zone: &str,
    started_at: u64,
) -> Result<(), CliError> {
    let Some(path) = &source.record else {
        return Ok(());
    };
    let fixture = Fixture {
        version: Fixture::VERSION,
        zone: zone.to_string(),
        started_at_unix: started_at,
        exchanges: client.take_recording(),
        http: client.take_http_recording(),
    };
    std::fs::write(path, json::render(&fixture)).map_err(|source| CliError::WriteFixture {
        path: path.clone(),
        source,
    })
}

fn read_fixture(path: &PathBuf) -> Result<Fixture, CliError> {
    let text = std::fs::read_to_string(path).map_err(|source| CliError::ReadFixture {
        path: path.clone(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| CliError::ParseFixture {
        path: path.clone(),
        source,
    })
}

/// Run `zoneblick check`. `color` asks for ANSI colours in text output.
pub async fn check(args: &CheckArgs, color: bool) -> CommandOutput {
    match try_check(args, color).await {
        Ok(output) => output,
        Err(e) => failed(&args.zone, args.json, &e),
    }
}

async fn try_check(args: &CheckArgs, color: bool) -> Result<CommandOutput, CliError> {
    let zone = normalise_zone(&args.zone)?;
    let (client, started_at, _) = make_client(&args.source, &zone)?;
    let observed = observe_zone(client.clone(), &zone, started_at).await;
    save_recording(&args.source, &client, &zone, started_at)?;

    let obs = observed?;
    let findings = run_all(&obs);
    let report = Report::new(obs, findings);
    let stdout = if args.json {
        json::render(&report)
    } else {
        human::render(&report, color)
    };
    Ok(CommandOutput {
        stdout,
        stderr: String::new(),
        exit_code: report.exit_code,
    })
}

/// Run `zoneblick run`: check, collect records, store, and compare.
pub async fn run(args: &RunArgs, color: bool) -> CommandOutput {
    match try_run(args, color).await {
        Ok(output) => output,
        Err(e) => failed(&args.zone, args.json, &e),
    }
}

async fn try_run(args: &RunArgs, color: bool) -> Result<CommandOutput, CliError> {
    let zone = normalise_zone(&args.zone)?;
    let mut store = Store::open(&args.db)?;

    // Names: the ones remembered for the zone, plus any given now, minus
    // any the user asked to forget.
    let mut names = store.names(&zone)?;
    for input in &args.names {
        let name = name_in_zone(&zone, input)?;
        if name != zone && !names.contains(&name) {
            names.push(name);
        }
    }
    for input in &args.forget_names {
        let name = name_in_zone(&zone, input)?;
        store.forget_name(&zone, &name)?;
        names.retain(|n| *n != name);
    }
    let (client, started_at, replaying) = make_client(&args.source, &zone)?;

    // More names from certificate logs, when asked. A failure here is
    // reported and the run goes on with the names it has.
    let mut discovered: Vec<String> = Vec::new();
    let mut notes = String::new();
    if !args.discover.is_empty() {
        match crate::discover::ct_names(&client, &zone).await {
            Ok(found) => {
                let total = found.len();
                discovered = found.into_iter().filter(|n| !names.contains(n)).collect();
                notes = format!(
                    "zoneblick: certificate logs name {total} hosts in {zone}, {} of them new\n",
                    discovered.len()
                );
                names.extend(discovered.iter().cloned());
            }
            Err(e) => notes = format!("zoneblick: discovery failed, continuing without it: {e}\n"),
        }
    }
    names.sort();

    let observed = observe_zone_records(client.clone(), &zone, started_at, &names).await;
    save_recording(&args.source, &client, &zone, started_at)?;
    let obs = observed?;

    let findings = run_all(&obs);
    let queries = client.queries_sent();
    let meta = RunMeta {
        names: &names,
        finished_at_unix: if replaying { started_at } else { now_unix() },
        queries,
        trigger: "cli",
    };
    let run_id = store.save_run(&obs, &findings, &meta)?;
    store.set_name_source(&zone, &discovered, "ct")?;

    // Compare with the previous stored run of the zone, when there is one.
    let diff: Option<DiffReport> = match store.pick_runs(&zone, None, Some(run_id)) {
        Ok((from, to)) => Some(store.diff(&zone, from, to, &[])?),
        Err(StoreError::NotEnoughRuns { .. }) => None,
        Err(e) => return Err(e.into()),
    };

    let stored = StoredRun {
        id: run_id,
        db: args.db.display().to_string(),
        names,
        queries,
    };
    let report = Report::new(obs, findings);
    let exit_code = report.exit_code;
    let stdout = if args.json {
        json::render(&RunDocument {
            schema_version: SCHEMA_VERSION,
            run: stored,
            report,
            diff,
        })
    } else {
        let mut text = human::render_as("run", &report, color);
        text.push_str(&human::render_stored(&stored, diff.as_ref(), color));
        text
    };
    Ok(CommandOutput {
        stdout,
        stderr: notes,
        exit_code,
    })
}

/// Open a database that must already exist.
fn open_existing(path: &Path) -> Result<Store, CliError> {
    if !path.exists() {
        return Err(CliError::NoDatabase {
            path: path.to_path_buf(),
        });
    }
    Ok(Store::open(path)?)
}

/// Run `zoneblick diff`.
pub fn diff(args: &DiffArgs, color: bool) -> CommandOutput {
    match try_diff(args, color) {
        Ok(output) => output,
        Err(e) => failed(&args.zone, args.json, &e),
    }
}

fn try_diff(args: &DiffArgs, color: bool) -> Result<CommandOutput, CliError> {
    let zone = normalise_zone(&args.zone)?;
    let store = open_existing(&args.db)?;
    let (from, to) = if args.baseline {
        let pinned = store
            .baseline(&zone)?
            .ok_or_else(|| CliError::NoBaseline { zone: zone.clone() })?;
        let (_, to) = store.pick_runs(&zone, Some(pinned.id), args.to)?;
        (pinned, to)
    } else {
        store.pick_runs(&zone, args.from, args.to)?
    };
    // Whatever order the IDs were given in, the older run comes first.
    let (from, to) = if from.id > to.id {
        (to, from)
    } else {
        (from, to)
    };
    let report = store.diff(&zone, from, to, &args.ignore)?;
    let stdout = if args.json {
        json::render(&report)
    } else {
        human::render_diff(&report, color)
    };
    Ok(CommandOutput {
        stdout,
        stderr: String::new(),
        exit_code: if report.changed {
            exit::FINDINGS
        } else {
            exit::CLEAN
        },
    })
}

/// Run `zoneblick baseline pin | show | clear`.
pub fn baseline(action: &BaselineAction) -> CommandOutput {
    let args = match action {
        BaselineAction::Pin(a) | BaselineAction::Show(a) | BaselineAction::Clear(a) => a,
    };
    let result = (|| -> Result<String, CliError> {
        let zone = normalise_zone(&args.zone)?;
        let store = open_existing(&args.db)?;
        let describe = |run: crate::diff::RunRef| {
            format!(
                "run #{} ({})",
                run.id,
                crate::output::utc(run.started_at_unix)
            )
        };
        Ok(match action {
            BaselineAction::Pin(_) => {
                let run = store.pin_baseline(&zone, args.run, now_unix())?;
                format!("The baseline of {zone} is now {}.\n", describe(run))
            }
            BaselineAction::Show(_) => match store.baseline(&zone)? {
                Some(run) => format!("The baseline of {zone} is {}.\n", describe(run)),
                None => format!("{zone} has no baseline.\n"),
            },
            BaselineAction::Clear(_) => {
                if store.clear_baseline(&zone)? {
                    format!("The baseline of {zone} is removed.\n")
                } else {
                    format!("{zone} has no baseline.\n")
                }
            }
        })
    })();
    match result {
        Ok(stdout) => CommandOutput {
            stdout,
            ..Default::default()
        },
        Err(e) => failed(&args.zone, false, &e),
    }
}

/// Run `zoneblick prune`.
pub fn prune(args: &PruneArgs) -> CommandOutput {
    let result = (|| -> Result<String, CliError> {
        let retention = crate::config::RetentionConfig {
            keep_all: args.keep_all.clone(),
            keep_daily: args.keep_daily.clone(),
        };
        let (keep_all, keep_daily) = retention
            .limits()
            .map_err(|e| CliError::Usage(e.to_string().replace("[retention] ", "")))?;
        let mut store = open_existing(&args.db)?;
        let pruned = store.prune(now_unix(), keep_all, keep_daily)?;
        Ok(format!(
            "Deleted {} runs and {} record sets no run uses any more.\n",
            pruned.runs, pruned.record_sets
        ))
    })();
    match result {
        Ok(stdout) => CommandOutput {
            stdout,
            ..Default::default()
        },
        Err(e) => failed("", false, &e),
    }
}

/// Run `zoneblick zones list`.
pub fn zones_list(args: &ZonesListArgs, color: bool) -> CommandOutput {
    let result = open_existing(&args.db).and_then(|store| Ok(store.zones()?));
    match result {
        Ok(zones) => {
            let db = args.db.display().to_string();
            let stdout = if args.json {
                json::render(&ZonesDocument {
                    schema_version: SCHEMA_VERSION,
                    db,
                    zones,
                })
            } else {
                human::render_zones(&db, &zones, color)
            };
            CommandOutput {
                stdout,
                stderr: String::new(),
                exit_code: exit::CLEAN,
            }
        }
        Err(e) => failed("", args.json, &e),
    }
}

/// Run `zoneblick serve` until interrupted.
pub async fn serve(args: &ServeArgs) -> CommandOutput {
    let result: Result<(), crate::serve::ServeError> = async {
        let config = crate::config::Config::load(&args.config)?;
        let factory = crate::serve::live_client_factory(&config);
        let state = crate::serve::AppState::new(config, factory)?;
        crate::serve::serve(state, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    }
    .await;
    match result {
        Ok(()) => CommandOutput::default(),
        Err(e) => CommandOutput {
            stderr: format!("zoneblick: {e}\n"),
            exit_code: exit::RUN_FAILED,
            ..Default::default()
        },
    }
}

/// Run `zoneblick token`: print the config line for a token's hash.
pub fn token(args: &TokenArgs) -> CommandOutput {
    let token = match &args.token {
        Some(t) => t.clone(),
        None => {
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_err() {
                line.clear();
            }
            line
        }
    };
    let token = token.trim();
    if token.len() < 16 {
        return CommandOutput {
            stderr:
                "zoneblick: the token must be at least 16 characters; try `openssl rand -hex 32`\n"
                    .to_string(),
            exit_code: exit::RUN_FAILED,
            ..Default::default()
        };
    }
    CommandOutput {
        stdout: format!("token_sha256 = \"{}\"\n", crate::serve::token_hash(token)),
        ..Default::default()
    }
}
