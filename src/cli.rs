//! Command-line interface: argument parsing and the `check` command.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};

use crate::checks::run_all;
use crate::output::{FailureReport, Report, exit, human, json};
use crate::resolver::{Client, Fixture, NetConfig, ResolveError, normalise_zone, observe_zone};

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
    /// Exit codes: 0 clean, 1 notices or warnings, 2 at least one critical
    /// finding, 3 the run itself failed.
    Check(CheckArgs),
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// The zone to check, for example example.org. Check only zones you control.
    pub zone: String,

    /// Print one JSON document instead of text.
    #[arg(long)]
    pub json: bool,

    /// Save every DNS exchange of this run to a fixture file.
    #[arg(long, value_name = "FILE", conflicts_with = "replay")]
    pub record: Option<PathBuf>,

    /// Answer from a fixture file instead of the network.
    #[arg(long, value_name = "FILE")]
    pub replay: Option<PathBuf>,
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
            _ => "fixture_error",
        }
    }
}

/// Run `zoneblick check`. `color` asks for ANSI colours in text output.
pub async fn check(args: &CheckArgs, color: bool) -> CommandOutput {
    match try_check(args, color).await {
        Ok(output) => output,
        Err(e) => {
            let mut output = CommandOutput {
                exit_code: exit::RUN_FAILED,
                ..Default::default()
            };
            if args.json {
                let zone = normalise_zone(&args.zone).unwrap_or_else(|_| args.zone.clone());
                let doc = FailureReport::new(&zone, e.kind(), e.to_string());
                output.stdout = json::render(&doc);
            } else {
                output.stderr = format!("zoneblick: {e}\n");
            }
            output
        }
    }
}

async fn try_check(args: &CheckArgs, color: bool) -> Result<CommandOutput, CliError> {
    let zone = normalise_zone(&args.zone)?;

    let (client, started_at) = match &args.replay {
        Some(path) => {
            let fixture = read_fixture(path)?;
            if fixture.zone != zone {
                return Err(CliError::FixtureZone {
                    path: path.clone(),
                    recorded: fixture.zone,
                    asked: zone,
                });
            }
            (Client::replay(&fixture), fixture.started_at_unix)
        }
        None => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            (Client::live(NetConfig::default()), now)
        }
    };
    let client = Arc::new(if args.record.is_some() {
        client.with_recording()
    } else {
        client
    });

    let observed = observe_zone(client.clone(), &zone, started_at).await;

    // Save the recording even when the run failed: a failing run is exactly
    // what one wants to replay.
    if let Some(path) = &args.record {
        let fixture = Fixture {
            version: Fixture::VERSION,
            zone: zone.clone(),
            started_at_unix: started_at,
            exchanges: client.take_recording(),
        };
        std::fs::write(path, json::render(&fixture)).map_err(|source| CliError::WriteFixture {
            path: path.clone(),
            source,
        })?;
    }

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
