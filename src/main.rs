use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use zoneblick::cli::{self, Cli, Command, ZonesAction};
use zoneblick::output::exit;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // clap would exit with 2 on a usage error, which here means
            // "critical finding". A bad command line is a failed run.
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() {
                exit::RUN_FAILED
            } else {
                exit::CLEAN
            });
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("zoneblick: {e:#}");
            ExitCode::from(exit::RUN_FAILED)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let output = match cli.command {
        Command::Check(args) => runtime.block_on(cli::check(&args, color)),
        Command::Run(args) => runtime.block_on(cli::run(&args, color)),
        Command::Diff(args) => cli::diff(&args, color),
        Command::Zones {
            action: ZonesAction::List(args),
        } => cli::zones_list(&args, color),
        Command::Baseline { action } => cli::baseline(&action),
        Command::Prune(args) => cli::prune(&args),
        Command::Serve(args) => runtime.block_on(cli::serve(&args)),
        Command::Token(args) => cli::token(&args),
    };
    std::io::stdout()
        .write_all(output.stdout.as_bytes())
        .context("cannot write to stdout")?;
    std::io::stderr()
        .write_all(output.stderr.as_bytes())
        .context("cannot write to stderr")?;
    Ok(output.exit_code)
}
