//! zoneblick: a self-hosted DNS zone watchdog.
//!
//! Phase 0 provides the one-shot `check` command. The modules follow the
//! components in `DESIGN.md`:
//!
//! - [`observe`]: the recorded observations of one run (plain data, no I/O)
//! - [`resolver`]: the iterative resolver and per-server probing (all network I/O)
//! - [`checks`]: pure functions from observations to findings (no I/O)
//! - [`output`]: human and JSON rendering
//! - [`cli`]: argument parsing and the `check` command

pub mod alerts;
pub mod checks;
pub mod cli;
pub mod config;
pub mod diff;
pub mod digest;
pub mod discover;
pub mod dnssec;
pub mod observe;
pub mod output;
pub mod plan;
pub mod providers;
pub mod registration;
pub mod resolver;
pub mod runner;
pub mod serve;
pub mod signatures;
pub mod store;
pub mod tls;
pub mod vantage;
pub mod verify;
pub mod zonefile;
