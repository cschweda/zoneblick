//! The resolver core: all network I/O lives under this module.
//!
//! - [`transport`]: sends one query to one server; live, recorded or replayed
//! - [`limiter`]: bounded concurrency and the per-server rate cap
//! - [`hints`]: built-in root hints

pub mod hints;
pub mod limiter;
pub mod transport;

pub use transport::{Client, Exchange, Fixture, NetConfig, QuerySpec, RawOutcome};
