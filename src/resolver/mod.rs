//! The resolver core: all network I/O lives under this module.
//!
//! - [`transport`]: sends one query to one server; live, recorded or replayed
//! - [`limiter`]: bounded concurrency and the per-server rate cap
//! - [`hints`]: built-in root hints
//! - [`iterate`]: walks from the root to a name, recording each referral
//! - [`signed`]: collects DS, DNSKEY and signature records for the SEC checks
//! - [`probe`]: queries every nameserver address of a zone and builds the
//!   [`ZoneObservation`](crate::observe::ZoneObservation)

pub mod deep;
pub mod hints;
pub mod iterate;
pub mod limiter;
pub mod policy;
pub mod probe;
pub mod signed;
pub mod transport;

pub use deep::add_deep;
pub use policy::add_dkim_selectors;
pub use probe::{name_in_zone, normalise_zone, observe_zone, observe_zone_records};
pub use transport::{
    Client, Exchange, Fixture, HttpExchange, HttpOutcome, NetConfig, QuerySpec, RawOutcome,
};

/// Why a run could not produce an observation.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("'{0}' is not a valid domain name")]
    InvalidName(String),
    #[error("no root server answered over IPv4 or IPv6; is the network up?")]
    NoNetwork,
    #[error("zone {zone} does not exist (NXDOMAIN)")]
    ZoneNotFound { zone: String },
    #[error("{name} is not a zone apex{}", enclosing_hint(.enclosing))]
    NotAZone {
        name: String,
        enclosing: Option<String>,
    },
    #[error("no usable answer from the nameservers of {zone} ({detail})")]
    ServersFailed { zone: String, detail: String },
    #[error("gave up resolving {name}: too many referrals")]
    TooManyReferrals { name: String },
    #[error("{name} is not inside the zone {zone}")]
    NameOutsideZone { name: String, zone: String },
    #[error("no nameserver of {zone} answered any query")]
    NoServerReachable { zone: String },
}

fn enclosing_hint(enclosing: &Option<String>) -> String {
    match enclosing {
        Some(zone) => format!("; the enclosing zone is {zone}"),
        None => String::new(),
    }
}
