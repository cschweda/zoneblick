//! Rendering: the report document, as JSON or as terminal text.

pub mod human;
pub mod json;

use serde::Serialize;

use crate::checks::{Finding, Severity};
use crate::observe::{NsHost, ReferralStep, ServerProbe, Vantage, ZoneObservation};

/// Version of the JSON document. It changes only when a field is removed,
/// renamed or changes meaning; new fields may be added without a bump.
pub const SCHEMA_VERSION: u32 = 1;

/// Exit codes of `zoneblick check`.
pub mod exit {
    /// No findings above `info`.
    pub const CLEAN: u8 = 0;
    /// Notices or warnings, nothing critical.
    pub const FINDINGS: u8 = 1;
    /// At least one critical finding.
    pub const CRITICAL: u8 = 2;
    /// The run itself failed.
    pub const RUN_FAILED: u8 = 3;
}

/// How many findings there are at each severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Summary {
    pub critical: usize,
    pub warning: usize,
    pub notice: usize,
    pub info: usize,
}

impl Summary {
    pub fn of(findings: &[Finding]) -> Self {
        let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
        Self {
            critical: count(Severity::Critical),
            warning: count(Severity::Warning),
            notice: count(Severity::Notice),
            info: count(Severity::Info),
        }
    }

    /// `info` findings alone do not change the exit code.
    pub fn exit_code(&self) -> u8 {
        if self.critical > 0 {
            exit::CRITICAL
        } else if self.warning + self.notice > 0 {
            exit::FINDINGS
        } else {
            exit::CLEAN
        }
    }
}

/// The result of a completed `check` run. This is the `--json` document.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub zone: String,
    pub started_at_unix: u64,
    pub vantage: Vantage,
    pub delegation_path: Vec<ReferralStep>,
    pub nameservers: Vec<NsHost>,
    pub probes: Vec<ServerProbe>,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    pub exit_code: u8,
}

impl Report {
    pub fn new(obs: ZoneObservation, findings: Vec<Finding>) -> Self {
        let summary = Summary::of(&findings);
        Self {
            schema_version: SCHEMA_VERSION,
            zone: obs.zone,
            started_at_unix: obs.started_at_unix,
            vantage: obs.vantage,
            delegation_path: obs.delegation_path,
            nameservers: obs.ns_hosts,
            probes: obs.probes,
            findings,
            summary,
            exit_code: summary.exit_code(),
        }
    }
}

/// The `--json` document for a run that failed before it could report.
#[derive(Debug, Clone, Serialize)]
pub struct FailureReport {
    pub schema_version: u32,
    pub zone: String,
    pub error: FailureDetail,
    pub exit_code: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct FailureDetail {
    /// A stable identifier, for example `zone_not_found`.
    pub kind: String,
    pub message: String,
}

impl FailureReport {
    pub fn new(zone: &str, kind: &str, message: String) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            zone: zone.to_string(),
            error: FailureDetail {
                kind: kind.to_string(),
                message,
            },
            exit_code: exit::RUN_FAILED,
        }
    }
}
