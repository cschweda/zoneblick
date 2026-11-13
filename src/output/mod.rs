//! Rendering: the report document, as JSON or as terminal text.

pub mod human;
pub mod json;

use serde::Serialize;

use crate::checks::{Finding, Severity};
use crate::diff::DiffReport;
use crate::observe::{
    DnssecObservation, NsHost, PolicyObservation, RecordObservation, ReferralStep, ServerProbe,
    Vantage, ZoneObservation,
};
use crate::store::ZoneSummary;

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
    /// DNSSEC data: the parent's DS set, and each server's keys and signatures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnssec: Option<DnssecObservation>,
    /// Mail and policy records, the SPF chain, and alias targets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyObservation>,
    /// The deep probes. Present only for a deep run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deep: Option<crate::observe::DeepObservation>,
    /// Record sets per name, type and server. Present only for `run`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<RecordObservation>,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    pub exit_code: u8,
}

/// Where a run was stored.
#[derive(Debug, Clone, Serialize)]
pub struct StoredRun {
    pub id: i64,
    /// The database file.
    pub db: String,
    /// The names checked besides the apex.
    pub names: Vec<String>,
    pub queries: usize,
}

/// The `run --json` document: the report, where it was stored, and what
/// changed since the previous stored run of the zone.
#[derive(Debug, Clone, Serialize)]
pub struct RunDocument {
    pub schema_version: u32,
    pub run: StoredRun,
    pub report: Report,
    /// `null` for the first stored run of a zone.
    pub diff: Option<DiffReport>,
}

/// The `zones list --json` document.
#[derive(Debug, Clone, Serialize)]
pub struct ZonesDocument {
    pub schema_version: u32,
    pub db: String,
    pub zones: Vec<ZoneSummary>,
}

/// A Unix time as `2026-11-13 16:40 UTC`.
pub fn utc(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // Civil date from a day count (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60
    )
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
            dnssec: obs.dnssec,
            deep: obs.deep,
            policy: obs.policy,
            records: obs.records,
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

#[cfg(test)]
mod tests {
    use super::utc;

    #[test]
    fn formats_utc_times() {
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(1_700_000_000), "2023-11-14 22:13 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(utc(1_794_587_999), "2026-11-13 16:39 UTC");
    }
}
