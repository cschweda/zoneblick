//! The digest: a summary of every zone over a period, for people who want
//! one message a week as well as an alert per change.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::checks::Severity;
use crate::output::{Summary, utc};
use crate::store::{FindingRow, Store, StoreError};

/// A finding named in a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DigestFinding {
    pub check_id: String,
    pub severity: Severity,
    pub name: String,
    pub summary: String,
}

impl From<&FindingRow> for DigestFinding {
    fn from(row: &FindingRow) -> Self {
        Self {
            check_id: row.check_id.clone(),
            severity: row.severity,
            name: row.name.clone(),
            summary: row.summary.clone(),
        }
    }
}

/// One zone's part of a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZoneDigest {
    pub zone: String,
    /// Runs stored in the period.
    pub runs: usize,
    pub last_run_unix: Option<u64>,
    /// Findings open now, by severity. Muted ones are not counted.
    pub open: Summary,
    /// Findings first seen in the period.
    pub opened: Vec<DigestFinding>,
    /// Findings last seen in the period and resolved since.
    pub resolved: Vec<DigestFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Digest {
    /// Always `digest`, so a webhook can tell it from an alert.
    pub kind: &'static str,
    pub since_unix: u64,
    pub until_unix: u64,
    /// The most severe open finding of any zone.
    pub severity: Severity,
    pub title: String,
    /// Plain text, one item per line.
    pub text: String,
    pub zones: Vec<ZoneDigest>,
}

fn counts(s: &Summary) -> String {
    let parts: Vec<String> = [
        (s.critical, "critical"),
        (s.warning, "warning"),
        (s.notice, "notice"),
        (s.info, "info"),
    ]
    .into_iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, label)| format!("{n} {label}"))
    .collect();
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(", ")
    }
}

/// Summarise every zone in the store over `since_unix..=until_unix`.
pub fn compose(store: &Store, since_unix: u64, until_unix: u64) -> Result<Digest, StoreError> {
    let mut zones = Vec::new();
    for summary in store.zones()? {
        let runs = store.runs(&summary.zone)?;
        let started: BTreeMap<i64, u64> = runs.iter().map(|r| (r.id, r.started_at_unix)).collect();
        let in_period = |run: i64| {
            started
                .get(&run)
                .is_some_and(|at| (since_unix..=until_unix).contains(at))
        };
        let rows = store.finding_rows(Some(&summary.zone), None)?;
        let mut open = Summary::default();
        for row in rows.iter().filter(|r| r.state == "open") {
            match row.severity {
                Severity::Critical => open.critical += 1,
                Severity::Warning => open.warning += 1,
                Severity::Notice => open.notice += 1,
                Severity::Info => open.info += 1,
            }
        }
        zones.push(ZoneDigest {
            runs: runs.iter().filter(|r| in_period(r.id)).count(),
            last_run_unix: summary.last_run.map(|r| r.started_at_unix),
            open,
            opened: rows
                .iter()
                .filter(|r| r.state != "muted" && in_period(r.first_seen_run))
                .map(DigestFinding::from)
                .collect(),
            resolved: rows
                .iter()
                .filter(|r| r.state == "resolved" && in_period(r.last_seen_run))
                .map(DigestFinding::from)
                .collect(),
            zone: summary.zone,
        });
    }

    let total = |pick: fn(&Summary) -> usize| zones.iter().map(|z| pick(&z.open)).sum::<usize>();
    let (critical, warning, notice) = (
        total(|s| s.critical),
        total(|s| s.warning),
        total(|s| s.notice),
    );
    let open_total = critical + warning + notice + total(|s| s.info);
    let severity = if critical > 0 {
        Severity::Critical
    } else if warning > 0 {
        Severity::Warning
    } else if notice > 0 {
        Severity::Notice
    } else {
        Severity::Info
    };
    let plural = |n: usize, one: &str, many: &str| {
        if n == 1 {
            format!("1 {one}")
        } else {
            format!("{n} {many}")
        }
    };
    let mut title = format!(
        "zoneblick digest: {}, {}",
        plural(zones.len(), "zone", "zones"),
        plural(open_total, "open finding", "open findings")
    );
    if critical > 0 {
        title.push_str(&format!(" ({critical} critical)"));
    }

    let mut lines = vec![format!("{} to {}", utc(since_unix), utc(until_unix))];
    for z in &zones {
        lines.push(String::new());
        lines.push(match z.last_run_unix {
            Some(at) if z.runs > 0 => {
                format!(
                    "{}  {}, last {}",
                    z.zone,
                    plural(z.runs, "run", "runs"),
                    utc(at)
                )
            }
            Some(at) => format!("{}  NO RUNS in this period; last {}", z.zone, utc(at)),
            None => format!("{}  never checked", z.zone),
        });
        lines.push(format!("  open: {}", counts(&z.open)));
        for f in &z.opened {
            lines.push(format!(
                "  OPENED {} ({}) {}",
                f.check_id,
                f.severity.as_str(),
                f.summary
            ));
        }
        for f in &z.resolved {
            lines.push(format!(
                "  RESOLVED {} ({}) {}",
                f.check_id,
                f.severity.as_str(),
                f.summary
            ));
        }
    }
    if zones.is_empty() {
        lines.push("no zones are stored yet".to_string());
    }

    Ok(Digest {
        kind: "digest",
        since_unix,
        until_unix,
        severity,
        title,
        text: lines.join("\n"),
        zones,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::*;
    use crate::runner::store_observation;

    #[test]
    fn a_digest_covers_the_period() {
        let mut store = Store::open_in_memory().unwrap();
        let mut run = |at: u64, broken: bool| {
            let mut obs = healthy();
            obs.started_at_unix = at;
            if broken {
                set_serial(&mut obs, V4_B, 43);
            }
            store_observation(&mut store, obs, vec![], 1, at, "test", &[]).unwrap();
        };
        run(100, true);
        run(200, true);
        run(300, false);

        // The whole history: opened and resolved again, nothing open.
        let all = compose(&store, 0, 1000).unwrap();
        assert_eq!(all.title, "zoneblick digest: 1 zone, 0 open findings");
        assert_eq!(all.severity, Severity::Info);
        let z = &all.zones[0];
        assert_eq!((z.runs, z.opened.len(), z.resolved.len()), (3, 1, 1));
        assert!(
            all.text.contains("example.test.  3 runs, last"),
            "{}",
            all.text
        );
        assert!(
            all.text.contains("  OPENED CON-01 (warning)"),
            "{}",
            all.text
        );
        assert!(all.text.contains("  open: none"));

        // Only the first run: one finding opened and still open then.
        let later = compose(&store, 250, 1000).unwrap();
        assert_eq!(later.zones[0].runs, 1);
        assert!(later.zones[0].opened.is_empty());

        // A period with no runs says so.
        let quiet = compose(&store, 5000, 6000).unwrap();
        assert!(
            quiet.text.contains("NO RUNS in this period"),
            "{}",
            quiet.text
        );
        assert_eq!(serde_json::to_value(&quiet).unwrap()["kind"], "digest");
    }
}
