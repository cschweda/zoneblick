//! The store: one SQLite file holding every run of every zone.
//!
//! Record sets are content-addressed: a set is stored once under the hash
//! of its name, type and data, and each observation points at it. A run
//! that sees nothing new adds only small observation rows. TTLs live on the
//! observation, so a TTL change does not make a new record set.

use std::collections::BTreeSet;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::checks::{Evidence, Finding, Severity};
use crate::diff::{DiffReport, RunData, RunRef, StoredFinding, Volatility, diff_with};
use crate::observe::{
    DnssecObservation, NsHost, QType, RecordAnswer, RecordObservation, RecordOutcome, ReferralStep,
    ServerProbe, Transport, Vantage, ZoneObservation,
};

/// Version of the database layout, kept in SQLite's `user_version`.
const SCHEMA_VERSION: i64 = 5;

/// Changes to the layout since version 1, in order. Entry `i` takes a
/// database from version `i + 1` to `i + 2`. A new database is created at
/// version 1 and then walks the same steps, so both paths are the same code.
const MIGRATIONS: &[&str] = &[
    // 2: each run keeps the DNSSEC data it observed.
    "ALTER TABLE runs ADD COLUMN dnssec_json TEXT;",
    // 3: and the mail and policy data.
    "ALTER TABLE runs ADD COLUMN policy_json TEXT;",
    // 4: a zone can pin one run as its baseline.
    "CREATE TABLE baselines (
         zone_id    INTEGER PRIMARY KEY REFERENCES zones(id),
         run_id     INTEGER NOT NULL REFERENCES runs(id),
         pinned_at  INTEGER NOT NULL
     );",
    // 5: small values the daemon keeps between restarts.
    "CREATE TABLE meta (
         key    TEXT PRIMARY KEY,
         value  TEXT NOT NULL
     );",
];

/// How many earlier runs are read to learn which names rotate.
const HISTORY_RUNS: usize = 10;

/// What [`Store::prune`] removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct Pruned {
    pub runs: usize,
    pub record_sets: usize,
}

const SCHEMA: &str = "
CREATE TABLE zones (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL
);
CREATE TABLE names (
    id              INTEGER PRIMARY KEY,
    zone_id         INTEGER NOT NULL REFERENCES zones(id),
    fqdn            TEXT NOT NULL,
    source          TEXT NOT NULL,
    first_seen_run  INTEGER NOT NULL,
    last_seen_run   INTEGER NOT NULL,
    volatile        INTEGER NOT NULL DEFAULT 0,
    UNIQUE (zone_id, fqdn)
);
CREATE TABLE runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    zone_id          INTEGER NOT NULL REFERENCES zones(id),
    started_at       INTEGER NOT NULL,
    finished_at      INTEGER NOT NULL,
    trigger          TEXT NOT NULL,
    level            TEXT NOT NULL,
    status           TEXT NOT NULL,
    queries          INTEGER NOT NULL,
    vantage_ipv4     INTEGER NOT NULL,
    vantage_ipv6     INTEGER NOT NULL,
    delegation_json  TEXT NOT NULL,
    ns_hosts_json    TEXT NOT NULL,
    probes_json      TEXT NOT NULL
);
CREATE INDEX runs_by_zone ON runs (zone_id, id);
CREATE TABLE rrsets (
    hash   TEXT PRIMARY KEY,
    name   TEXT NOT NULL,
    rtype  TEXT NOT NULL,
    rdata  TEXT NOT NULL
);
CREATE TABLE observations (
    id             INTEGER PRIMARY KEY,
    run_id         INTEGER NOT NULL REFERENCES runs(id),
    name           TEXT NOT NULL,
    rtype          TEXT NOT NULL,
    ns_name        TEXT NOT NULL,
    server         TEXT NOT NULL,
    transport      TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    rcode          TEXT,
    authoritative  INTEGER,
    ttl            INTEGER,
    rrset_hash     TEXT REFERENCES rrsets(hash),
    message        TEXT
);
CREATE INDEX observations_by_run ON observations (run_id);
CREATE TABLE findings (
    id              INTEGER PRIMARY KEY,
    zone_id         INTEGER NOT NULL REFERENCES zones(id),
    fingerprint     TEXT NOT NULL,
    check_id        TEXT NOT NULL,
    name            TEXT NOT NULL,
    severity        TEXT NOT NULL,
    summary         TEXT NOT NULL,
    evidence_json   TEXT NOT NULL,
    first_seen_run  INTEGER NOT NULL,
    last_seen_run   INTEGER NOT NULL,
    state           TEXT NOT NULL,
    UNIQUE (zone_id, fingerprint)
);
CREATE TABLE run_findings (
    run_id      INTEGER NOT NULL REFERENCES runs(id),
    finding_id  INTEGER NOT NULL REFERENCES findings(id),
    severity    TEXT NOT NULL,
    summary     TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_id)
);
";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("stored data could not be read: {0}")]
    Json(#[from] serde_json::Error),
    #[error("stored data could not be read: {0}")]
    Corrupt(String),
    #[error(
        "the database was written by a newer zoneblick (layout {found}, this version reads {supported})"
    )]
    NewerSchema { found: i64, supported: i64 },
    #[error("zone {zone} has no stored runs in this database")]
    UnknownZone { zone: String },
    #[error("zone {zone} has no run #{run}; its runs are {available}")]
    UnknownRun {
        zone: String,
        run: i64,
        available: String,
    },
    #[error("zone {zone} has only {runs} stored run; a diff needs two")]
    NotEnoughRuns { zone: String, runs: usize },
    #[error(
        "zone {zone} has no finding whose ID starts with {id}; list them with: zoneblick findings list {zone}"
    )]
    UnknownFinding { zone: String, id: String },
    #[error("{count} findings of {zone} have an ID starting with {id}; give more of it")]
    AmbiguousFinding {
        zone: String,
        id: String,
        count: usize,
    },
}

/// One zone in the store, for `zones list`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ZoneSummary {
    pub zone: String,
    /// Names checked besides the apex.
    pub names: usize,
    pub runs: usize,
    pub last_run: Option<RunRef>,
    pub open_findings: usize,
}

/// The observation data of one stored run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunView {
    pub run: RunRef,
    pub vantage: Vantage,
    pub delegation_path: Vec<ReferralStep>,
    pub nameservers: Vec<NsHost>,
    pub probes: Vec<ServerProbe>,
    pub dnssec: Option<DnssecObservation>,
    pub queries: i64,
}

/// A finding and where it is in its lifecycle.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FindingRow {
    pub zone: String,
    pub fingerprint: String,
    pub check_id: String,
    pub name: String,
    pub severity: Severity,
    pub summary: String,
    pub evidence: Evidence,
    pub first_seen_run: i64,
    pub last_seen_run: i64,
    /// `open`, `resolved` or `muted`.
    pub state: String,
}

/// What a run needs besides the observation itself.
#[derive(Debug, Clone)]
pub struct RunMeta<'a> {
    /// Full names given for this run or remembered from earlier ones.
    pub names: &'a [String],
    pub finished_at_unix: u64,
    pub queries: usize,
    /// What started the run: `cli` in this phase.
    pub trigger: &'a str,
}

pub struct Store {
    conn: Connection,
}

/// The stable identity of a finding across runs.
pub fn fingerprint(finding: &Finding) -> String {
    hex(&Sha256::digest(finding.fingerprint_key().as_bytes()))[..32].to_string()
}

/// The content hash of a record set.
fn rrset_hash(name: &str, rtype: QType, rdata: &[String]) -> String {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update([0]);
    h.update(rtype.as_str().as_bytes());
    for item in rdata {
        h.update([0]);
        h.update(item.as_bytes());
    }
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn transport_str(t: Transport) -> &'static str {
    match t {
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
    }
}

fn corrupt(what: &str, value: &str) -> StoreError {
    StoreError::Corrupt(format!("unknown {what} '{value}'"))
}

impl Store {
    /// Open the database file, creating it and its tables when it is new.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        // The database lists what is wrong with the zones, so a new one is
        // readable by its owner only. On Unix, SQLite gives its side files
        // the same permissions. An existing file is left as it is.
        #[cfg(unix)]
        if !path.exists() {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path);
        }
        // Windows has no file mode: the new file is made empty and its
        // permissions are narrowed before SQLite writes anything to it.
        #[cfg(windows)]
        let new_on_windows = !path.exists()
            && std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .is_ok()
            && crate::private::restrict(path).is_ok();
        let conn = Connection::open(path)?;
        // WAL keeps readers and the writer out of each other's way.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let store = Self::init(conn)?;
        // On Windows the side files take the directory's permissions, so
        // those of a database made here are narrowed as well.
        #[cfg(windows)]
        if new_on_windows {
            for suffix in ["-wal", "-shm"] {
                let mut side = path.as_os_str().to_owned();
                side.push(suffix);
                let side = std::path::PathBuf::from(side);
                if side.exists() {
                    let _ = crate::private::restrict(&side);
                }
            }
        }
        Ok(store)
    }

    /// A store that lives only in memory, for tests.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, StoreError> {
        conn.pragma_update(None, "foreign_keys", true)?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::NewerSchema {
                found: version,
                supported: SCHEMA_VERSION,
            });
        }
        let mut version = version;
        if version == 0 {
            conn.execute_batch(&format!("BEGIN; {SCHEMA} PRAGMA user_version = 1; COMMIT;"))?;
            version = 1;
        }
        while version < SCHEMA_VERSION {
            let step = MIGRATIONS[(version - 1) as usize];
            version += 1;
            conn.execute_batch(&format!(
                "BEGIN; {step} PRAGMA user_version = {version}; COMMIT;"
            ))?;
        }
        Ok(Self { conn })
    }

    fn zone_id(&self, zone: &str) -> Result<i64, StoreError> {
        self.conn
            .query_row("SELECT id FROM zones WHERE name = ?1", [zone], |r| r.get(0))
            .optional()?
            .ok_or_else(|| StoreError::UnknownZone {
                zone: zone.to_string(),
            })
    }

    /// The ID of the newest run of any zone; 0 for an empty store.
    pub fn latest_run_id(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT COALESCE(MAX(id), 0) FROM runs", [], |r| r.get(0))?)
    }

    /// A small value kept between restarts, such as when the last digest
    /// went out.
    pub fn meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// The names remembered for a zone, besides the apex. Empty for a zone
    /// that has never been stored.
    pub fn names(&self, zone: &str) -> Result<Vec<String>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT n.fqdn FROM names n JOIN zones z ON z.id = n.zone_id
             WHERE z.name = ?1 AND n.source != 'apex' ORDER BY n.fqdn",
        )?;
        let rows = stmt.query_map([zone], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Record where names came from, for example `ct` for names found in
    /// certificate logs. Names not yet stored for the zone are left alone.
    pub fn set_name_source(
        &self,
        zone: &str,
        names: &[String],
        source: &str,
    ) -> Result<(), StoreError> {
        for name in names {
            self.conn.execute(
                "UPDATE names SET source = ?3 WHERE fqdn = ?2 AND source != 'apex'
                 AND zone_id = (SELECT id FROM zones WHERE name = ?1)",
                params![zone, name, source],
            )?;
        }
        Ok(())
    }

    /// Stop checking a name in later runs. Its history stays.
    pub fn forget_name(&self, zone: &str, name: &str) -> Result<bool, StoreError> {
        let n = self.conn.execute(
            "DELETE FROM names WHERE fqdn = ?2 AND source != 'apex'
             AND zone_id = (SELECT id FROM zones WHERE name = ?1)",
            params![zone, name],
        )?;
        Ok(n > 0)
    }

    /// Store one run as a snapshot and update the lifecycle of findings.
    /// Returns the new run's ID.
    pub fn save_run(
        &mut self,
        obs: &ZoneObservation,
        findings: &[Finding],
        meta: &RunMeta<'_>,
    ) -> Result<i64, StoreError> {
        let tx = self.conn.transaction()?;
        let started = obs.started_at_unix as i64;

        tx.execute(
            "INSERT OR IGNORE INTO zones (name, created_at) VALUES (?1, ?2)",
            params![obs.zone, started],
        )?;
        let zone_id: i64 =
            tx.query_row("SELECT id FROM zones WHERE name = ?1", [&obs.zone], |r| {
                r.get(0)
            })?;

        tx.execute(
            "INSERT INTO runs (zone_id, started_at, finished_at, trigger, level, status, queries,
                               vantage_ipv4, vantage_ipv6, delegation_json, ns_hosts_json, probes_json,
                               dnssec_json, policy_json)
             VALUES (?1, ?2, ?3, ?4, ?13, 'ok', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                zone_id,
                started,
                meta.finished_at_unix as i64,
                meta.trigger,
                meta.queries as i64,
                obs.vantage.ipv4,
                obs.vantage.ipv6,
                serde_json::to_string(&obs.delegation_path)?,
                serde_json::to_string(&obs.ns_hosts)?,
                serde_json::to_string(&obs.probes)?,
                obs.dnssec.as_ref().map(serde_json::to_string).transpose()?,
                obs.policy.as_ref().map(serde_json::to_string).transpose()?,
                if obs.deep.is_some() { "deep" } else { "light" },
            ],
        )?;
        let run_id = tx.last_insert_rowid();

        {
            let mut upsert = tx.prepare(
                "INSERT INTO names (zone_id, fqdn, source, first_seen_run, last_seen_run)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT (zone_id, fqdn) DO UPDATE SET last_seen_run = ?4",
            )?;
            upsert.execute(params![zone_id, obs.zone, "apex", run_id])?;
            for name in meta.names.iter().filter(|n| **n != obs.zone) {
                upsert.execute(params![zone_id, name, "seed", run_id])?;
            }

            let mut add_rrset = tx.prepare(
                "INSERT OR IGNORE INTO rrsets (hash, name, rtype, rdata) VALUES (?1, ?2, ?3, ?4)",
            )?;
            let mut add_obs = tx.prepare(
                "INSERT INTO observations (run_id, name, rtype, ns_name, server, transport,
                                           outcome, rcode, authoritative, ttl, rrset_hash, message)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?;
            for rec in &obs.records {
                let (outcome, rcode, aa, ttl, hash, message) = match &rec.outcome {
                    RecordOutcome::Answer(a) => {
                        let hash = rrset_hash(&rec.name, rec.qtype, &a.rdata);
                        add_rrset.execute(params![
                            hash,
                            rec.name,
                            rec.qtype.as_str(),
                            serde_json::to_string(&a.rdata)?
                        ])?;
                        (
                            "answer",
                            Some(a.rcode.as_str()),
                            Some(a.authoritative),
                            a.ttl,
                            Some(hash),
                            None,
                        )
                    }
                    RecordOutcome::Timeout => ("timeout", None, None, None, None, None),
                    RecordOutcome::NetError { message } => {
                        ("net_error", None, None, None, None, Some(message.as_str()))
                    }
                    RecordOutcome::Malformed { message } => {
                        ("malformed", None, None, None, None, Some(message.as_str()))
                    }
                };
                add_obs.execute(params![
                    run_id,
                    rec.name,
                    rec.qtype.as_str(),
                    rec.ns_name,
                    rec.address.to_string(),
                    transport_str(rec.transport),
                    outcome,
                    rcode,
                    aa,
                    ttl,
                    hash,
                    message,
                ])?;
            }

            // Findings: seen again stays (or becomes) open; not seen is resolved.
            let mut upsert_finding = tx.prepare(
                "INSERT INTO findings (zone_id, fingerprint, check_id, name, severity, summary,
                                       evidence_json, first_seen_run, last_seen_run, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 'open')
                 ON CONFLICT (zone_id, fingerprint) DO UPDATE SET
                     severity = ?5, summary = ?6, evidence_json = ?7,
                     last_seen_run = ?8,
                     state = CASE state WHEN 'muted' THEN 'muted' ELSE 'open' END",
            )?;
            let mut link = tx.prepare(
                "INSERT OR IGNORE INTO run_findings (run_id, finding_id, severity, summary)
                 SELECT ?1, id, ?4, ?5 FROM findings WHERE zone_id = ?2 AND fingerprint = ?3",
            )?;
            for finding in findings {
                let print = fingerprint(finding);
                upsert_finding.execute(params![
                    zone_id,
                    print,
                    finding.check_id,
                    finding.name,
                    finding.severity.as_str(),
                    finding.summary,
                    serde_json::to_string(&finding.evidence)?,
                    run_id,
                ])?;
                link.execute(params![
                    run_id,
                    zone_id,
                    print,
                    finding.severity.as_str(),
                    finding.summary
                ])?;
            }
            // A light run says nothing about the deep checks, and a run
            // that did not read certificate logs says nothing about the
            // certificate checks: their open findings carry over, and only
            // a run that makes those checks resolves them.
            let deep_ids: Vec<String> = crate::checks::CATALOG
                .iter()
                .filter(|c| {
                    (c.deep && obs.deep.is_none())
                        || (crate::checks::needs_certificates(c.id) && obs.certificates.is_none())
                })
                .map(|c| format!("'{}'", c.id))
                .collect();
            if !deep_ids.is_empty() {
                let carried = format!(
                    "zone_id = ?2 AND state IN ('open', 'muted') AND last_seen_run < ?1
                     AND check_id IN ({})",
                    deep_ids.join(", ")
                );
                tx.execute(
                    &format!(
                        "INSERT OR IGNORE INTO run_findings (run_id, finding_id, severity, summary)
                         SELECT ?1, id, severity, summary FROM findings WHERE {carried}"
                    ),
                    params![run_id, zone_id],
                )?;
                tx.execute(
                    &format!("UPDATE findings SET last_seen_run = ?1 WHERE {carried}"),
                    params![run_id, zone_id],
                )?;
            }
            tx.execute(
                "UPDATE findings SET state = 'resolved'
                 WHERE zone_id = ?1 AND state = 'open' AND last_seen_run < ?2",
                params![zone_id, run_id],
            )?;
        }

        tx.commit()?;
        Ok(run_id)
    }

    /// The stored runs of a zone, oldest first.
    pub fn runs(&self, zone: &str) -> Result<Vec<RunRef>, StoreError> {
        let zone_id = self.zone_id(zone)?;
        let mut stmt = self
            .conn
            .prepare("SELECT id, started_at FROM runs WHERE zone_id = ?1 ORDER BY id")?;
        let rows = stmt.query_map([zone_id], |r| {
            Ok(RunRef {
                id: r.get(0)?,
                started_at_unix: r.get::<_, i64>(1)? as u64,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The latest `limit` runs of a zone, oldest first, each with how many
    /// findings it had at each severity (critical, warning, notice). Muted
    /// findings are not counted.
    pub fn run_timeline(
        &self,
        zone: &str,
        limit: usize,
    ) -> Result<Vec<(RunRef, [usize; 3])>, StoreError> {
        let zone_id = self.zone_id(zone)?;
        let mut stmt = self.conn.prepare(
            "SELECT r.id, r.started_at,
                    COALESCE(SUM(rf.severity = 'critical'), 0),
                    COALESCE(SUM(rf.severity = 'warning'), 0),
                    COALESCE(SUM(rf.severity = 'notice'), 0)
             FROM runs r
             LEFT JOIN run_findings rf ON rf.run_id = r.id
                  AND rf.finding_id NOT IN (SELECT id FROM findings WHERE state = 'muted')
             WHERE r.zone_id = ?1
             GROUP BY r.id ORDER BY r.id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![zone_id, limit as i64], |r| {
            Ok((
                RunRef {
                    id: r.get(0)?,
                    started_at_unix: r.get::<_, i64>(1)? as u64,
                },
                [
                    r.get::<_, i64>(2)? as usize,
                    r.get::<_, i64>(3)? as usize,
                    r.get::<_, i64>(4)? as usize,
                ],
            ))
        })?;
        let mut out: Vec<(RunRef, [usize; 3])> = rows.collect::<Result<_, _>>()?;
        out.reverse();
        Ok(out)
    }

    /// The two runs a diff compares. With no IDs given: the latest run and
    /// the one before it. With only `to` given: that run and the one before.
    pub fn pick_runs(
        &self,
        zone: &str,
        from: Option<i64>,
        to: Option<i64>,
    ) -> Result<(RunRef, RunRef), StoreError> {
        let runs = self.runs(zone)?;
        let find = |id: i64| {
            runs.iter()
                .copied()
                .find(|r| r.id == id)
                .ok_or_else(|| StoreError::UnknownRun {
                    zone: zone.to_string(),
                    run: id,
                    available: runs
                        .iter()
                        .map(|r| format!("#{}", r.id))
                        .collect::<Vec<_>>()
                        .join(", "),
                })
        };
        let too_few = || StoreError::NotEnoughRuns {
            zone: zone.to_string(),
            runs: runs.len(),
        };
        let to_run = match to {
            Some(id) => find(id)?,
            None => *runs.last().ok_or_else(too_few)?,
        };
        let from_run = match from {
            Some(id) => find(id)?,
            None => *runs
                .iter()
                .rev()
                .find(|r| r.id < to_run.id)
                .ok_or_else(too_few)?,
        };
        Ok((from_run, to_run))
    }

    /// Compare two stored runs, `from` the older one. Address rotation of
    /// names that the runs before `from` show to be volatile is marked.
    pub fn diff(
        &self,
        zone: &str,
        from: RunRef,
        to: RunRef,
        ignore: &[String],
    ) -> Result<DiffReport, StoreError> {
        let mut history = Vec::new();
        let earlier: Vec<RunRef> = self
            .runs(zone)?
            .into_iter()
            .filter(|r| r.id <= from.id)
            .collect();
        let skip = earlier.len().saturating_sub(HISTORY_RUNS);
        for run in &earlier[skip..] {
            history.push(self.load_run(zone, *run)?);
        }
        let volatility = Volatility::learn(&history);
        let from_data = match history.pop() {
            Some(data) if data.run == from => data,
            _ => self.load_run(zone, from)?,
        };
        let mut report = diff_with(&from_data, &self.load_run(zone, to)?, ignore, &volatility);
        report.drop_findings(&self.muted(zone)?);
        Ok(report)
    }

    /// The fingerprints of the zone's muted findings.
    pub fn muted(&self, zone: &str) -> Result<BTreeSet<String>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT f.fingerprint FROM findings f JOIN zones z ON z.id = f.zone_id
             WHERE z.name = ?1 AND f.state = 'muted'",
        )?;
        let rows = stmt.query_map([zone], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Mute or unmute the one finding whose fingerprint starts with `id`.
    /// A muted finding is still recorded but not reported or alerted on.
    /// Unmuting makes it open when the latest run saw it, else resolved.
    /// Returns the finding with its new state.
    pub fn set_muted(&self, zone: &str, id: &str, muted: bool) -> Result<FindingRow, StoreError> {
        let zone_id = self.zone_id(zone)?;
        let id = id.trim().to_ascii_lowercase();
        let mut matches: Vec<FindingRow> = self
            .finding_rows(Some(zone), None)?
            .into_iter()
            .filter(|f| !id.is_empty() && f.fingerprint.starts_with(&id))
            .collect();
        if matches.len() > 1 {
            return Err(StoreError::AmbiguousFinding {
                zone: zone.to_string(),
                id,
                count: matches.len(),
            });
        }
        let Some(mut row) = matches.pop() else {
            return Err(StoreError::UnknownFinding {
                zone: zone.to_string(),
                id,
            });
        };
        let latest: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(id), 0) FROM runs WHERE zone_id = ?1",
            [zone_id],
            |r| r.get(0),
        )?;
        row.state = if muted {
            "muted"
        } else if row.last_seen_run == latest {
            "open"
        } else {
            "resolved"
        }
        .to_string();
        self.conn.execute(
            "UPDATE findings SET state = ?3 WHERE zone_id = ?1 AND fingerprint = ?2",
            params![zone_id, row.fingerprint, row.state],
        )?;
        Ok(row)
    }

    /// Add a zone that has no runs yet. True when it was not there before.
    pub fn add_zone(&self, zone: &str, now_unix: u64) -> Result<bool, StoreError> {
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO zones (name, created_at) VALUES (?1, ?2)",
            params![zone, now_unix as i64],
        )?;
        Ok(n > 0)
    }

    /// Remember names for a zone, to be checked from the next run on.
    /// `run` is the run that found them, 0 for names given by hand.
    /// Returns how many were new.
    pub fn add_names(
        &self,
        zone: &str,
        names: &[String],
        source: &str,
        run: i64,
    ) -> Result<usize, StoreError> {
        let zone_id = self.zone_id(zone)?;
        let mut added = 0;
        for name in names.iter().filter(|n| *n != zone) {
            added += self.conn.execute(
                "INSERT OR IGNORE INTO names (zone_id, fqdn, source, first_seen_run, last_seen_run)
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                params![zone_id, name, source, run],
            )?;
        }
        Ok(added)
    }

    /// Delete a zone with all its runs, names and findings. Returns how
    /// many runs went with it.
    pub fn remove_zone(&mut self, zone: &str) -> Result<usize, StoreError> {
        let zone_id = self.zone_id(zone)?;
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM baselines WHERE zone_id = ?1", [zone_id])?;
        tx.execute(
            "DELETE FROM run_findings WHERE run_id IN (SELECT id FROM runs WHERE zone_id = ?1)",
            [zone_id],
        )?;
        tx.execute(
            "DELETE FROM observations WHERE run_id IN (SELECT id FROM runs WHERE zone_id = ?1)",
            [zone_id],
        )?;
        tx.execute("DELETE FROM findings WHERE zone_id = ?1", [zone_id])?;
        tx.execute("DELETE FROM names WHERE zone_id = ?1", [zone_id])?;
        let runs = tx.execute("DELETE FROM runs WHERE zone_id = ?1", [zone_id])?;
        tx.execute("DELETE FROM zones WHERE id = ?1", [zone_id])?;
        tx.execute(
            "DELETE FROM rrsets WHERE hash NOT IN
                 (SELECT rrset_hash FROM observations WHERE rrset_hash IS NOT NULL)",
            [],
        )?;
        tx.commit()?;
        Ok(runs)
    }

    /// Pin a run as the zone's baseline: the state that counts as correct.
    /// Without a run ID, the latest run is pinned.
    pub fn pin_baseline(
        &self,
        zone: &str,
        run: Option<i64>,
        now_unix: u64,
    ) -> Result<RunRef, StoreError> {
        let zone_id = self.zone_id(zone)?;
        let runs = self.runs(zone)?;
        let picked = match run {
            None => runs.last().copied(),
            Some(id) => runs.iter().copied().find(|r| r.id == id),
        }
        .ok_or_else(|| StoreError::UnknownRun {
            zone: zone.to_string(),
            run: run.unwrap_or(0),
            available: runs
                .iter()
                .map(|r| format!("#{}", r.id))
                .collect::<Vec<_>>()
                .join(", "),
        })?;
        self.conn.execute(
            "INSERT INTO baselines (zone_id, run_id, pinned_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (zone_id) DO UPDATE SET run_id = ?2, pinned_at = ?3",
            params![zone_id, picked.id, now_unix as i64],
        )?;
        Ok(picked)
    }

    /// Remove the zone's baseline. True when there was one.
    pub fn clear_baseline(&self, zone: &str) -> Result<bool, StoreError> {
        let zone_id = self.zone_id(zone)?;
        let n = self
            .conn
            .execute("DELETE FROM baselines WHERE zone_id = ?1", [zone_id])?;
        Ok(n > 0)
    }

    /// The zone's pinned baseline run, when it has one.
    pub fn baseline(&self, zone: &str) -> Result<Option<RunRef>, StoreError> {
        let zone_id = self.zone_id(zone)?;
        Ok(self
            .conn
            .query_row(
                "SELECT r.id, r.started_at FROM baselines b JOIN runs r ON r.id = b.run_id
                 WHERE b.zone_id = ?1",
                [zone_id],
                |r| {
                    Ok(RunRef {
                        id: r.get(0)?,
                        started_at_unix: r.get::<_, i64>(1)? as u64,
                    })
                },
            )
            .optional()?)
    }

    /// Delete old runs. Runs younger than `keep_all_secs` stay. Older ones
    /// are thinned to the last run of each UTC day, and deleted once older
    /// than `keep_daily_secs`. A zone's latest run and its baseline always
    /// stay, and so does the history of findings.
    pub fn prune(
        &mut self,
        now_unix: u64,
        keep_all_secs: u64,
        keep_daily_secs: u64,
    ) -> Result<Pruned, StoreError> {
        let tx = self.conn.transaction()?;
        let mut doomed: Vec<i64> = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT r.id, r.zone_id, r.started_at,
                        r.id = (SELECT MAX(id) FROM runs WHERE zone_id = r.zone_id),
                        EXISTS (SELECT 1 FROM baselines b WHERE b.run_id = r.id)
                 FROM runs r ORDER BY r.zone_id, r.id DESC",
            )?;
            let mut rows = stmt.query([])?;
            // Newest first, so the first run seen for a day is its last.
            let mut days_kept: BTreeSet<(i64, i64)> = BTreeSet::new();
            while let Some(r) = rows.next()? {
                let (id, zone_id, started): (i64, i64, i64) = (r.get(0)?, r.get(1)?, r.get(2)?);
                let (latest, pinned): (bool, bool) = (r.get(3)?, r.get(4)?);
                let age = (now_unix as i64).saturating_sub(started);
                let day = (zone_id, started.div_euclid(86_400));
                let keep = if age <= keep_all_secs as i64 {
                    true
                } else if age <= keep_daily_secs as i64 {
                    days_kept.insert(day)
                } else {
                    false
                };
                if !(keep || latest || pinned) {
                    doomed.push(id);
                }
            }
        }
        for id in &doomed {
            tx.execute("DELETE FROM run_findings WHERE run_id = ?1", [id])?;
            tx.execute("DELETE FROM observations WHERE run_id = ?1", [id])?;
            tx.execute("DELETE FROM runs WHERE id = ?1", [id])?;
        }
        let record_sets = if doomed.is_empty() {
            0
        } else {
            tx.execute(
                "DELETE FROM rrsets WHERE hash NOT IN
                     (SELECT rrset_hash FROM observations WHERE rrset_hash IS NOT NULL)",
                [],
            )?
        };
        tx.commit()?;
        Ok(Pruned {
            runs: doomed.len(),
            record_sets,
        })
    }

    /// Load what a diff needs from one stored run.
    pub fn load_run(&self, zone: &str, run: RunRef) -> Result<RunData, StoreError> {
        let delegation_json: String = self.conn.query_row(
            "SELECT delegation_json FROM runs WHERE id = ?1",
            [run.id],
            |r| r.get(0),
        )?;
        let path: Vec<ReferralStep> = serde_json::from_str(&delegation_json)?;
        let parent = path.last().filter(|s| s.to_zone == zone);

        let mut stmt = self.conn.prepare(
            "SELECT o.name, o.rtype, o.ns_name, o.server, o.transport, o.outcome, o.rcode,
                    o.authoritative, o.ttl, s.rdata, o.message
             FROM observations o LEFT JOIN rrsets s ON s.hash = o.rrset_hash
             WHERE o.run_id = ?1",
        )?;
        let mut rows = stmt.query([run.id])?;
        let mut records = Vec::new();
        while let Some(r) = rows.next()? {
            let rtype: String = r.get(1)?;
            let server: String = r.get(3)?;
            let transport: String = r.get(4)?;
            let outcome: String = r.get(5)?;
            let message: Option<String> = r.get(10)?;
            let message = message.unwrap_or_default();
            let outcome = match outcome.as_str() {
                "answer" => {
                    let rdata: Option<String> = r.get(9)?;
                    RecordOutcome::Answer(RecordAnswer {
                        rcode: r.get(6)?,
                        authoritative: r.get(7)?,
                        ttl: r.get(8)?,
                        rdata: serde_json::from_str(&rdata.unwrap_or_else(|| "[]".into()))?,
                    })
                }
                "timeout" => RecordOutcome::Timeout,
                "net_error" => RecordOutcome::NetError { message },
                "malformed" => RecordOutcome::Malformed { message },
                other => return Err(corrupt("outcome", other)),
            };
            records.push(RecordObservation {
                name: r.get(0)?,
                qtype: QType::parse(&rtype).ok_or_else(|| corrupt("record type", &rtype))?,
                ns_name: r.get(2)?,
                address: server.parse().map_err(|_| corrupt("address", &server))?,
                transport: match transport.as_str() {
                    "udp" => Transport::Udp,
                    "tcp" => Transport::Tcp,
                    other => return Err(corrupt("transport", other)),
                },
                outcome,
            });
        }
        records.sort();

        let mut stmt = self.conn.prepare(
            "SELECT rf.severity, f.check_id, f.name, rf.summary, f.fingerprint
             FROM run_findings rf JOIN findings f ON f.id = rf.finding_id
             WHERE rf.run_id = ?1",
        )?;
        let mut rows = stmt.query([run.id])?;
        let mut findings = Vec::new();
        while let Some(r) = rows.next()? {
            let severity: String = r.get(0)?;
            findings.push(StoredFinding {
                severity: Severity::parse(&severity)
                    .ok_or_else(|| corrupt("severity", &severity))?,
                check_id: r.get(1)?,
                name: r.get(2)?,
                summary: r.get(3)?,
                fingerprint: r.get(4)?,
            });
        }
        findings.sort();

        Ok(RunData {
            run,
            zone: zone.to_string(),
            parent_ns: parent.map(|p| p.ns.clone()),
            glue: parent.map(|p| p.glue.clone()).unwrap_or_default(),
            records,
            findings,
        })
    }

    /// Every zone in the store, by name.
    pub fn zones(&self) -> Result<Vec<ZoneSummary>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT z.name,
                    (SELECT COUNT(*) FROM names n WHERE n.zone_id = z.id AND n.source != 'apex'),
                    (SELECT COUNT(*) FROM runs r WHERE r.zone_id = z.id),
                    (SELECT MAX(r.id) FROM runs r WHERE r.zone_id = z.id),
                    (SELECT r.started_at FROM runs r WHERE r.zone_id = z.id ORDER BY r.id DESC LIMIT 1),
                    (SELECT COUNT(*) FROM findings f WHERE f.zone_id = z.id AND f.state = 'open')
             FROM zones z ORDER BY z.name",
        )?;
        let rows = stmt.query_map([], |r| {
            let last_id: Option<i64> = r.get(3)?;
            let last_at: Option<i64> = r.get(4)?;
            Ok(ZoneSummary {
                zone: r.get(0)?,
                names: r.get::<_, i64>(1)? as usize,
                runs: r.get::<_, i64>(2)? as usize,
                last_run: last_id.zip(last_at).map(|(id, at)| RunRef {
                    id,
                    started_at_unix: at as u64,
                }),
                open_findings: r.get::<_, i64>(5)? as usize,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The DNSKEY set seen in the zone's latest stored run, over all its
    /// nameservers. `None` when there is no run, or it has no key data.
    pub fn latest_dnskeys(
        &self,
        zone: &str,
    ) -> Result<Option<Vec<crate::dnssec::Dnskey>>, StoreError> {
        let json: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT r.dnssec_json FROM runs r JOIN zones z ON z.id = r.zone_id
                 WHERE z.name = ?1 ORDER BY r.id DESC LIMIT 1",
                [zone],
                |r| r.get(0),
            )
            .optional()?;
        let Some(Some(json)) = json else {
            return Ok(None);
        };
        let sec: DnssecObservation = serde_json::from_str(&json)?;
        if !sec.servers.iter().any(|s| s.dnskeys.is_some()) {
            return Ok(None);
        }
        let keys: BTreeSet<crate::dnssec::Dnskey> = sec
            .servers
            .into_iter()
            .filter_map(|s| s.dnskeys)
            .flatten()
            .collect();
        Ok(Some(keys.into_iter().collect()))
    }

    /// The observation data of the zone's latest run, for the API and UI.
    pub fn latest_run_view(&self, zone: &str) -> Result<Option<RunView>, StoreError> {
        let Some(run) = self.runs(zone)?.pop() else {
            return Ok(None);
        };
        let mut stmt = self.conn.prepare(
            "SELECT vantage_ipv4, vantage_ipv6, delegation_json, ns_hosts_json, probes_json,
                    dnssec_json, queries
             FROM runs WHERE id = ?1",
        )?;
        let mut rows = stmt.query([run.id])?;
        let Some(r) = rows.next()? else {
            return Ok(None);
        };
        let delegation: String = r.get(2)?;
        let hosts: String = r.get(3)?;
        let probes: String = r.get(4)?;
        let dnssec: Option<String> = r.get(5)?;
        Ok(Some(RunView {
            run,
            vantage: Vantage {
                ipv4: r.get(0)?,
                ipv6: r.get(1)?,
            },
            delegation_path: serde_json::from_str(&delegation)?,
            nameservers: serde_json::from_str(&hosts)?,
            probes: serde_json::from_str(&probes)?,
            dnssec: dnssec.as_deref().map(serde_json::from_str).transpose()?,
            queries: r.get(6)?,
        }))
    }

    /// Findings with their lifecycle, optionally for one zone or one state
    /// (`open` or `resolved`), most severe first.
    pub fn finding_rows(
        &self,
        zone: Option<&str>,
        state: Option<&str>,
    ) -> Result<Vec<FindingRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT z.name, f.fingerprint, f.check_id, f.name, f.severity, f.summary,
                    f.evidence_json, f.first_seen_run, f.last_seen_run, f.state
             FROM findings f JOIN zones z ON z.id = f.zone_id
             WHERE (?1 IS NULL OR z.name = ?1) AND (?2 IS NULL OR f.state = ?2)",
        )?;
        let mut rows = stmt.query(params![zone, state])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            let severity: String = r.get(4)?;
            let evidence: String = r.get(6)?;
            out.push(FindingRow {
                zone: r.get(0)?,
                fingerprint: r.get(1)?,
                check_id: r.get(2)?,
                name: r.get(3)?,
                severity: Severity::parse(&severity)
                    .ok_or_else(|| corrupt("severity", &severity))?,
                summary: r.get(5)?,
                evidence: serde_json::from_str(&evidence)?,
                first_seen_run: r.get(7)?,
                last_seen_run: r.get(8)?,
                state: r.get(9)?,
            });
        }
        out.sort_by(|a, b| {
            (a.severity, &a.zone, &a.check_id, &a.name).cmp(&(
                b.severity,
                &b.zone,
                &b.check_id,
                &b.name,
            ))
        });
        Ok(out)
    }

    /// The state of every finding of a zone, as (fingerprint, state).
    pub fn finding_states(&self, zone: &str) -> Result<BTreeSet<(String, String)>, StoreError> {
        let zone_id = self.zone_id(zone)?;
        let mut stmt = self
            .conn
            .prepare("SELECT fingerprint, state FROM findings WHERE zone_id = ?1")?;
        let rows = stmt.query_map([zone_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    #[cfg(test)]
    fn count(&self, table: &str) -> i64 {
        self.conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::run_all;
    use crate::checks::testkit::*;
    use crate::diff::diff;

    fn rec(name: &str, server: &str, rdata: &[&str]) -> RecordObservation {
        RecordObservation {
            name: name.to_string(),
            qtype: QType::A,
            ns_name: "ns1.example.test.".to_string(),
            address: ip(server),
            transport: Transport::Udp,
            outcome: RecordOutcome::Answer(RecordAnswer {
                rcode: "NOERROR".to_string(),
                authoritative: true,
                ttl: Some(300),
                rdata: rdata.iter().map(|s| s.to_string()).collect(),
            }),
        }
    }

    fn obs_with(www: &str, at: u64) -> ZoneObservation {
        let mut obs = healthy();
        obs.started_at_unix = at;
        obs.records = vec![
            rec("www.example.test.", V4_A, &[www]),
            rec("www.example.test.", V4_B, &[www]),
            RecordObservation {
                outcome: RecordOutcome::Timeout,
                ..rec("mail.example.test.", V4_A, &[])
            },
        ];
        obs.records.sort();
        obs
    }

    fn save(store: &mut Store, obs: &ZoneObservation) -> i64 {
        let names = vec![
            "www.example.test.".to_string(),
            "mail.example.test.".to_string(),
        ];
        let meta = RunMeta {
            names: &names,
            finished_at_unix: obs.started_at_unix + 2,
            queries: 10,
            trigger: "cli",
        };
        store.save_run(obs, &run_all(obs), &meta).unwrap()
    }

    #[test]
    fn a_run_round_trips() {
        let mut store = Store::open_in_memory().unwrap();
        let obs = obs_with("192.0.2.10", 100);
        let id = save(&mut store, &obs);
        let runs = store.runs(ZONE).unwrap();
        assert_eq!(
            runs,
            [RunRef {
                id,
                started_at_unix: 100
            }]
        );
        let data = store.load_run(ZONE, runs[0]).unwrap();
        assert_eq!(data.records, obs.records);
        assert_eq!(
            data.parent_ns.unwrap(),
            ["ns1.example.test.", "ns2.example.test."]
        );
        assert_eq!(data.glue.len(), 2);
        assert_eq!(
            store.names(ZONE).unwrap(),
            ["mail.example.test.", "www.example.test."]
        );
    }

    #[test]
    fn unchanged_record_sets_are_stored_once() {
        let mut store = Store::open_in_memory().unwrap();
        save(&mut store, &obs_with("192.0.2.10", 100));
        assert_eq!(store.count("rrsets"), 1);
        assert_eq!(store.count("observations"), 3);
        save(&mut store, &obs_with("192.0.2.10", 200));
        assert_eq!(store.count("rrsets"), 1, "same data, no new record set");
        assert_eq!(store.count("observations"), 6);
        save(&mut store, &obs_with("192.0.2.99", 300));
        assert_eq!(store.count("rrsets"), 2);
    }

    #[test]
    fn stored_runs_diff() {
        let mut store = Store::open_in_memory().unwrap();
        save(&mut store, &obs_with("192.0.2.10", 100));
        save(&mut store, &obs_with("192.0.2.99", 200));
        let (from, to) = store.pick_runs(ZONE, None, None).unwrap();
        assert_eq!((from.id, to.id), (1, 2));
        let d = diff(
            &store.load_run(ZONE, from).unwrap(),
            &store.load_run(ZONE, to).unwrap(),
            &[],
        );
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].added, ["192.0.2.99"]);
        assert_eq!(d.changes[0].removed, ["192.0.2.10"]);
    }

    #[test]
    fn picking_runs() {
        let mut store = Store::open_in_memory().unwrap();
        assert!(matches!(
            store.pick_runs(ZONE, None, None),
            Err(StoreError::UnknownZone { .. })
        ));
        save(&mut store, &obs_with("192.0.2.10", 100));
        assert!(matches!(
            store.pick_runs(ZONE, None, None),
            Err(StoreError::NotEnoughRuns { runs: 1, .. })
        ));
        save(&mut store, &obs_with("192.0.2.10", 200));
        save(&mut store, &obs_with("192.0.2.10", 300));
        let ids = |r: (RunRef, RunRef)| (r.0.id, r.1.id);
        assert_eq!(ids(store.pick_runs(ZONE, None, None).unwrap()), (2, 3));
        assert_eq!(ids(store.pick_runs(ZONE, None, Some(2)).unwrap()), (1, 2));
        assert_eq!(
            ids(store.pick_runs(ZONE, Some(1), Some(3)).unwrap()),
            (1, 3)
        );
        let err = store.pick_runs(ZONE, Some(9), None).unwrap_err();
        assert!(err.to_string().contains("#1, #2, #3"), "{err}");
    }

    #[test]
    fn findings_open_resolve_and_reopen() {
        let mut store = Store::open_in_memory().unwrap();
        let clean = obs_with("192.0.2.10", 100);
        let mut broken = obs_with("192.0.2.10", 200);
        set_serial(&mut broken, V4_B, 43);
        let print = fingerprint(&run_all(&broken)[0]);
        let state = |store: &Store| {
            store
                .finding_states(ZONE)
                .unwrap()
                .into_iter()
                .find(|(p, _)| *p == print)
                .map(|(_, s)| s)
        };

        save(&mut store, &clean);
        assert_eq!(state(&store), None);
        save(&mut store, &broken);
        assert_eq!(state(&store).as_deref(), Some("open"));
        // The serial moves on but still differs: the same finding, still open.
        set_serial(&mut broken, V4_B, 44);
        broken.started_at_unix = 300;
        save(&mut store, &broken);
        assert_eq!(state(&store).as_deref(), Some("open"));
        assert_eq!(store.count("findings"), 1);
        let mut later = clean.clone();
        later.started_at_unix = 400;
        save(&mut store, &later);
        assert_eq!(state(&store).as_deref(), Some("resolved"));
        broken.started_at_unix = 500;
        save(&mut store, &broken);
        assert_eq!(state(&store).as_deref(), Some("open"));
        assert_eq!(store.count("findings"), 1);

        // The diff between a clean and a broken run shows the finding opening.
        let runs = store.runs(ZONE).unwrap();
        let d = diff(
            &store.load_run(ZONE, runs[3]).unwrap(),
            &store.load_run(ZONE, runs[4]).unwrap(),
            &[],
        );
        assert_eq!(d.findings_opened.len(), 1);
        assert_eq!(d.findings_opened[0].check_id, "CON-01");

        let zones = store.zones().unwrap();
        assert_eq!(zones.len(), 1);
        assert_eq!(
            (zones[0].runs, zones[0].names, zones[0].open_findings),
            (5, 2, 1)
        );
    }

    #[test]
    fn an_older_database_is_upgraded_in_place() {
        // Build a version 1 database by hand, with one run in it.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&format!("{SCHEMA} PRAGMA user_version = 1;"))
            .unwrap();
        conn.execute_batch(
            "INSERT INTO zones (name, created_at) VALUES ('example.test.', 1);
             INSERT INTO runs (zone_id, started_at, finished_at, trigger, level, status, queries,
                               vantage_ipv4, vantage_ipv6, delegation_json, ns_hosts_json, probes_json)
             VALUES (1, 50, 51, 'cli', 'light', 'ok', 3, 1, 0, '[]', '[]', '[]');",
        )
        .unwrap();
        let mut store = Store::init(conn).unwrap();
        let version: i64 = store
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        // The old run is still there, and new runs can be added after it.
        assert_eq!(store.runs(ZONE).unwrap().len(), 1);
        save(&mut store, &obs_with("192.0.2.10", 100));
        assert_eq!(store.runs(ZONE).unwrap().len(), 2);

        // A database from the future is refused, not guessed at.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA user_version = 99;").unwrap();
        assert!(matches!(
            Store::init(conn),
            Err(StoreError::NewerSchema { found: 99, .. })
        ));
    }

    #[test]
    fn names_can_be_forgotten() {
        let mut store = Store::open_in_memory().unwrap();
        save(&mut store, &obs_with("192.0.2.10", 100));
        assert!(store.forget_name(ZONE, "mail.example.test.").unwrap());
        assert!(!store.forget_name(ZONE, "mail.example.test.").unwrap());
        assert_eq!(store.names(ZONE).unwrap(), ["www.example.test."]);
    }

    #[test]
    fn a_file_store_reopens() {
        let path =
            std::env::temp_dir().join(format!("zoneblick-test-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut store = Store::open(&path).unwrap();
            save(&mut store, &obs_with("192.0.2.10", 100));
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.runs(ZONE).unwrap().len(), 1);
        drop(store);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    fn a_baseline_is_pinned_shown_and_cleared() {
        let mut store = Store::open_in_memory().unwrap();
        let first = save(&mut store, &obs_with("192.0.2.10", 100));
        let second = save(&mut store, &obs_with("192.0.2.20", 200));
        assert_eq!(store.baseline(ZONE).unwrap(), None);
        // The latest run by default, a named run when asked.
        assert_eq!(store.pin_baseline(ZONE, None, 300).unwrap().id, second);
        assert_eq!(
            store.pin_baseline(ZONE, Some(first), 300).unwrap().id,
            first
        );
        assert_eq!(store.baseline(ZONE).unwrap().unwrap().id, first);
        assert!(matches!(
            store.pin_baseline(ZONE, Some(99), 300),
            Err(StoreError::UnknownRun { run: 99, .. })
        ));
        assert!(store.clear_baseline(ZONE).unwrap());
        assert!(!store.clear_baseline(ZONE).unwrap());
    }

    #[test]
    fn pruning_thins_old_runs_and_keeps_what_matters() {
        const DAY: u64 = 86_400;
        let now = 1000 * DAY;
        let mut store = Store::open_in_memory().unwrap();
        let mut at = |days_ago: u64, offset: u64, www: &str| {
            save(&mut store, &obs_with(www, now - days_ago * DAY + offset))
        };
        let ancient = at(500, 0, "192.0.2.1");
        let pinned = at(400, 0, "192.0.2.2");
        let old_morning = at(60, 100, "192.0.2.3");
        let old_evening = at(60, 5000, "192.0.2.4");
        let recent_a = at(2, 100, "192.0.2.5");
        let recent_b = at(2, 200, "192.0.2.5");
        store.pin_baseline(ZONE, Some(pinned), now).unwrap();
        let sets_before = store.count("rrsets");

        let pruned = store.prune(now, 30 * DAY, 365 * DAY).unwrap();
        assert_eq!(pruned.runs, 2);
        let left: Vec<i64> = store.runs(ZONE).unwrap().iter().map(|r| r.id).collect();
        // Gone: the run past a year, and the earlier of two on one old day.
        assert_eq!(left, [pinned, old_evening, recent_a, recent_b]);
        assert!(!left.contains(&ancient) && !left.contains(&old_morning));
        assert_eq!(
            store.count("rrsets"),
            sets_before - pruned.record_sets as i64
        );
        assert_eq!(pruned.record_sets, 2);
        // What is left still loads and compares.
        let runs = store.runs(ZONE).unwrap();
        assert!(store.diff(ZONE, runs[0], runs[3], &[]).unwrap().changed);
        // A second pass finds nothing more.
        assert_eq!(
            store.prune(now, 30 * DAY, 365 * DAY).unwrap(),
            Pruned::default()
        );
        // Even with nothing allowed to stay, the latest run and the baseline do.
        store.prune(now, 1, 1).unwrap();
        let left: Vec<i64> = store.runs(ZONE).unwrap().iter().map(|r| r.id).collect();
        assert_eq!(left, [pinned, recent_b]);
    }

    #[test]
    fn rotation_of_a_volatile_name_is_not_a_change() {
        let mut store = Store::open_in_memory().unwrap();
        let mut ids = Vec::new();
        for (i, www) in [
            "192.0.2.10",
            "192.0.2.11",
            "192.0.2.12",
            "192.0.2.10",
            "192.0.2.11",
        ]
        .iter()
        .enumerate()
        {
            ids.push(save(&mut store, &obs_with(www, 100 * (i as u64 + 1))));
        }
        let runs = store.runs(ZONE).unwrap();
        // The first three flaps are ordinary changes.
        for step in 0..3 {
            let d = store.diff(ZONE, runs[step], runs[step + 1], &[]).unwrap();
            assert!(d.changed && !d.changes[0].rotation, "step {step}");
        }
        // The fourth, back to an address seen before, is rotation.
        let d = store.diff(ZONE, runs[3], runs[4], &[]).unwrap();
        assert!(!d.changed);
        assert!(d.changes[0].rotation);
        assert_eq!((d.summary.modified, d.summary.rotations), (0, 1));

        // An address never seen before still counts, even a neighbouring one.
        save(&mut store, &obs_with("192.0.2.13", 600));
        let runs = store.runs(ZONE).unwrap();
        let d = store.diff(ZONE, runs[4], runs[5], &[]).unwrap();
        assert!(d.changed && !d.changes[0].rotation);
        assert_eq!(d.summary.modified, 1);
    }

    #[test]
    fn discovered_names_keep_their_source() {
        let mut store = Store::open_in_memory().unwrap();
        save(&mut store, &obs_with("192.0.2.10", 100));
        store
            .set_name_source(ZONE, &["www.example.test.".to_string()], "ct")
            .unwrap();
        let source: String = store
            .conn
            .query_row(
                "SELECT source FROM names WHERE fqdn = 'www.example.test.'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(source, "ct");
        // Discovered names are checked like any other, and can be forgotten.
        assert_eq!(store.names(ZONE).unwrap().len(), 2);
        assert!(store.forget_name(ZONE, "www.example.test.").unwrap());
    }

    #[test]
    fn a_muted_finding_stays_muted_and_out_of_diffs() {
        let mut store = Store::open_in_memory().unwrap();
        // A lame server gives a finding in every run.
        let broken = |at: u64| {
            let mut obs = obs_with("192.0.2.10", at);
            set_child_ns(&mut obs, &["ns1.example.test.", "ns3.example.test."]);
            obs
        };
        save(&mut store, &obs_with("192.0.2.10", 100));
        save(&mut store, &broken(200));
        let rows = store.finding_rows(Some(ZONE), Some("open")).unwrap();
        assert_eq!(rows.len(), 1);
        let print = rows[0].fingerprint.clone();
        let runs = store.runs(ZONE).unwrap();
        assert_eq!(
            store
                .diff(ZONE, runs[0], runs[1], &[])
                .unwrap()
                .findings_opened
                .len(),
            1
        );

        assert!(matches!(
            store.set_muted(ZONE, "zzzz", true),
            Err(StoreError::UnknownFinding { .. })
        ));
        let row = store.set_muted(ZONE, &print[..8], true).unwrap();
        assert_eq!(row.state, "muted");
        assert_eq!(store.muted(ZONE).unwrap().len(), 1);
        // Muted: no longer a finding that opened, and the diff is quiet.
        let d = store.diff(ZONE, runs[0], runs[1], &[]).unwrap();
        assert!(d.findings_opened.is_empty() && !d.changed);
        // Seen again in a later run, it stays muted.
        save(&mut store, &broken(300));
        assert_eq!(store.muted(ZONE).unwrap().len(), 1);
        assert_eq!(store.zones().unwrap()[0].open_findings, 0);
        // Unmuted while still seen, it is open again; once gone, resolved.
        assert_eq!(store.set_muted(ZONE, &print, false).unwrap().state, "open");
        store.set_muted(ZONE, &print, true).unwrap();
        save(&mut store, &obs_with("192.0.2.10", 400));
        assert_eq!(
            store.set_muted(ZONE, &print, false).unwrap().state,
            "resolved"
        );
    }

    #[test]
    fn zones_are_added_and_removed() {
        let mut store = Store::open_in_memory().unwrap();
        assert!(store.add_zone("other.test.", 1).unwrap());
        assert!(!store.add_zone("other.test.", 2).unwrap());
        let names = vec!["www.other.test.".to_string(), "other.test.".to_string()];
        assert_eq!(
            store.add_names("other.test.", &names, "seed", 0).unwrap(),
            1
        );
        assert_eq!(
            store.add_names("other.test.", &names, "seed", 0).unwrap(),
            0
        );
        assert_eq!(store.names("other.test.").unwrap(), ["www.other.test."]);

        save(&mut store, &obs_with("192.0.2.10", 100));
        save(&mut store, &obs_with("192.0.2.20", 200));
        store.pin_baseline(ZONE, None, 300).unwrap();
        assert_eq!(store.remove_zone(ZONE).unwrap(), 2);
        for table in [
            "runs",
            "observations",
            "rrsets",
            "findings",
            "run_findings",
            "baselines",
        ] {
            assert_eq!(store.count(table), 0, "{table}");
        }
        // The other zone is untouched.
        assert_eq!(store.zones().unwrap().len(), 1);
        assert!(matches!(
            store.remove_zone(ZONE),
            Err(StoreError::UnknownZone { .. })
        ));
    }

    #[test]
    fn a_deep_finding_survives_light_runs() {
        use crate::observe::{DeepObservation, ProbeAnswer, ServerDeep};
        let deep_obs = |at: u64, recursion: bool| {
            let mut obs = obs_with("192.0.2.10", at);
            let answer = |rcode: &str| ProbeAnswer {
                rcode: Some(rcode.to_string()),
                opt_present: true,
                error: None,
            };
            obs.deep = Some(DeepObservation {
                servers: vec![ServerDeep {
                    ns_name: "ns1.example.test.".to_string(),
                    address: ip(V4_A),
                    edns_version: answer("BADVERS"),
                    edns_option: answer("NOERROR"),
                    recursion_available: Some(recursion),
                    case_preserved: Some(true),
                    axfr_allowed: Some(false),
                    nsec3param: Some(vec![]),
                    cds: Some(vec![]),
                    cdnskey: Some(vec![]),
                    denial: None,
                }],
                mname: None,
                rname_domain: None,
                rname_mx: None,
                rname_address: None,
                previous_dnskeys: None,
                origins: Vec::new(),
                chain: Vec::new(),
                record_signatures: Vec::new(),
                mail_tls: Vec::new(),
                registration: None,
            });
            obs
        };
        let state = |store: &Store| -> String {
            store
                .finding_rows(Some(ZONE), None)
                .unwrap()
                .into_iter()
                .find(|f| f.check_id == "NSB-03")
                .map(|f| f.state)
                .unwrap_or_default()
        };
        let mut store = Store::open_in_memory().unwrap();
        save(&mut store, &deep_obs(100, true));
        assert_eq!(state(&store), "open");
        // Two light runs: the deep finding stays open, and no diff calls it resolved.
        save(&mut store, &obs_with("192.0.2.10", 200));
        save(&mut store, &obs_with("192.0.2.10", 300));
        assert_eq!(state(&store), "open");
        let runs = store.runs(ZONE).unwrap();
        for pair in runs.windows(2) {
            let d = store.diff(ZONE, pair[0], pair[1], &[]).unwrap();
            assert!(d.findings_resolved.is_empty() && d.findings_opened.is_empty());
        }
        let levels: Vec<String> = store
            .conn
            .prepare("SELECT level FROM runs ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(levels, ["deep", "light", "light"]);
        // A deep run that no longer sees it resolves it.
        save(&mut store, &deep_obs(400, false));
        assert_eq!(state(&store), "resolved");
        let runs = store.runs(ZONE).unwrap();
        let d = store.diff(ZONE, runs[2], runs[3], &[]).unwrap();
        assert_eq!(d.findings_resolved.len(), 1);
    }
}
