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
use crate::diff::{RunData, RunRef, StoredFinding};
use crate::observe::{
    DnssecObservation, NsHost, QType, RecordAnswer, RecordObservation, RecordOutcome, ReferralStep,
    ServerProbe, Transport, Vantage, ZoneObservation,
};

/// Version of the database layout, kept in SQLite's `user_version`.
const SCHEMA_VERSION: i64 = 3;

/// Changes to the layout since version 1, in order. Entry `i` takes a
/// database from version `i + 1` to `i + 2`. A new database is created at
/// version 1 and then walks the same steps, so both paths are the same code.
const MIGRATIONS: &[&str] = &[
    // 2: each run keeps the DNSSEC data it observed.
    "ALTER TABLE runs ADD COLUMN dnssec_json TEXT;",
    // 3: and the mail and policy data.
    "ALTER TABLE runs ADD COLUMN policy_json TEXT;",
];

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
    /// `open` or `resolved`.
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
        let conn = Connection::open(path)?;
        // WAL keeps readers and the writer out of each other's way.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
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

    /// The names remembered for a zone, besides the apex. Empty for a zone
    /// that has never been stored.
    pub fn names(&self, zone: &str) -> Result<Vec<String>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT n.fqdn FROM names n JOIN zones z ON z.id = n.zone_id
             WHERE z.name = ?1 AND n.source = 'seed' ORDER BY n.fqdn",
        )?;
        let rows = stmt.query_map([zone], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Stop checking a name in later runs. Its history stays.
    pub fn forget_name(&self, zone: &str, name: &str) -> Result<bool, StoreError> {
        let n = self.conn.execute(
            "DELETE FROM names WHERE fqdn = ?2 AND source = 'seed'
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
             VALUES (?1, ?2, ?3, ?4, 'light', 'ok', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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
                     last_seen_run = ?8, state = 'open'",
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
                    (SELECT COUNT(*) FROM names n WHERE n.zone_id = z.id AND n.source = 'seed'),
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
}
