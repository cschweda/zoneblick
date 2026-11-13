//! The diff engine: what changed between two stored runs of a zone.
//!
//! Pure functions over two [`RunData`] values; no I/O. Noise control here:
//!
//! - Record data is already canonical (sorted, lowercase names), and TTLs
//!   are kept apart from the data.
//! - Runs are compared as *pools*: the union of what all authoritative
//!   servers returned for a name and type. Servers handing out different
//!   rotations of the same pool is not drift.
//! - Names matching an ignore pattern are left out.
//! - A SOA whose only difference is the serial is reported on one line, not
//!   as a record change.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::checks::Severity;
use crate::observe::{Glue, QType, RecordObservation};

/// Version of the diff JSON document.
pub const SCHEMA_VERSION: u32 = 1;

/// A stored run, as named in a diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRef {
    pub id: i64,
    pub started_at_unix: u64,
}

/// A finding as stored with a run.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct StoredFinding {
    pub severity: Severity,
    pub check_id: String,
    pub name: String,
    pub summary: String,
    /// Stable identity of the finding across runs.
    pub fingerprint: String,
}

/// What a stored run holds that a diff needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunData {
    pub run: RunRef,
    pub zone: String,
    /// The parent's NS set for the zone; `None` when no referral was seen.
    pub parent_ns: Option<Vec<String>>,
    pub glue: Vec<Glue>,
    pub records: Vec<RecordObservation>,
    pub findings: Vec<StoredFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
    /// Same records, different TTL.
    Ttl,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Added => "added",
            ChangeKind::Removed => "removed",
            ChangeKind::Modified => "modified",
            ChangeKind::Ttl => "ttl",
        }
    }
}

/// What one server served before and after. `None` means the server gave no
/// authoritative answer in that run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerChange {
    pub ns_name: String,
    pub address: IpAddr,
    pub before: Option<Vec<String>>,
    pub after: Option<Vec<String>>,
}

/// A change to one record set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordChange {
    pub name: String,
    pub rtype: QType,
    pub kind: ChangeKind,
    /// Record data in the newer run's pool but not the older one's.
    pub added: Vec<String>,
    /// Record data in the older run's pool but not the newer one's.
    pub removed: Vec<String>,
    pub ttl_before: Vec<u32>,
    pub ttl_after: Vec<u32>,
    /// Servers whose own answer changed.
    pub servers: Vec<ServerChange>,
    /// True when every server observed in both runs changed the same way.
    pub all_servers: bool,
    /// True when this is an address rotation of a name known to rotate:
    /// reported, but not counted as a change.
    #[serde(default, skip_serializing_if = "is_false")]
    pub rotation: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SerialChange {
    pub before: Vec<u32>,
    pub after: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct DelegationChange {
    pub ns_added: Vec<String>,
    pub ns_removed: Vec<String>,
    pub glue_added: Vec<Glue>,
    pub glue_removed: Vec<Glue>,
}

impl DelegationChange {
    fn is_empty(&self) -> bool {
        self.ns_added.is_empty()
            && self.ns_removed.is_empty()
            && self.glue_added.is_empty()
            && self.glue_removed.is_empty()
    }
}

/// A record set that could not be compared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotCompared {
    pub name: String,
    pub rtype: QType,
    /// `not_in_older_run`, `not_in_newer_run` or `ignored`.
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct DiffSummary {
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub ttl: usize,
    pub findings_opened: usize,
    pub findings_resolved: usize,
    /// Address rotations of volatile names; not counted above.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rotations: usize,
}

/// The result of comparing two runs. This is the `diff --json` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffReport {
    pub schema_version: u32,
    pub zone: String,
    pub from: RunRef,
    pub to: RunRef,
    pub changes: Vec<RecordChange>,
    /// Set when the SOA serial moved.
    pub soa_serial: Option<SerialChange>,
    /// Set when the parent's NS set or glue changed.
    pub delegation: Option<DelegationChange>,
    pub findings_opened: Vec<StoredFinding>,
    pub findings_resolved: Vec<StoredFinding>,
    pub not_compared: Vec<NotCompared>,
    pub summary: DiffSummary,
    /// True when anything other than the SOA serial changed.
    pub changed: bool,
}

impl DiffReport {
    /// Leave out findings with these fingerprints (muted ones), and count
    /// again.
    pub fn drop_findings(&mut self, fingerprints: &BTreeSet<String>) {
        if fingerprints.is_empty() {
            return;
        }
        self.findings_opened
            .retain(|f| !fingerprints.contains(&f.fingerprint));
        self.findings_resolved
            .retain(|f| !fingerprints.contains(&f.fingerprint));
        self.summary.findings_opened = self.findings_opened.len();
        self.summary.findings_resolved = self.findings_resolved.len();
        self.changed = self.changes.iter().any(|c| !c.rotation)
            || self.delegation.is_some()
            || !self.findings_opened.is_empty()
            || !self.findings_resolved.is_empty();
    }
}

/// One run's view of one record set.
#[derive(Default)]
struct View {
    /// Per server: the record data it served.
    servers: BTreeMap<(String, IpAddr), Vec<String>>,
    pool: BTreeSet<String>,
    ttls: BTreeSet<u32>,
}

type Key = (String, QType);

fn views(run: &RunData) -> BTreeMap<Key, View> {
    let mut map: BTreeMap<Key, View> = BTreeMap::new();
    for rec in &run.records {
        let Some(answer) = rec.outcome.answer() else {
            continue;
        };
        // Only authoritative answers count; NXDOMAIN is an empty set.
        if !answer.authoritative || !matches!(answer.rcode.as_str(), "NOERROR" | "NXDOMAIN") {
            continue;
        }
        let view = map.entry((rec.name.clone(), rec.qtype)).or_default();
        view.servers
            .insert((rec.ns_name.clone(), rec.address), answer.rdata.clone());
        view.pool.extend(answer.rdata.iter().cloned());
        if !answer.rdata.is_empty() {
            view.ttls.extend(answer.ttl);
        }
    }
    map
}

/// Split SOA text into (serial, the rest).
fn split_soa(text: &str) -> Option<(u32, String)> {
    let parts: Vec<&str> = text.split(' ').collect();
    if parts.len() != 7 {
        return None;
    }
    let serial = parts[2].parse().ok()?;
    let rest = [&parts[..2], &parts[3..]].concat().join(" ");
    Some((serial, rest))
}

/// Match a name against an ignore pattern. `*` matches any run of
/// characters; the pattern must match the whole name, written without the
/// trailing dot. `_acme-challenge.*` matches `_acme-challenge.example.org`.
pub fn matches_pattern(pattern: &str, name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let pattern = pattern
        .strip_suffix('.')
        .unwrap_or(pattern)
        .to_ascii_lowercase();
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return name == pattern;
    }
    let mut rest = name.as_str();
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            let Some(r) = rest.strip_prefix(part) else {
                return false;
            };
            rest = r;
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            let Some(pos) = rest.find(part) else {
                return false;
            };
            rest = &rest[pos + part.len()..];
        }
    }
    true
}

/// A name is volatile when its addresses changed in each of this many
/// consecutive run-to-run steps.
pub const VOLATILE_AFTER: usize = 3;

/// What earlier runs say about names whose addresses rotate, as those
/// behind a CDN or a load balancer do.
#[derive(Debug, Default, Clone)]
pub struct Volatility {
    /// Per volatile record set: every address seen in the earlier runs.
    pools: BTreeMap<Key, BTreeSet<String>>,
}

impl Volatility {
    /// Learn from consecutive runs, oldest first, ending with the older run
    /// of the diff. An A or AAAA set is volatile when it was present and
    /// different in each of the last [`VOLATILE_AFTER`] steps.
    pub fn learn(history: &[RunData]) -> Self {
        let mut out = Volatility::default();
        if history.len() <= VOLATILE_AFTER {
            return out;
        }
        let all: Vec<BTreeMap<Key, View>> = history.iter().map(views).collect();
        let recent = &all[all.len() - VOLATILE_AFTER - 1..];
        for key in recent[0].keys() {
            if !matches!(key.1, QType::A | QType::Aaaa) {
                continue;
            }
            let pools: Option<Vec<&BTreeSet<String>>> = recent
                .iter()
                .map(|v| v.get(key).map(|view| &view.pool).filter(|p| !p.is_empty()))
                .collect();
            let Some(pools) = pools else { continue };
            if pools.windows(2).all(|w| w[0] != w[1]) {
                let seen = all
                    .iter()
                    .filter_map(|v| v.get(key))
                    .flat_map(|view| view.pool.iter().cloned())
                    .collect();
                out.pools.insert(key.clone(), seen);
            }
        }
        out
    }

    /// The volatile record sets, as (name, type).
    pub fn names(&self) -> impl Iterator<Item = &(String, QType)> {
        self.pools.keys()
    }

    /// True when a change to `key` is only rotation: the set is volatile
    /// and every address now served was served in an earlier run. Nearness
    /// does not count: an address that was never seen is a change, even in
    /// the same network, because a neighbouring address can belong to
    /// someone else.
    fn is_rotation(&self, key: &Key, added: &[String]) -> bool {
        self.pools
            .get(key)
            .is_some_and(|pool| added.iter().all(|a| pool.contains(a)))
    }
}

/// Compare two runs of the same zone. `from` is the older one.
pub fn diff(from: &RunData, to: &RunData, ignore: &[String]) -> DiffReport {
    diff_with(from, to, ignore, &Volatility::default())
}

/// [`diff`], with what earlier runs taught about rotating names.
pub fn diff_with(
    from: &RunData,
    to: &RunData,
    ignore: &[String],
    volatility: &Volatility,
) -> DiffReport {
    let before = views(from);
    let after = views(to);
    let keys: BTreeSet<&Key> = before.keys().chain(after.keys()).collect();

    let mut changes = Vec::new();
    let mut not_compared = Vec::new();
    let mut soa_serial = None;

    for key in keys {
        let (name, rtype) = key;
        let skip = |reason: &str| NotCompared {
            name: name.clone(),
            rtype: *rtype,
            reason: reason.to_string(),
        };
        let (b, a) = match (before.get(key), after.get(key)) {
            (Some(b), Some(a)) => (b, a),
            (None, _) => {
                not_compared.push(skip("not_in_older_run"));
                continue;
            }
            (_, None) => {
                not_compared.push(skip("not_in_newer_run"));
                continue;
            }
        };
        if b.pool == a.pool && b.ttls == a.ttls {
            continue;
        }
        if ignore.iter().any(|p| matches_pattern(p, name)) {
            not_compared.push(skip("ignored"));
            continue;
        }

        if *rtype == QType::Soa {
            let split = |pool: &BTreeSet<String>| -> Option<(Vec<u32>, BTreeSet<String>)> {
                let parts: Option<Vec<(u32, String)>> = pool.iter().map(|t| split_soa(t)).collect();
                let parts = parts?;
                let serials: BTreeSet<u32> = parts.iter().map(|p| p.0).collect();
                Some((
                    serials.into_iter().collect(),
                    parts.into_iter().map(|p| p.1).collect(),
                ))
            };
            if let (Some((sb, rb)), Some((sa, ra))) = (split(&b.pool), split(&a.pool)) {
                if sb != sa {
                    soa_serial = Some(SerialChange {
                        before: sb,
                        after: sa,
                    });
                }
                if rb == ra {
                    continue;
                }
            }
        }

        let kind = if b.pool == a.pool {
            ChangeKind::Ttl
        } else if b.pool.is_empty() {
            ChangeKind::Added
        } else if a.pool.is_empty() {
            ChangeKind::Removed
        } else {
            ChangeKind::Modified
        };

        let server_keys: BTreeSet<&(String, IpAddr)> =
            b.servers.keys().chain(a.servers.keys()).collect();
        let mut servers = Vec::new();
        let mut in_both = 0;
        let mut changed_in_both = 0;
        for sk in server_keys {
            let (sb, sa) = (b.servers.get(sk), a.servers.get(sk));
            if sb.is_some() && sa.is_some() {
                in_both += 1;
            }
            if sb == sa {
                continue;
            }
            if sb.is_some() && sa.is_some() {
                changed_in_both += 1;
            }
            servers.push(ServerChange {
                ns_name: sk.0.clone(),
                address: sk.1,
                before: sb.cloned(),
                after: sa.cloned(),
            });
        }
        let uniform = |list: &[ServerChange]| {
            list.windows(2)
                .all(|w| w[0].before == w[1].before && w[0].after == w[1].after)
        };
        let all_servers = kind == ChangeKind::Ttl
            || (in_both > 0
                && changed_in_both == in_both
                && servers.len() == in_both
                && uniform(&servers));

        let added: Vec<String> = a.pool.difference(&b.pool).cloned().collect();
        let rotation = kind == ChangeKind::Modified && volatility.is_rotation(key, &added);
        changes.push(RecordChange {
            name: name.clone(),
            rtype: *rtype,
            kind,
            rotation,
            added,
            removed: b.pool.difference(&a.pool).cloned().collect(),
            ttl_before: b.ttls.iter().copied().collect(),
            ttl_after: a.ttls.iter().copied().collect(),
            servers,
            all_servers,
        });
    }

    let delegation = match (&from.parent_ns, &to.parent_ns) {
        (Some(b), Some(a)) => {
            let (b, a): (BTreeSet<&String>, BTreeSet<&String>) =
                (b.iter().collect(), a.iter().collect());
            let (gb, ga): (BTreeSet<&Glue>, BTreeSet<&Glue>) =
                (from.glue.iter().collect(), to.glue.iter().collect());
            let change = DelegationChange {
                ns_added: a.difference(&b).map(|s| s.to_string()).collect(),
                ns_removed: b.difference(&a).map(|s| s.to_string()).collect(),
                glue_added: ga.difference(&gb).map(|g| (*g).clone()).collect(),
                glue_removed: gb.difference(&ga).map(|g| (*g).clone()).collect(),
            };
            (!change.is_empty()).then_some(change)
        }
        _ => None,
    };

    let prints = |run: &RunData| -> BTreeSet<String> {
        run.findings.iter().map(|f| f.fingerprint.clone()).collect()
    };
    let (fb, fa) = (prints(from), prints(to));
    let mut findings_opened: Vec<StoredFinding> = to
        .findings
        .iter()
        .filter(|f| !fb.contains(&f.fingerprint))
        .cloned()
        .collect();
    let mut findings_resolved: Vec<StoredFinding> = from
        .findings
        .iter()
        .filter(|f| !fa.contains(&f.fingerprint))
        .cloned()
        .collect();
    findings_opened.sort();
    findings_resolved.sort();

    let count = |k: ChangeKind| {
        changes
            .iter()
            .filter(|c| c.kind == k && !c.rotation)
            .count()
    };
    let summary = DiffSummary {
        added: count(ChangeKind::Added),
        removed: count(ChangeKind::Removed),
        modified: count(ChangeKind::Modified),
        ttl: count(ChangeKind::Ttl),
        findings_opened: findings_opened.len(),
        findings_resolved: findings_resolved.len(),
        rotations: changes.iter().filter(|c| c.rotation).count(),
    };
    let changed = changes.iter().any(|c| !c.rotation)
        || delegation.is_some()
        || !findings_opened.is_empty()
        || !findings_resolved.is_empty();

    DiffReport {
        schema_version: SCHEMA_VERSION,
        zone: to.zone.clone(),
        from: from.run,
        to: to.run,
        changes,
        soa_serial,
        delegation,
        findings_opened,
        findings_resolved,
        not_compared,
        summary,
        changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{RecordAnswer, RecordOutcome, Transport};

    const ZONE: &str = "example.test.";
    const S1: &str = "192.0.2.1";
    const S2: &str = "198.51.100.1";

    fn rec(name: &str, qtype: QType, server: &str, rdata: &[&str], ttl: u32) -> RecordObservation {
        RecordObservation {
            name: name.to_string(),
            qtype,
            ns_name: format!("ns-{server}."),
            address: server.parse().unwrap(),
            transport: Transport::Udp,
            outcome: RecordOutcome::Answer(RecordAnswer {
                rcode: "NOERROR".to_string(),
                authoritative: true,
                ttl: (!rdata.is_empty()).then_some(ttl),
                rdata: rdata.iter().map(|s| s.to_string()).collect(),
            }),
        }
    }

    fn both(name: &str, qtype: QType, rdata: &[&str]) -> Vec<RecordObservation> {
        vec![
            rec(name, qtype, S1, rdata, 300),
            rec(name, qtype, S2, rdata, 300),
        ]
    }

    fn run(id: i64, records: Vec<RecordObservation>) -> RunData {
        RunData {
            run: RunRef {
                id,
                started_at_unix: 1000 + id as u64,
            },
            zone: ZONE.to_string(),
            parent_ns: Some(vec!["ns1.example.test.".to_string()]),
            glue: vec![],
            records,
            findings: vec![],
        }
    }

    #[test]
    fn identical_runs_have_no_changes() {
        let a = run(1, both("www.example.test.", QType::A, &["192.0.2.10"]));
        let b = run(2, both("www.example.test.", QType::A, &["192.0.2.10"]));
        let d = diff(&a, &b, &[]);
        assert!(!d.changed);
        assert!(d.changes.is_empty());
    }

    #[test]
    fn modified_on_all_servers() {
        let a = run(1, both("www.example.test.", QType::A, &["192.0.2.10"]));
        let b = run(2, both("www.example.test.", QType::A, &["192.0.2.99"]));
        let d = diff(&a, &b, &[]);
        assert!(d.changed);
        assert_eq!(d.changes.len(), 1);
        let c = &d.changes[0];
        assert_eq!(c.kind, ChangeKind::Modified);
        assert_eq!(c.added, ["192.0.2.99"]);
        assert_eq!(c.removed, ["192.0.2.10"]);
        assert!(c.all_servers);
        assert_eq!(c.servers.len(), 2);
        assert_eq!(d.summary.modified, 1);
    }

    #[test]
    fn change_on_one_server_names_that_server() {
        let a = run(1, both("www.example.test.", QType::A, &["192.0.2.10"]));
        let b = run(
            2,
            vec![
                rec("www.example.test.", QType::A, S1, &["192.0.2.10"], 300),
                rec("www.example.test.", QType::A, S2, &["192.0.2.99"], 300),
            ],
        );
        let d = diff(&a, &b, &[]);
        let c = &d.changes[0];
        assert_eq!(c.kind, ChangeKind::Modified);
        assert!(!c.all_servers);
        assert_eq!(c.servers.len(), 1);
        assert_eq!(c.servers[0].address.to_string(), S2);
        assert_eq!(c.added, ["192.0.2.99"]);
        assert!(c.removed.is_empty());
    }

    #[test]
    fn rotation_of_the_same_pool_is_not_drift() {
        let name = "cdn.example.test.";
        let a = run(
            1,
            vec![
                rec(name, QType::A, S1, &["192.0.2.1", "192.0.2.2"], 60),
                rec(name, QType::A, S2, &["192.0.2.3"], 60),
            ],
        );
        let b = run(
            2,
            vec![
                rec(name, QType::A, S1, &["192.0.2.3"], 60),
                rec(name, QType::A, S2, &["192.0.2.1", "192.0.2.2"], 60),
            ],
        );
        assert!(!diff(&a, &b, &[]).changed);
    }

    #[test]
    fn added_and_removed() {
        let a = run(
            1,
            [
                both("new.example.test.", QType::A, &[]),
                both("old.example.test.", QType::Cname, &["target.example.net."]),
            ]
            .concat(),
        );
        let b = run(
            2,
            [
                both("new.example.test.", QType::A, &["192.0.2.5"]),
                both("old.example.test.", QType::Cname, &[]),
            ]
            .concat(),
        );
        let d = diff(&a, &b, &[]);
        let kinds: Vec<(&str, ChangeKind)> = d
            .changes
            .iter()
            .map(|c| (c.name.as_str(), c.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                ("new.example.test.", ChangeKind::Added),
                ("old.example.test.", ChangeKind::Removed)
            ]
        );
        assert_eq!((d.summary.added, d.summary.removed), (1, 1));
    }

    #[test]
    fn ttl_only_change() {
        let name = "www.example.test.";
        let a = run(1, both(name, QType::A, &["192.0.2.10"]));
        let b = run(
            2,
            vec![
                rec(name, QType::A, S1, &["192.0.2.10"], 3600),
                rec(name, QType::A, S2, &["192.0.2.10"], 3600),
            ],
        );
        let d = diff(&a, &b, &[]);
        assert_eq!(d.changes[0].kind, ChangeKind::Ttl);
        assert_eq!(d.changes[0].ttl_before, [300]);
        assert_eq!(d.changes[0].ttl_after, [3600]);
        assert!(d.changes[0].added.is_empty());
    }

    #[test]
    fn soa_serial_alone_is_not_a_record_change() {
        let soa = |serial: u32| {
            format!("ns1.example.test. host.example.test. {serial} 7200 3600 1209600 3600")
        };
        let a = run(1, both(ZONE, QType::Soa, &[&soa(1)]));
        let b = run(2, both(ZONE, QType::Soa, &[&soa(2)]));
        let d = diff(&a, &b, &[]);
        assert!(d.changes.is_empty());
        assert!(!d.changed);
        assert_eq!(
            d.soa_serial,
            Some(SerialChange {
                before: vec![1],
                after: vec![2]
            })
        );
        // A timer change is a real change.
        let other = "ns1.example.test. host.example.test. 2 60 3600 1209600 3600";
        let c = run(3, both(ZONE, QType::Soa, &[other]));
        let d = diff(&a, &c, &[]);
        assert_eq!(d.changes.len(), 1);
        assert!(d.soa_serial.is_some());
    }

    #[test]
    fn ignore_patterns() {
        assert!(matches_pattern(
            "_acme-challenge.*",
            "_acme-challenge.example.org."
        ));
        assert!(matches_pattern(
            "_acme-challenge.*",
            "_acme-challenge.www.example.org."
        ));
        assert!(!matches_pattern("_acme-challenge.*", "www.example.org."));
        assert!(matches_pattern("*.cdn.example.org", "a.cdn.example.org."));
        assert!(matches_pattern("www.example.org", "WWW.example.org."));
        assert!(!matches_pattern("www.example.org", "www2.example.org."));
        assert!(matches_pattern("a*c*e", "abcde"));
        assert!(!matches_pattern("a*c*e", "abde"));

        let name = "_acme-challenge.example.test.";
        let a = run(1, both(name, QType::Txt, &["\"one\""]));
        let b = run(2, both(name, QType::Txt, &["\"two\""]));
        let d = diff(&a, &b, &["_acme-challenge.*".to_string()]);
        assert!(!d.changed);
        assert_eq!(d.not_compared[0].reason, "ignored");
    }

    #[test]
    fn a_name_seen_in_only_one_run_is_not_compared() {
        let a = run(1, both("www.example.test.", QType::A, &["192.0.2.10"]));
        let mut records = both("www.example.test.", QType::A, &["192.0.2.10"]);
        records.extend(both("api.example.test.", QType::A, &["192.0.2.20"]));
        let b = run(2, records);
        let d = diff(&a, &b, &[]);
        assert!(!d.changed);
        assert_eq!(d.not_compared.len(), 1);
        assert_eq!(d.not_compared[0].reason, "not_in_older_run");
    }

    #[test]
    fn non_authoritative_answers_are_left_out() {
        let name = "www.example.test.";
        let a = run(1, both(name, QType::A, &["192.0.2.10"]));
        let mut lame = rec(name, QType::A, S2, &[], 0);
        if let RecordOutcome::Answer(ans) = &mut lame.outcome {
            ans.rcode = "REFUSED".to_string();
            ans.authoritative = false;
        }
        let b = run(2, vec![rec(name, QType::A, S1, &["192.0.2.10"], 300), lame]);
        assert!(!diff(&a, &b, &[]).changed);
    }

    #[test]
    fn delegation_and_findings() {
        let mut a = run(1, vec![]);
        let mut b = run(2, vec![]);
        b.parent_ns = Some(vec![
            "ns1.example.test.".to_string(),
            "ns2.example.test.".to_string(),
        ]);
        let finding = |fp: &str| StoredFinding {
            severity: Severity::Warning,
            check_id: "CON-01".to_string(),
            name: ZONE.to_string(),
            summary: "x".to_string(),
            fingerprint: fp.to_string(),
        };
        a.findings = vec![finding("old"), finding("same")];
        b.findings = vec![finding("same"), finding("new")];
        let d = diff(&a, &b, &[]);
        assert!(d.changed);
        assert_eq!(d.delegation.unwrap().ns_added, ["ns2.example.test."]);
        assert_eq!(d.findings_opened[0].fingerprint, "new");
        assert_eq!(d.findings_resolved[0].fingerprint, "old");
        assert_eq!(
            (d.summary.findings_opened, d.summary.findings_resolved),
            (1, 1)
        );
    }
}
