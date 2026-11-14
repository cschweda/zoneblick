//! `zoneblick plan`: look at a zone file before it is deployed.
//!
//! Two things are worked out. Mistakes in the file itself, which need no
//! network: an alias beside other records, a mail server that is an
//! alias, a target in the zone with no address. And, unless told to stay
//! offline, what deploying the file would change: each record set that
//! differs from what the nameservers serve now, and targets outside the
//! zone that do not exist.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::checks::Severity;
use crate::observe::{ZoneObservation, is_ancestor_or_equal};
use crate::zonefile::{COMPARED, ParsedZone, comparable};

/// Something wrong with the proposed zone.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Issue {
    pub severity: Severity,
    /// Stable ID, `PLN-01` and up.
    pub id: &'static str,
    pub name: String,
    pub message: String,
}

/// One record set that deploying the file would add, change or remove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    /// `add`, `change` or `remove`.
    pub kind: &'static str,
    pub name: String,
    pub rtype: String,
    /// What the nameservers serve now.
    pub live: Vec<String>,
    /// What the file says.
    pub file: Vec<String>,
}

/// The result of `zoneblick plan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub schema_version: u32,
    pub zone: String,
    pub file: String,
    pub issues: Vec<Issue>,
    /// `None` when the plan was made offline.
    pub changes: Option<Vec<Change>>,
    /// 0 no issues, 1 warnings or notices, 2 a critical issue.
    pub exit_code: u8,
}

fn issue(severity: Severity, id: &'static str, name: &str, message: String) -> Issue {
    Issue {
        severity,
        id,
        name: name.to_string(),
        message,
    }
}

/// The target name in a record value of a type that has one.
fn target_of<'a>(rtype: &str, value: &'a str) -> Option<&'a str> {
    match rtype {
        "CNAME" | "NS" => Some(value),
        "MX" => value.split_whitespace().nth(1).filter(|t| *t != "."),
        _ => None,
    }
}

/// The mistakes that show in the file alone.
pub fn lint(zone: &str, parsed: &ParsedZone) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut types_at: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (name, rtype) in parsed.seen.keys() {
        types_at.entry(name).or_default().insert(rtype);
    }
    let set = |name: &str, rtype: &str| {
        parsed
            .sets
            .iter()
            .find(|s| s.name == name && s.rtype == rtype)
    };

    for (name, types) in &types_at {
        if !types.contains("CNAME") {
            continue;
        }
        if *name == zone {
            issues.push(issue(
                Severity::Critical,
                "PLN-01",
                name,
                format!("{name} is the zone's own name and cannot be an alias (CNAME)"),
            ));
        }
        // DNSSEC records may sit beside an alias; nothing else may.
        let others: Vec<&str> = types
            .iter()
            .copied()
            .filter(|t| !matches!(*t, "CNAME" | "RRSIG" | "NSEC"))
            .collect();
        if !others.is_empty() && *name != zone {
            issues.push(issue(
                Severity::Critical,
                "PLN-02",
                name,
                format!(
                    "{name} is an alias (CNAME) and also has {} records; an alias must stand alone",
                    others.join(", ")
                ),
            ));
        }
        if set(name, "CNAME").is_some_and(|s| s.rdata.len() > 1) {
            issues.push(issue(
                Severity::Critical,
                "PLN-03",
                name,
                format!("{name} has more than one CNAME record"),
            ));
        }
    }

    for s in parsed
        .sets
        .iter()
        .filter(|s| matches!(s.rtype.as_str(), "MX" | "NS"))
    {
        for value in &s.rdata {
            let Some(target) = target_of(&s.rtype, value) else {
                continue;
            };
            if !is_ancestor_or_equal(zone, target) {
                continue;
            }
            let at = types_at.get(target);
            if at.is_some_and(|t| t.contains("CNAME")) {
                issues.push(issue(
                    Severity::Warning,
                    "PLN-04",
                    &s.name,
                    format!(
                        "the {} record of {} points at {target}, which is an alias; it must be a name with address records",
                        s.rtype, s.name
                    ),
                ));
            } else if !at.is_some_and(|t| t.contains("A") || t.contains("AAAA"))
                // Below a delegation in the file, the address is elsewhere.
                && !delegated(zone, target, &types_at)
                && !covered_by_wildcard(zone, target, &types_at)
            {
                issues.push(issue(
                    Severity::Warning,
                    "PLN-05",
                    &s.name,
                    format!(
                        "the {} record of {} points at {target}, which has no address record in the file",
                        s.rtype, s.name
                    ),
                ));
            }
        }
    }

    if let Some(txt) = set(zone, "TXT") {
        let spf = txt
            .rdata
            .iter()
            .filter(|v| {
                let v = v.to_ascii_lowercase();
                v == "v=spf1" || v.starts_with("v=spf1 ")
            })
            .count();
        if spf > 1 {
            issues.push(issue(
                Severity::Warning,
                "PLN-06",
                zone,
                format!("{zone} has {spf} SPF records; receivers reject all of them"),
            ));
        }
    }
    issues.sort();
    issues
}

/// True when `name` is at or below a name, other than the apex, that the
/// file delegates with NS records.
fn delegated(zone: &str, name: &str, types_at: &BTreeMap<&str, BTreeSet<&str>>) -> bool {
    types_at
        .iter()
        .any(|(cut, types)| *cut != zone && types.contains("NS") && is_ancestor_or_equal(cut, name))
}

fn covered_by_wildcard(zone: &str, name: &str, types_at: &BTreeMap<&str, BTreeSet<&str>>) -> bool {
    let mut at = crate::observe::parent_name(name);
    loop {
        if types_at.contains_key(format!("*.{at}").as_str()) {
            return true;
        }
        if at == zone || at == "." || !is_ancestor_or_equal(zone, at) {
            return false;
        }
        at = crate::observe::parent_name(at);
    }
}

/// The names outside the zone that the file's CNAME, MX and NS records
/// point at, with the record that names each.
pub fn outside_targets(zone: &str, parsed: &ParsedZone) -> Vec<(String, String, String)> {
    let mut out = BTreeSet::new();
    for s in &parsed.sets {
        for value in &s.rdata {
            if let Some(target) = target_of(&s.rtype, value)
                && !is_ancestor_or_equal(zone, target)
            {
                out.insert((s.name.clone(), s.rtype.clone(), target.to_string()));
            }
        }
    }
    out.into_iter().collect()
}

/// The issue, if any, for a target outside the zone that was looked up.
pub fn issue_for_target(
    owner: &str,
    rtype: &str,
    target: &str,
    lookup: &crate::observe::Lookup,
) -> Option<Issue> {
    if lookup.status != "nxdomain" {
        return None;
    }
    Some(match lookup.unregistered_domain() {
        Some(domain) => issue(
            Severity::Critical,
            "PLN-07",
            owner,
            format!(
                "the {rtype} record of {owner} points at {target}, in the unregistered domain {domain}: whoever registers it controls this name"
            ),
        ),
        None => issue(
            Severity::Warning,
            "PLN-07",
            owner,
            format!("the {rtype} record of {owner} points at {target}, which does not exist"),
        ),
    })
}

/// What deploying the file would change, given what the servers hold now
/// for the names in it. Only names and types the run asked about are
/// compared.
pub fn changes(obs: &ZoneObservation, parsed: &ParsedZone) -> Vec<Change> {
    let mut live: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for rec in &obs.records {
        let rtype = rec.qtype.as_str();
        if !COMPARED.contains(&rtype) {
            continue;
        }
        if let Some(answer) = rec.outcome.answer().filter(|a| a.authoritative) {
            live.entry((rec.name.clone(), rtype.to_string()))
                .or_default()
                .extend(answer.rdata.iter().map(|r| comparable(rtype, r)));
        }
    }
    let mut out = Vec::new();
    for s in &parsed.sets {
        let Some(now) = live.get(&(s.name.clone(), s.rtype.clone())) else {
            continue;
        };
        if now.iter().eq(s.rdata.iter()) {
            continue;
        }
        out.push(Change {
            kind: if now.is_empty() { "add" } else { "change" },
            name: s.name.clone(),
            rtype: s.rtype.clone(),
            live: now.iter().cloned().collect(),
            file: s.rdata.clone(),
        });
    }
    for ((name, rtype), now) in &live {
        let in_file = parsed
            .sets
            .iter()
            .any(|s| s.name == *name && s.rtype == *rtype);
        // The apex NS set belongs to the DNS host unless the file states it.
        if now.is_empty() || in_file || rtype == "NS" {
            continue;
        }
        out.push(Change {
            kind: "remove",
            name: name.clone(),
            rtype: rtype.clone(),
            live: now.iter().cloned().collect(),
            file: Vec::new(),
        });
    }
    out.sort_by(|a, b| (&a.name, &a.rtype).cmp(&(&b.name, &b.rtype)));
    out
}

impl Plan {
    pub fn new(
        zone: &str,
        file: &str,
        mut issues: Vec<Issue>,
        changes: Option<Vec<Change>>,
    ) -> Self {
        issues.sort();
        let exit_code = match issues.iter().map(|i| i.severity).min() {
            Some(Severity::Critical) => 2,
            Some(Severity::Warning | Severity::Notice) => 1,
            _ => 0,
        };
        Self {
            schema_version: crate::output::SCHEMA_VERSION,
            zone: zone.to_string(),
            file: file.to_string(),
            issues,
            changes,
            exit_code,
        }
    }

    /// The plan as text for a terminal. Every piece that came from the
    /// file or the network is made safe to print, here as well as where
    /// it was read.
    pub fn render(&self) -> String {
        let safe = |text: &str| crate::resolver::iterate::printable(text);
        let mut out = format!(
            "zoneblick plan {}\nfile: {}\n",
            safe(&self.zone),
            safe(&self.file)
        );
        out.push_str("\nIssues in the file\n");
        if self.issues.is_empty() {
            out.push_str("  None.\n");
        }
        for i in &self.issues {
            out.push_str(&format!(
                "  {:<8} {}  {}\n",
                i.severity.as_str().to_uppercase(),
                i.id,
                safe(&i.message)
            ));
        }
        match &self.changes {
            None => out.push_str("\nNot compared with the live zone (--offline).\n"),
            Some(changes) => {
                out.push_str("\nWhat deploying it would change\n");
                if changes.is_empty() {
                    out.push_str("  Nothing: the nameservers already serve what the file says.\n");
                }
                let join = |v: &[String]| safe(&v.join(", "));
                for c in changes {
                    match c.kind {
                        "add" => out.push_str(&format!(
                            "  + add     {} {}  {}\n",
                            c.name,
                            c.rtype,
                            join(&c.file)
                        )),
                        "remove" => out.push_str(&format!(
                            "  - remove  {} {}  {}\n",
                            c.name,
                            c.rtype,
                            join(&c.live)
                        )),
                        _ => out.push_str(&format!(
                            "  ~ change  {} {}  {}  ->  {}\n",
                            c.name,
                            c.rtype,
                            join(&c.live),
                            join(&c.file)
                        )),
                    }
                }
            }
        }
        let count = |s: Severity| self.issues.iter().filter(|i| i.severity == s).count();
        out.push_str(&format!(
            "\nSummary: {} critical, {} warning{}\n",
            count(Severity::Critical),
            count(Severity::Warning) + count(Severity::Notice),
            match &self.changes {
                Some(c) => format!("; {} record sets would change", c.len()),
                None => String::new(),
            }
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zonefile::parse_full;

    const ZONE: &str = "example.org.";

    fn lint_of(text: &str) -> Vec<(&'static str, Severity, String)> {
        lint(ZONE, &parse_full(ZONE, text).unwrap())
            .into_iter()
            .map(|i| (i.id, i.severity, i.name))
            .collect()
    }

    #[test]
    fn a_sound_file_has_no_issues() {
        let text = "@ MX 10 mail\n@ MX 20 mx.provider.example.\n@ TXT \"v=spf1 mx -all\"\n@ NS ns1\nns1 A 192.0.2.1\nmail A 192.0.2.25\nwww CNAME mail\n_sip._tcp SRV 0 5 5060 mail\nsub NS ns.sub\n*.apps A 192.0.2.9\napi MX 10 x.apps\n";
        assert_eq!(lint_of(text), []);
    }

    #[test]
    fn mistakes_in_the_file_are_found() {
        let text = "@ CNAME other.example.net.\n\
                    www CNAME a\nwww CNAME b\nwww TXT \"x\"\n\
                    shop CNAME shops.example.net.\nshop SRV 0 0 443 x\n\
                    @ MX 10 www\n@ MX 20 nowhere\n\
                    @ TXT \"v=spf1 -all\"\n@ TXT \"v=spf1 mx -all\"\n";
        assert_eq!(
            lint_of(text),
            [
                ("PLN-01", Severity::Critical, ZONE.to_string()),
                (
                    "PLN-02",
                    Severity::Critical,
                    "shop.example.org.".to_string()
                ),
                ("PLN-02", Severity::Critical, "www.example.org.".to_string()),
                ("PLN-03", Severity::Critical, "www.example.org.".to_string()),
                ("PLN-04", Severity::Warning, ZONE.to_string()),
                ("PLN-05", Severity::Warning, ZONE.to_string()),
                ("PLN-06", Severity::Warning, ZONE.to_string()),
            ]
        );
        let plan = Plan::new(
            ZONE,
            "f",
            lint(ZONE, &parse_full(ZONE, text).unwrap()),
            None,
        );
        assert_eq!(plan.exit_code, 2);
        assert!(
            plan.render().contains("CRITICAL PLN-01"),
            "{}",
            plan.render()
        );
        assert!(plan.render().contains("Not compared with the live zone"));
    }

    #[test]
    fn targets_outside_the_zone_are_listed() {
        let parsed = parse_full(
            ZONE,
            "www CNAME host.example.net.\n@ MX 10 mail\n@ MX 0 .\nb MX 5 mx.example.com.\n",
        )
        .unwrap();
        assert_eq!(
            outside_targets(ZONE, &parsed),
            [
                (
                    "b.example.org.".to_string(),
                    "MX".to_string(),
                    "mx.example.com.".to_string()
                ),
                (
                    "www.example.org.".to_string(),
                    "CNAME".to_string(),
                    "host.example.net.".to_string()
                ),
            ]
        );
    }
}
