//! Terminal output: delegation path, nameserver table, findings by severity.

use std::fmt::Write;
use std::net::IpAddr;

use std::collections::{BTreeMap, BTreeSet};

use super::{Report, StoredRun, utc};
use crate::checks::{Evidence, Finding, LameReason, ProbeSummary, ServerRef, Severity};
use crate::diff::{ChangeKind, DiffReport, RecordChange};
use crate::observe::{QType, ServerProbe, Transport};
use crate::store::ZoneSummary;

struct Style {
    color: bool,
}

impl Style {
    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }

    fn dim(&self, text: &str) -> String {
        self.paint("2", text)
    }

    fn severity(&self, severity: Severity, text: &str) -> String {
        let code = match severity {
            Severity::Critical => "1;31",
            Severity::Warning => "1;33",
            Severity::Notice => "1;36",
            Severity::Info => "1",
        };
        self.paint(code, text)
    }
}

/// Render a `check` report for a terminal. `color` turns ANSI colours on.
pub fn render(report: &Report, color: bool) -> String {
    render_as("check", report, color)
}

/// Render a report under the name of the command that produced it.
pub fn render_as(command: &str, report: &Report, color: bool) -> String {
    let st = Style { color };
    let mut out = String::new();
    let w = &mut out;

    let _ = writeln!(
        w,
        "{}",
        st.bold(&format!("zoneblick {command} {}", report.zone))
    );
    let _ = writeln!(w);
    delegation(w, &st, report);
    nameservers(w, &st, report);
    dnssec(w, &st, report);
    mail_policy(w, &st, report);
    records(w, &st, report);
    findings(w, &st, report);

    let s = report.summary;
    let _ = writeln!(
        w,
        "{} {} critical, {} warning, {} notice, {} info",
        st.bold("Summary:"),
        s.critical,
        s.warning,
        s.notice,
        s.info
    );
    out
}

fn delegation(w: &mut String, st: &Style, report: &Report) {
    let _ = writeln!(w, "{}", st.bold("Delegation path"));
    if report.delegation_path.is_empty() {
        let _ = writeln!(w, "  (none: the root servers answer for this zone)");
    }
    let width = report
        .delegation_path
        .iter()
        .map(|s| s.from_zone.len() + s.to_zone.len())
        .max()
        .unwrap_or(0);
    for step in &report.delegation_path {
        let hop = format!("{} -> {}", step.from_zone, step.to_zone);
        let server = match &step.server_name {
            Some(name) => format!("{name} ({})", step.server_address),
            None => step.server_address.to_string(),
        };
        let _ = writeln!(
            w,
            "  {hop:<pad$}  {}",
            st.dim(&format!(
                "asked {server}: {} NS, {} glue",
                step.ns.len(),
                step.glue.len()
            )),
            pad = width + 4
        );
    }
    let delegated = report
        .delegation_path
        .last()
        .is_some_and(|s| s.to_zone == report.zone);
    if !delegated && !report.delegation_path.is_empty() {
        let _ = writeln!(
            w,
            "  (no referral to {}: the parent's servers answer for it themselves)",
            report.zone
        );
    }
    let _ = writeln!(w);
}

fn nameservers(w: &mut String, st: &Style, report: &Report) {
    let _ = writeln!(w, "{}", st.bold("Nameservers"));
    for host in &report.nameservers {
        let listed = match (host.in_parent, host.in_child) {
            (true, true) => "parent and zone",
            (true, false) => "parent only",
            (false, true) => "zone only",
            (false, false) => "answering servers",
        };
        let _ = writeln!(
            w,
            "  {}  {}",
            host.name,
            st.dim(&format!("listed by: {listed}"))
        );
        let addresses = host.addresses();
        if addresses.is_empty() {
            let why = host.resolve_error.as_deref().unwrap_or("unknown reason");
            let _ = writeln!(w, "    no address ({why})");
        }
        let width = addresses
            .iter()
            .map(|a| a.to_string().len())
            .max()
            .unwrap_or(0);
        for address in addresses {
            let probes: Vec<&ServerProbe> = report
                .probes
                .iter()
                .filter(|p| p.address == address)
                .collect();
            let _ = writeln!(
                w,
                "    {:<width$}  {}",
                address.to_string(),
                server_line(&probes)
            );
        }
    }
    let _ = writeln!(w);
}

/// One line for one address: serial, then UDP and TCP status.
fn server_line(probes: &[&ServerProbe]) -> String {
    if probes.is_empty() {
        return "not tested (address family does not work from this host)".to_string();
    }
    let serial = probes
        .iter()
        .filter(|p| p.qtype == QType::Soa)
        .filter_map(|p| p.outcome.response())
        .filter(|r| r.is_authoritative_answer())
        .find_map(|r| r.soa.as_ref())
        .map(|soa| format!("serial {}", soa.serial))
        .unwrap_or_else(|| "no authoritative SOA".to_string());
    let status = |transport: Transport| {
        let mut labels: Vec<String> = probes
            .iter()
            .filter(|p| p.transport == transport)
            .map(|p| match p.outcome.response() {
                Some(r) if r.is_authoritative_answer() => "ok".to_string(),
                _ => p.outcome.label(),
            })
            .collect();
        labels.sort();
        labels.dedup();
        labels.join(", ")
    };
    format!(
        "{serial}   udp: {}   tcp: {}",
        status(Transport::Udp),
        status(Transport::Tcp)
    )
}

fn findings(w: &mut String, st: &Style, report: &Report) {
    let _ = writeln!(w, "{}", st.bold("Findings"));
    if report.findings.is_empty() {
        let _ = writeln!(w, "  None. All checks passed.");
        let _ = writeln!(w);
        return;
    }
    for severity in Severity::ALL {
        let group: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect();
        if group.is_empty() {
            continue;
        }
        let heading = format!("{} ({})", severity.as_str().to_uppercase(), group.len());
        let _ = writeln!(w, "  {}", st.severity(severity, &heading));
        for finding in group {
            let _ = writeln!(w, "    {}  {}", st.bold(&finding.check_id), finding.name);
            let _ = writeln!(w, "      {}", finding.summary);
            for line in evidence_lines(&finding.evidence) {
                let _ = writeln!(w, "      {}", st.dim(&line));
            }
        }
        let _ = writeln!(w);
    }
}

fn list<T: ToString>(items: &[T]) -> String {
    if items.is_empty() {
        return "(none)".to_string();
    }
    items
        .iter()
        .map(T::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn server_list(servers: &[ServerRef]) -> String {
    servers
        .iter()
        .map(|s| format!("{} ({})", s.ns_name, s.address))
        .collect::<Vec<_>>()
        .join(", ")
}

fn probe_lines(probes: &[ProbeSummary]) -> Vec<String> {
    probes
        .iter()
        .map(|p| {
            format!(
                "{:<3} over {}{}: {}",
                p.qtype.as_str(),
                match p.transport {
                    Transport::Udp => "UDP",
                    Transport::Tcp => "TCP",
                },
                if p.edns { "" } else { " without EDNS" },
                p.result
            )
        })
        .collect()
}

/// The evidence of a finding as plain lines.
pub fn evidence_lines(evidence: &Evidence) -> Vec<String> {
    match evidence {
        Evidence::NsSetMismatch {
            parent,
            child,
            only_in_parent,
            only_in_child,
        } => vec![
            format!("parent lists: {}", list(parent)),
            format!("zone lists:   {}", list(child)),
            format!("only at parent: {}", list(only_in_parent)),
            format!("only in zone:   {}", list(only_in_child)),
        ],
        Evidence::LameServer { reason, probes, .. } => {
            let mut lines = vec![match reason {
                LameReason::NotAuthoritative => {
                    "answers, but never with an authoritative SOA for the zone".to_string()
                }
                LameReason::NoResponse => "no response on any transport".to_string(),
                LameReason::Unresolvable => "the name has no A or AAAA record".to_string(),
            }];
            lines.extend(probe_lines(probes));
            lines
        }
        Evidence::GlueMismatch { glue, resolved, .. } => vec![
            format!("glue at parent: {}", list(glue)),
            format!("resolves to:    {}", list(resolved)),
        ],
        Evidence::TooFewNameservers { nameservers } => {
            vec![format!("nameservers: {}", list(nameservers))]
        }
        Evidence::SingleNetwork { addresses, .. } => {
            vec![format!("addresses: {}", list::<IpAddr>(addresses))]
        }
        Evidence::NsIsCname { target, .. } => vec![format!("CNAME target: {target}")],
        Evidence::SerialMismatch { serials } => serials
            .iter()
            .map(|v| format!("serial {}: {}", v.value, server_list(&v.servers)))
            .collect(),
        Evidence::RrsetMismatch { variants, .. } => variants
            .iter()
            .flat_map(|v| {
                [
                    format!("{}:", server_list(&v.servers)),
                    format!("  {}", list(&v.value)),
                ]
            })
            .collect(),
        Evidence::NoTcp { probes, .. } | Evidence::Ipv6Unreachable { probes, .. } => {
            probe_lines(probes)
        }
        Evidence::Ipv6NotTested { addresses } => {
            vec![format!("not tested: {}", list::<IpAddr>(addresses))]
        }
        Evidence::EdnsProblem { problems, .. } => problems.clone(),
        Evidence::DsWithoutKey { ds, servers } => {
            let mut lines: Vec<String> = ds.iter().map(|d| format!("DS at parent: {d}")).collect();
            for v in servers {
                lines.push(format!("{} serves:", server_list(&v.servers)));
                lines.push(format!("  {}", list(&v.value)));
            }
            lines
        }
        Evidence::SignatureExpiry {
            key_tag,
            expiration_unix,
            servers,
            ..
        } => vec![
            format!(
                "signed by key tag {key_tag}, expires {}",
                utc(u64::from(*expiration_unix))
            ),
            if servers.len() > 4 {
                format!("seen on {} nameserver addresses", servers.len())
            } else {
                format!("seen on: {}", server_list(servers))
            },
        ],
        Evidence::SignedNotChained { dnskeys } => vec![format!("keys: {}", list(dnskeys))],
        Evidence::WeakAlgorithm { items } => items.clone(),
        Evidence::SpfProblem {
            records,
            lookups,
            chain,
        } => {
            let mut lines: Vec<String> = records.iter().map(|r| format!("record: {r}")).collect();
            lines.push(format!("{lookups} DNS lookups:"));
            lines.extend(chain.iter().map(|c| format!("  {c}")));
            lines
        }
        Evidence::DmarcProblem { record, .. } => match record {
            Some(r) => vec![format!("record: {r}")],
            None => vec!["no TXT record starting with v=DMARC1".to_string()],
        },
        Evidence::NoCaa {} => vec!["no CAA record at the zone apex".to_string()],
        Evidence::MtaStsProblem {
            record,
            policy_url,
            problems,
        } => {
            let mut lines = vec![format!("record: {record}"), format!("policy: {policy_url}")];
            lines.extend(problems.iter().cloned());
            lines
        }
        Evidence::MailTargetProblem { cname, .. } => match cname {
            Some(c) => vec![format!("CNAME target: {c}")],
            None => vec!["no A or AAAA record".to_string()],
        },
        Evidence::DanglingTarget {
            owner,
            rtype,
            target,
            said_by,
            unregistered_domain,
        } => {
            let mut lines = vec![format!("{owner}  {rtype}  {target}")];
            if let Some(zone) = said_by {
                lines.push(format!("the servers of {zone} say the name does not exist"));
            }
            if let Some(domain) = unregistered_domain {
                lines.push(format!(
                    "{domain} is not delegated: unregistered or expired"
                ));
            }
            lines
        }
        Evidence::UnclaimedService {
            owner,
            target,
            service,
            url,
            status,
        } => vec![
            format!("{owner}  CNAME  {target}"),
            match status {
                Some(code) => format!(
                    "{url} answered HTTP {code} with the {service} page for an unclaimed site"
                ),
                None => format!("{url} gave the {service} page for an unclaimed site"),
            },
        ],
        Evidence::ServerBehaviour { details, .. }
        | Evidence::ZoneDetail { details }
        | Evidence::RecordDetail { details, .. } => details.clone(),
        Evidence::Drift {
            declared,
            served,
            source,
            ..
        } => {
            let show = |v: &[String]| {
                if v.is_empty() {
                    "(nothing)".to_string()
                } else {
                    v.join(", ")
                }
            };
            vec![
                format!("zone file: {}", show(declared)),
                format!("served:    {}", show(served)),
                format!("file: {source}"),
            ]
        }
        Evidence::WildcardAlias { wildcard, target } => {
            vec![format!("{wildcard}  CNAME  {target}")]
        }
        Evidence::SignaturesDiffer { variants } => variants
            .iter()
            .flat_map(|v| {
                [
                    format!("{}:", server_list(&v.servers)),
                    format!("  {}", v.value.join("; ")),
                ]
            })
            .collect(),
    }
}

/// A short DNSSEC summary: the DS set, the keys, and when signatures run out.
fn dnssec(w: &mut String, st: &Style, report: &Report) {
    let Some(d) = &report.dnssec else {
        return;
    };
    let _ = writeln!(w, "{}", st.bold("DNSSEC"));
    match &d.parent_ds {
        None => {
            let _ = writeln!(
                w,
                "  DS at parent: not applicable (no referral to this zone)"
            );
        }
        Some(p) => match &p.records {
            None => {
                let why = p.error.as_deref().unwrap_or("no answer");
                let _ = writeln!(w, "  DS at {}: could not be read ({why})", p.parent_zone);
            }
            Some(ds) if ds.is_empty() => {
                let _ = writeln!(w, "  DS at {}: none", p.parent_zone);
            }
            Some(ds) => {
                let items: Vec<String> = ds
                    .iter()
                    .map(|r| {
                        format!(
                            "key tag {} ({}, {})",
                            r.key_tag,
                            crate::dnssec::algorithm_name(r.algorithm),
                            crate::dnssec::digest_name(r.digest_type)
                        )
                    })
                    .collect();
                let _ = writeln!(w, "  DS at {}: {}", p.parent_zone, items.join("; "));
            }
        },
    }
    let answered = d.servers.iter().filter(|s| s.dnskeys.is_some()).count();
    let keys: BTreeSet<String> = d
        .servers
        .iter()
        .flat_map(|s| s.dnskeys.iter().flatten())
        .map(|k| {
            format!(
                "key tag {} ({}, {})",
                k.key_tag,
                if k.is_ksk() { "KSK" } else { "ZSK" },
                crate::dnssec::algorithm_name(k.algorithm)
            )
        })
        .collect();
    if answered == 0 {
        let _ = writeln!(w, "  DNSKEY: no server answered");
    } else if keys.is_empty() {
        let _ = writeln!(w, "  DNSKEY: none; the zone is not signed");
    } else {
        for key in keys {
            let _ = writeln!(w, "  DNSKEY: {key}");
        }
        let soonest = d
            .servers
            .iter()
            .flat_map(|s| s.dnskey_sigs.iter().chain(s.soa_sigs.iter().flatten()))
            .map(|sig| sig.expiration)
            .min();
        if let Some(expiry) = soonest {
            let _ = writeln!(
                w,
                "  {}",
                st.dim(&format!(
                    "earliest signature expiry: {}",
                    utc(u64::from(expiry))
                ))
            );
        }
    }
    let _ = writeln!(w);
}

/// A short summary of the zone's mail and policy records.
fn mail_policy(w: &mut String, st: &Style, report: &Report) {
    let Some(p) = &report.policy else {
        return;
    };
    let known = [&p.apex_txt, &p.dmarc, &p.caa, &p.mx]
        .iter()
        .any(|l| l.status != "failed");
    if !known {
        return;
    }
    let state = |l: &crate::observe::Lookup, present: String| match l.status.as_str() {
        "failed" => "could not be read".to_string(),
        "answer" => present,
        _ => "none".to_string(),
    };
    let _ = writeln!(w, "{}", st.bold("Mail and policy"));
    let mx: Vec<&str> =
        p.mx.rdata
            .iter()
            .map(|r| r.split_whitespace().nth(1).unwrap_or(r))
            .collect();
    let mx_text = if mx == ["."] {
        "null MX (the zone takes no mail)".to_string()
    } else {
        mx.join(", ")
    };
    let _ = writeln!(w, "  MX:    {}", state(&p.mx, mx_text));
    let spf = match &p.spf {
        Some(s) => format!("{} DNS lookups", s.lookups.len()),
        None => state(&p.apex_txt, "none".to_string()),
    };
    let _ = writeln!(w, "  SPF:   {spf}");
    let dmarc = p
        .dmarc
        .rdata
        .iter()
        .map(|r| crate::resolver::policy::txt_value(r))
        .find(|v| v.to_ascii_lowercase().starts_with("v=dmarc1"));
    let dmarc_policy = dmarc
        .as_deref()
        .and_then(|text| {
            text.split(';')
                .filter_map(|part| part.trim().split_once('='))
                .find(|(k, _)| k.trim().eq_ignore_ascii_case("p"))
                .map(|(_, v)| format!("p={}", v.trim()))
        })
        .unwrap_or_else(|| "none".to_string());
    let _ = writeln!(w, "  DMARC: {}", state(&p.dmarc, dmarc_policy));
    let _ = writeln!(
        w,
        "  CAA:   {}",
        state(&p.caa, format!("{} records", p.caa.rdata.len()))
    );
    if let Some(sts) = &p.mta_sts {
        let _ = writeln!(
            w,
            "  MTA-STS: mode {}",
            sts.mode.as_deref().unwrap_or("unknown")
        );
    }
    let _ = writeln!(w);
}

/// What all servers together served for one name and type.
type Pool<'a> = (BTreeSet<&'a str>, Option<u32>);

/// The record sets a run collected: one line per name and type that exists.
fn records(w: &mut String, st: &Style, report: &Report) {
    if report.records.is_empty() {
        return;
    }
    let mut pools: BTreeMap<(&str, QType), Pool<'_>> = BTreeMap::new();
    for rec in &report.records {
        let Some(answer) = rec.outcome.answer() else {
            continue;
        };
        if !answer.authoritative || rec.qtype == QType::Soa {
            continue;
        }
        let entry = pools.entry((&rec.name, rec.qtype)).or_default();
        entry.0.extend(answer.rdata.iter().map(String::as_str));
        entry.1 = entry.1.or(answer.ttl);
    }
    let names: BTreeSet<&str> = pools.keys().map(|k| k.0).collect();
    let empty = pools.values().filter(|p| p.0.is_empty()).count();
    let _ = writeln!(w, "{}", st.bold("Records"));
    let width = names.iter().map(|n| n.len()).max().unwrap_or(0);
    for ((name, qtype), (pool, ttl)) in &pools {
        if pool.is_empty() {
            continue;
        }
        let values: Vec<&str> = pool.iter().copied().collect();
        let ttl = ttl.map(|t| format!("  ttl {t}")).unwrap_or_default();
        let _ = writeln!(
            w,
            "  {name:<width$}  {:<5}  {}{}",
            qtype.as_str(),
            values.join(", "),
            st.dim(&ttl)
        );
    }
    let _ = writeln!(
        w,
        "  {}",
        st.dim(&format!(
            "{} names checked; {empty} name and type pairs have no records",
            names.len()
        ))
    );
    let _ = writeln!(w);
}

/// The lines `run` adds after the report: where the run was stored and what
/// changed since the previous one.
pub fn render_stored(run: &StoredRun, diff: Option<&DiffReport>, color: bool) -> String {
    let st = Style { color };
    let mut out = String::new();
    let w = &mut out;
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "{} run #{} in {} ({} besides the apex, {} queries)",
        st.bold("Stored:"),
        run.id,
        run.db,
        match run.names.len() {
            1 => "1 name".to_string(),
            n => format!("{n} names"),
        },
        run.queries
    );
    match diff {
        None => {
            let _ = writeln!(
                w,
                "This is the first stored run of the zone. Later runs are compared with it."
            );
        }
        Some(d) => {
            let _ = writeln!(w);
            let _ = writeln!(
                w,
                "{}",
                st.bold(&format!(
                    "Changes since run #{} ({})",
                    d.from.id,
                    utc(d.from.started_at_unix)
                ))
            );
            diff_body(w, &st, d);
        }
    }
    out
}

/// Render a diff for a terminal.
pub fn render_diff(d: &DiffReport, color: bool) -> String {
    let st = Style { color };
    let mut out = String::new();
    let w = &mut out;
    let _ = writeln!(w, "{}", st.bold(&format!("zoneblick diff {}", d.zone)));
    let _ = writeln!(
        w,
        "run #{} ({}) -> run #{} ({})",
        d.from.id,
        utc(d.from.started_at_unix),
        d.to.id,
        utc(d.to.started_at_unix)
    );
    let _ = writeln!(w);
    diff_body(w, &st, d);
    out
}

fn change_label(st: &Style, kind: ChangeKind) -> String {
    let (text, severity) = match kind {
        ChangeKind::Added => ("ADDED", Severity::Notice),
        ChangeKind::Removed => ("REMOVED", Severity::Critical),
        ChangeKind::Modified => ("MODIFIED", Severity::Warning),
        ChangeKind::Ttl => ("TTL", Severity::Info),
    };
    st.severity(severity, &format!("{text:<8}"))
}

fn record_change(w: &mut String, st: &Style, c: &RecordChange) {
    let label = if c.rotation {
        st.dim("ROTATION")
    } else {
        change_label(st, c.kind)
    };
    let _ = writeln!(w, "  {}  {} {}", label, c.name, c.rtype.as_str());
    for value in &c.removed {
        let _ = writeln!(
            w,
            "    {}",
            st.severity(Severity::Critical, &format!("- {value}"))
        );
    }
    for value in &c.added {
        let _ = writeln!(w, "    {}", st.paint("1;32", &format!("+ {value}")));
    }
    if c.ttl_before != c.ttl_after && !c.ttl_before.is_empty() && !c.ttl_after.is_empty() {
        let _ = writeln!(
            w,
            "    ttl {} -> {}",
            list(&c.ttl_before),
            list(&c.ttl_after)
        );
    }
    if c.kind == ChangeKind::Ttl {
        return;
    }
    if c.rotation {
        let _ = writeln!(
            w,
            "    {}",
            st.dim("this name's addresses rotate; not counted as a change")
        );
        return;
    }
    if c.all_servers {
        let _ = writeln!(w, "    {}", st.dim("on every nameserver"));
        return;
    }
    for s in &c.servers {
        let side = |v: &Option<Vec<String>>| match v {
            None => "no answer".to_string(),
            Some(v) => list(v),
        };
        let _ = writeln!(
            w,
            "    {}",
            st.dim(&format!(
                "{} ({}): {} -> {}",
                s.ns_name,
                s.address,
                side(&s.before),
                side(&s.after)
            ))
        );
    }
}

fn diff_body(w: &mut String, st: &Style, d: &DiffReport) {
    if !d.changed && d.soa_serial.is_none() {
        let _ = writeln!(w, "  No changes.");
    }
    for c in &d.changes {
        record_change(w, st, c);
    }
    if let Some(del) = &d.delegation {
        let _ = writeln!(
            w,
            "  {}  delegation at the parent",
            st.severity(Severity::Warning, "MODIFIED")
        );
        for ns in &del.ns_removed {
            let _ = writeln!(
                w,
                "    {}",
                st.severity(Severity::Critical, &format!("- NS {ns}"))
            );
        }
        for ns in &del.ns_added {
            let _ = writeln!(w, "    {}", st.paint("1;32", &format!("+ NS {ns}")));
        }
        for g in &del.glue_removed {
            let _ = writeln!(
                w,
                "    {}",
                st.severity(
                    Severity::Critical,
                    &format!("- glue {} {}", g.name, g.address)
                )
            );
        }
        for g in &del.glue_added {
            let _ = writeln!(
                w,
                "    {}",
                st.paint("1;32", &format!("+ glue {} {}", g.name, g.address))
            );
        }
    }
    if let Some(serial) = &d.soa_serial {
        let _ = writeln!(
            w,
            "  {}",
            st.dim(&format!(
                "SOA serial {} -> {}",
                list(&serial.before),
                list(&serial.after)
            ))
        );
    }
    for f in &d.findings_opened {
        let _ = writeln!(
            w,
            "  {}  {} {}  {}",
            st.severity(f.severity, "OPENED  "),
            f.check_id,
            f.severity.as_str(),
            f.summary
        );
    }
    for f in &d.findings_resolved {
        let _ = writeln!(
            w,
            "  {}  {} {}  {}",
            st.paint("1;32", "RESOLVED"),
            f.check_id,
            f.severity.as_str(),
            f.summary
        );
    }
    let ignored = d
        .not_compared
        .iter()
        .filter(|n| n.reason == "ignored")
        .count();
    let new_names: BTreeSet<&str> = d
        .not_compared
        .iter()
        .filter(|n| n.reason != "ignored")
        .map(|n| n.name.as_str())
        .collect();
    if ignored > 0 {
        let _ = writeln!(
            w,
            "  {}",
            st.dim(&format!("{ignored} changed record sets ignored by pattern"))
        );
    }
    if !new_names.is_empty() {
        let names: Vec<&str> = new_names.into_iter().collect();
        let _ = writeln!(
            w,
            "  {}",
            st.dim(&format!(
                "not compared, checked in only one of the runs: {}",
                names.join(", ")
            ))
        );
    }
    let s = d.summary;
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "{} {} added, {} removed, {} modified, {} TTL; findings: {} opened, {} resolved",
        st.bold("Changes:"),
        s.added,
        s.removed,
        s.modified,
        s.ttl,
        s.findings_opened,
        s.findings_resolved
    );
}

/// Render the list of stored zones for a terminal.
pub fn render_zones(db: &str, zones: &[ZoneSummary], color: bool) -> String {
    let st = Style { color };
    let mut out = String::new();
    let w = &mut out;
    let _ = writeln!(w, "{}", st.bold(&format!("Zones in {db}")));
    if zones.is_empty() {
        let _ = writeln!(w, "  None yet. Store one with: zoneblick run <zone>");
        return out;
    }
    let width = zones.iter().map(|z| z.zone.len()).max().unwrap_or(0);
    for z in zones {
        let last = match z.last_run {
            Some(r) => format!("last run #{} at {}", r.id, utc(r.started_at_unix)),
            None => "no runs".to_string(),
        };
        let _ = writeln!(
            w,
            "  {:<width$}  {} runs, {} names, {} open findings, {}",
            z.zone, z.runs, z.names, z.open_findings, last
        );
    }
    out
}
