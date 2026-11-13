//! Terminal output: delegation path, nameserver table, findings by severity.

use std::fmt::Write;
use std::net::IpAddr;

use super::Report;
use crate::checks::{Evidence, Finding, LameReason, ProbeSummary, ServerRef, Severity};
use crate::observe::{QType, ServerProbe, Transport};

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

/// Render a report for a terminal. `color` turns ANSI colours on.
pub fn render(report: &Report, color: bool) -> String {
    let st = Style { color };
    let mut out = String::new();
    let w = &mut out;

    let _ = writeln!(
        w,
        "{}",
        st.bold(&format!("zoneblick check {}", report.zone))
    );
    let _ = writeln!(w);
    delegation(w, &st, report);
    nameservers(w, &st, report);
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
        let _ = writeln!(w, "  None. All delegation and consistency checks passed.");
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
fn evidence_lines(evidence: &Evidence) -> Vec<String> {
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
    }
}
