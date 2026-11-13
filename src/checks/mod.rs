//! The check engine: pure functions from observations to findings.
//!
//! Nothing in this module does I/O. A check reads a
//! [`ZoneObservation`] and returns findings, so every check can be tested
//! offline against hand-built or replayed observations.

pub mod consistency;
pub mod delegation;

use std::net::IpAddr;

use serde::Serialize;

use crate::observe::{NsHost, QType, ResponseObs, ServerProbe, Transport, ZoneObservation};

/// Severity levels from `DESIGN.md`, most severe first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    Notice,
    Info,
}

impl Severity {
    pub const ALL: [Severity; 4] = [
        Severity::Critical,
        Severity::Warning,
        Severity::Notice,
        Severity::Info,
    ];

    pub fn parse(s: &str) -> Option<Severity> {
        Severity::ALL.into_iter().find(|v| v.as_str() == s)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Notice => "notice",
            Severity::Info => "info",
        }
    }
}

/// One nameserver address, as named in evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ServerRef {
    pub ns_name: String,
    pub address: IpAddr,
}

/// One query and a short description of what came back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeSummary {
    pub qtype: QType,
    pub transport: Transport,
    pub edns: bool,
    pub result: String,
}

impl From<&ServerProbe> for ProbeSummary {
    fn from(p: &ServerProbe) -> Self {
        Self {
            qtype: p.qtype,
            transport: p.transport,
            edns: p.edns,
            result: p.outcome.label(),
        }
    }
}

/// Why a listed nameserver counts as lame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LameReason {
    /// It answered, but not authoritatively for the zone.
    NotAuthoritative,
    /// It answered no query on any transport.
    NoResponse,
    /// Its hostname has no address.
    Unresolvable,
}

/// A group of servers that agree on one value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Variant<T> {
    pub value: T,
    pub servers: Vec<ServerRef>,
}

/// The structured evidence behind a finding. The `kind` tag names the shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    NsSetMismatch {
        parent: Vec<String>,
        child: Vec<String>,
        only_in_parent: Vec<String>,
        only_in_child: Vec<String>,
    },
    LameServer {
        ns_name: String,
        address: Option<IpAddr>,
        reason: LameReason,
        probes: Vec<ProbeSummary>,
    },
    GlueMismatch {
        ns_name: String,
        glue: Vec<IpAddr>,
        resolved: Vec<IpAddr>,
    },
    TooFewNameservers {
        nameservers: Vec<String>,
    },
    SingleNetwork {
        prefix: String,
        addresses: Vec<IpAddr>,
    },
    NsIsCname {
        ns_name: String,
        target: String,
    },
    SerialMismatch {
        serials: Vec<Variant<u32>>,
    },
    RrsetMismatch {
        rrtype: String,
        variants: Vec<Variant<Vec<String>>>,
    },
    NoTcp {
        ns_name: String,
        address: IpAddr,
        probes: Vec<ProbeSummary>,
    },
    Ipv6Unreachable {
        ns_name: String,
        address: IpAddr,
        probes: Vec<ProbeSummary>,
    },
    Ipv6NotTested {
        addresses: Vec<IpAddr>,
    },
    EdnsProblem {
        ns_name: String,
        address: IpAddr,
        problems: Vec<String>,
    },
}

/// One result of one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Stable check ID, for example `DEL-02`.
    pub check_id: String,
    pub severity: Severity,
    /// The DNS name the finding is about.
    pub name: String,
    /// One line for people.
    pub summary: String,
    pub evidence: Evidence,
}

impl Finding {
    /// The part of a finding that stays the same from run to run while the
    /// underlying problem persists. Values that move, such as serials, are
    /// left out, so one problem is one finding across runs.
    pub fn fingerprint_key(&self) -> String {
        let detail = match &self.evidence {
            Evidence::NsSetMismatch { .. } => String::new(),
            Evidence::LameServer {
                address, reason, ..
            } => format!("{address:?}/{reason:?}"),
            Evidence::GlueMismatch { .. } => String::new(),
            Evidence::TooFewNameservers { .. } => "count".to_string(),
            Evidence::SingleNetwork { addresses, .. } => {
                if addresses.iter().any(|a| a.is_ipv6()) {
                    "ipv6".to_string()
                } else {
                    "ipv4".to_string()
                }
            }
            Evidence::NsIsCname { .. } => String::new(),
            Evidence::SerialMismatch { .. } => String::new(),
            Evidence::RrsetMismatch { rrtype, .. } => rrtype.clone(),
            Evidence::NoTcp { address, .. }
            | Evidence::Ipv6Unreachable { address, .. }
            | Evidence::EdnsProblem { address, .. } => address.to_string(),
            Evidence::Ipv6NotTested { .. } => "not-tested".to_string(),
        };
        format!("{}|{}|{}", self.check_id, self.name, detail)
    }

    pub(crate) fn new(
        check_id: &str,
        severity: Severity,
        name: &str,
        summary: String,
        evidence: Evidence,
    ) -> Self {
        Self {
            check_id: check_id.to_string(),
            severity,
            name: name.to_string(),
            summary,
            evidence,
        }
    }
}

/// A check in the catalog.
pub struct CheckInfo {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub implemented: bool,
}

/// The Phase 0 part of the check catalog in `DESIGN.md`.
pub const CATALOG: &[CheckInfo] = &[
    check(
        "DEL-01",
        "Parent NS set differs from child NS set",
        Severity::Warning,
        true,
    ),
    check(
        "DEL-02",
        "Lame delegation: listed NS is not authoritative for the zone",
        Severity::Critical,
        true,
    ),
    check(
        "DEL-03",
        "Glue at parent differs from the address the NS name resolves to",
        Severity::Warning,
        true,
    ),
    check(
        "DEL-04",
        "Fewer than two nameservers, or all in one /24 or /48",
        Severity::Notice,
        true,
    ),
    check("DEL-05", "NS target is a CNAME", Severity::Warning, true),
    check(
        "DEL-06",
        "NS hostname's own domain is unregistered or expired",
        Severity::Critical,
        false,
    ),
    check(
        "CON-01",
        "SOA serial differs across authoritative servers",
        Severity::Warning,
        true,
    ),
    check(
        "CON-02",
        "RRset differs across authoritative servers for the same name/type",
        Severity::Warning,
        true,
    ),
    check(
        "CON-03",
        "Server does not answer over TCP",
        Severity::Warning,
        true,
    ),
    check(
        "CON-04",
        "Server unreachable over IPv6 (AAAA published, no answer)",
        Severity::Notice,
        true,
    ),
    check(
        "CON-05",
        "Server truncates without EDNS support or mishandles EDNS",
        Severity::Notice,
        true,
    ),
];

const fn check(
    id: &'static str,
    title: &'static str,
    severity: Severity,
    implemented: bool,
) -> CheckInfo {
    CheckInfo {
        id,
        title,
        severity,
        implemented,
    }
}

type Check = fn(&ZoneObservation) -> Vec<Finding>;

const CHECKS: &[Check] = &[
    delegation::del_01_parent_child_ns,
    delegation::del_02_lame,
    delegation::del_03_glue,
    delegation::del_04_redundancy,
    delegation::del_05_ns_cname,
    delegation::del_06_ns_domain_registration,
    consistency::con_01_soa_serial,
    consistency::con_02_rrset,
    consistency::con_03_tcp,
    consistency::con_04_ipv6,
    consistency::con_05_edns,
];

/// Run every Phase 0 check. Findings come back in a stable order: by
/// severity, then check ID, then name, then summary.
pub fn run_all(obs: &ZoneObservation) -> Vec<Finding> {
    let mut findings: Vec<Finding> = CHECKS.iter().flat_map(|check| check(obs)).collect();
    findings.sort_by(|a, b| {
        (a.severity, &a.check_id, &a.name, &a.summary).cmp(&(
            b.severity,
            &b.check_id,
            &b.name,
            &b.summary,
        ))
    });
    findings
}

/// One reachable address of one nameserver, with the probes sent to it.
pub(crate) struct Server<'a> {
    pub host: &'a NsHost,
    pub address: IpAddr,
    pub probes: Vec<&'a ServerProbe>,
}

impl<'a> Server<'a> {
    pub fn server_ref(&self) -> ServerRef {
        ServerRef {
            ns_name: self.host.name.clone(),
            address: self.address,
        }
    }

    pub fn summaries(&self) -> Vec<ProbeSummary> {
        self.probes.iter().map(|p| ProbeSummary::from(*p)).collect()
    }

    /// The server sent something back to at least one query.
    pub fn responded(&self) -> bool {
        self.probes.iter().any(|p| {
            !matches!(
                p.outcome,
                crate::observe::Outcome::Timeout | crate::observe::Outcome::NetError { .. }
            )
        })
    }

    /// Responses to one kind of query.
    pub fn responses(
        &self,
        qtype: QType,
        transport: Transport,
    ) -> impl Iterator<Item = (&'a ServerProbe, &'a ResponseObs)> + '_ {
        self.probes
            .iter()
            .filter(move |p| p.qtype == qtype && p.transport == transport)
            .filter_map(|p| p.outcome.response().map(|r| (*p, r)))
    }

    /// This server's authoritative answer for a type: the EDNS UDP answer if
    /// there is one, otherwise TCP, otherwise UDP without EDNS.
    pub fn authoritative(&self, qtype: QType) -> Option<&'a ResponseObs> {
        let mut candidates: Vec<&ServerProbe> = self
            .probes
            .iter()
            .copied()
            .filter(|p| p.qtype == qtype)
            .collect();
        candidates.sort_by_key(|p| (p.transport, !p.edns));
        candidates
            .into_iter()
            .filter_map(|p| p.outcome.response())
            .find(|r| r.is_authoritative_answer())
    }
}

/// Every (nameserver, address) pair that could be probed from here.
pub(crate) fn servers(obs: &ZoneObservation) -> Vec<Server<'_>> {
    let mut out = Vec::new();
    for host in &obs.ns_hosts {
        for address in host.addresses() {
            if !obs.vantage.can_reach(&address) {
                continue;
            }
            out.push(Server {
                host,
                address,
                probes: obs.probes_for(address).collect(),
            });
        }
    }
    out
}

/// Group servers by a value, in value order.
pub(crate) fn group_by<T: Ord + Clone>(
    servers: &[Server<'_>],
    value: impl Fn(&Server<'_>) -> Option<T>,
) -> Vec<Variant<T>> {
    let mut map: std::collections::BTreeMap<T, Vec<ServerRef>> = Default::default();
    for server in servers {
        if let Some(v) = value(server) {
            map.entry(v).or_default().push(server.server_ref());
        }
    }
    map.into_iter()
        .map(|(value, servers)| Variant { value, servers })
        .collect()
}

#[cfg(test)]
pub(crate) mod testkit;
