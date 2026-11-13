//! The check engine: pure functions from observations to findings.
//!
//! Nothing in this module does I/O. A check reads a
//! [`ZoneObservation`] and returns findings, so every check can be tested
//! offline against hand-built or replayed observations.

pub mod consistency;
pub mod deep;
pub mod delegation;
pub mod policy;
pub mod security;

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::observe::{NsHost, QType, ResponseObs, ServerProbe, Transport, ZoneObservation};

/// Severity levels from `DESIGN.md`, most severe first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServerRef {
    pub ns_name: String,
    pub address: IpAddr,
}

/// One query and a short description of what came back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Variant<T> {
    pub value: T,
    pub servers: Vec<ServerRef>,
}

/// The structured evidence behind a finding. The `kind` tag names the shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    DsWithoutKey {
        /// The DS records at the parent.
        ds: Vec<String>,
        /// The keys each affected server serves instead.
        servers: Vec<Variant<Vec<String>>>,
    },
    SignatureExpiry {
        type_covered: String,
        key_tag: u16,
        expiration_unix: u32,
        /// Negative when the signature has already expired.
        seconds_left: i64,
        servers: Vec<ServerRef>,
    },
    SignedNotChained {
        dnskeys: Vec<String>,
    },
    WeakAlgorithm {
        items: Vec<String>,
    },
    SignaturesDiffer {
        variants: Vec<Variant<Vec<String>>>,
    },
    SpfProblem {
        records: Vec<String>,
        /// How many DNS lookups evaluating the record takes.
        lookups: usize,
        /// The lookups in order, indented by include depth.
        chain: Vec<String>,
    },
    DmarcProblem {
        record: Option<String>,
        policy: Option<String>,
    },
    NoCaa {},
    MtaStsProblem {
        record: String,
        policy_url: String,
        problems: Vec<String>,
    },
    MailTargetProblem {
        target: String,
        problem: String,
        cname: Option<String>,
    },
    DanglingTarget {
        owner: String,
        /// `CNAME`, `MX`, or `SPF include` / `SPF redirect`.
        rtype: String,
        target: String,
        /// The zone whose server said the target does not exist.
        said_by: Option<String>,
        /// Set when the target's whole domain is not registered.
        unregistered_domain: Option<String>,
    },
    UnclaimedService {
        owner: String,
        target: String,
        service: String,
        /// The address that was fetched, and the HTTP status it gave.
        url: String,
        status: Option<u16>,
    },
    ServerBehaviour {
        ns_name: String,
        address: IpAddr,
        details: Vec<String>,
    },
    ZoneDetail {
        details: Vec<String>,
    },
    WildcardAlias {
        /// The wildcard record's name, `*.<zone>`.
        wildcard: String,
        /// The name outside the zone it is an alias of.
        target: String,
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
            Evidence::DsWithoutKey { .. } => String::new(),
            Evidence::SignatureExpiry { type_covered, .. } => type_covered.clone(),
            Evidence::SignedNotChained { .. } => String::new(),
            Evidence::WeakAlgorithm { .. } => String::new(),
            Evidence::SignaturesDiffer { .. } => String::new(),
            Evidence::SpfProblem { .. } => String::new(),
            Evidence::DmarcProblem { .. } => String::new(),
            Evidence::NoCaa {} => String::new(),
            Evidence::MtaStsProblem { .. } => String::new(),
            Evidence::MailTargetProblem { target, .. } => target.clone(),
            Evidence::DanglingTarget { rtype, target, .. } => format!("{rtype}/{target}"),
            Evidence::WildcardAlias { target, .. } => target.clone(),
            Evidence::ServerBehaviour { address, .. } => address.to_string(),
            Evidence::ZoneDetail { .. } => String::new(),
            Evidence::UnclaimedService { service, .. } => service.clone(),
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
    /// True for the checks that only a deep run makes.
    pub deep: bool,
}

/// The implemented part of the check catalog in `DESIGN.md`.
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
        true,
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
    check(
        "SEC-01",
        "DS at parent, no matching DNSKEY at child (zone is bogus)",
        Severity::Critical,
        true,
    ),
    check(
        "SEC-02",
        "RRSIG expired, or expires within 7 days",
        Severity::Critical,
        true,
    ),
    check(
        "SEC-03",
        "DNSKEY present, no DS at parent (signed but not chained)",
        Severity::Notice,
        true,
    ),
    check(
        "SEC-04",
        "Weak or deprecated algorithm or digest",
        Severity::Warning,
        true,
    ),
    check(
        "SEC-05",
        "Signatures differ or are missing on some servers",
        Severity::Warning,
        true,
    ),
    check(
        "POL-01",
        "SPF exceeds 10 DNS lookups, or multiple SPF records",
        Severity::Warning,
        true,
    ),
    check(
        "POL-02",
        "No DMARC record, or policy p=none",
        Severity::Notice,
        true,
    ),
    check("POL-03", "No CAA record", Severity::Notice, true),
    check(
        "POL-04",
        "MTA-STS record and policy file disagree, or policy unreachable",
        Severity::Warning,
        true,
    ),
    check(
        "POL-05",
        "MX target is a CNAME or does not resolve",
        Severity::Warning,
        true,
    ),
    check(
        "TKO-01",
        "CNAME target does not resolve (NXDOMAIN)",
        Severity::Warning,
        true,
    ),
    check(
        "TKO-02",
        "CNAME points to a hosting service that says the site is unclaimed",
        Severity::Critical,
        true,
    ),
    check(
        "TKO-03",
        "CNAME or MX target's domain is not registered",
        Severity::Critical,
        true,
    ),
    check(
        "TKO-04",
        "SPF include or redirect names an unregistered domain",
        Severity::Critical,
        true,
    ),
    check(
        "TKO-05",
        "Wildcard record is an alias of a name outside the zone",
        Severity::Notice,
        true,
    ),
    deep_check(
        "SEC-07",
        "NSEC3 with extra iterations or a salt",
        Severity::Notice,
    ),
    deep_check(
        "SEC-09",
        "CDS or CDNSKEY records inconsistent, or not matching the DNSKEY set",
        Severity::Warning,
    ),
    deep_check(
        "SEC-10",
        "An announced algorithm has no signatures over some record sets",
        Severity::Warning,
    ),
    deep_check(
        "NSB-01",
        "Server does not follow the EDNS rules",
        Severity::Warning,
    ),
    deep_check(
        "NSB-02",
        "Zone transfer allowed to anyone",
        Severity::Warning,
    ),
    deep_check(
        "NSB-03",
        "Recursion offered by an authoritative server",
        Severity::Warning,
    ),
    deep_check("NSB-04", "Query name case not preserved", Severity::Notice),
    deep_check(
        "NET-02",
        "Nameserver address in private or reserved space",
        Severity::Warning,
    ),
    deep_check("SOA-01", "SOA timers outside sane ranges", Severity::Notice),
    deep_check(
        "SOA-02",
        "SOA primary is not a listed nameserver, or has no address",
        Severity::Notice,
    ),
    deep_check(
        "SOA-03",
        "SOA contact is at a domain that takes no mail",
        Severity::Notice,
    ),
];

const fn deep_check(id: &'static str, title: &'static str, severity: Severity) -> CheckInfo {
    CheckInfo {
        id,
        title,
        severity,
        implemented: true,
        deep: true,
    }
}

/// True for a check that only a deep run makes.
pub fn is_deep(check_id: &str) -> bool {
    CATALOG.iter().any(|c| c.deep && c.id == check_id)
}

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
        deep: false,
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
    security::sec_01_ds_without_key,
    security::sec_02_signature_expiry,
    security::sec_03_signed_not_chained,
    security::sec_04_weak_algorithm,
    security::sec_05_signatures_differ,
    policy::pol_01_spf,
    policy::pol_02_dmarc,
    policy::pol_03_caa,
    policy::pol_04_mta_sts,
    policy::pol_05_mx_target,
    policy::tko_01_dangling_cname,
    policy::tko_02_unclaimed_service,
    policy::tko_03_unregistered_target,
    policy::tko_04_spf_unregistered,
    policy::tko_05_wildcard,
    deep::sec_07_nsec3_parameters,
    deep::sec_09_cds,
    deep::sec_10_algorithm_completeness,
    deep::nsb_01_edns_compliance,
    deep::nsb_02_open_transfer,
    deep::nsb_03_recursion,
    deep::nsb_04_case,
    deep::net_02_reserved_address,
    deep::soa_01_timers,
    deep::soa_02_mname,
    deep::soa_03_rname,
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
