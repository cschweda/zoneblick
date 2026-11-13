//! The recorded observations of one run.
//!
//! Everything here is plain data. The resolver fills it in; the checks read
//! it. Names are stored as lowercase, fully qualified strings with a trailing
//! dot (`example.com.`), so checks can compare them directly.
//!
//! Each server's answers are kept separately. Nothing in this module merges
//! answers from different servers.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::dnssec::{Dnskey, Ds, Rrsig};

/// How a query was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Udp,
    Tcp,
}

/// The record types zoneblick asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum QType {
    Soa,
    Ns,
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Caa,
    Ds,
    Dnskey,
    Nsec3param,
    Cds,
    Cdnskey,
}

impl QType {
    /// The types asked for every name in a stored run. SOA and NS are asked
    /// at the apex only, by the nameserver probes.
    pub const SWEEP: [QType; 6] = [
        QType::A,
        QType::Aaaa,
        QType::Cname,
        QType::Mx,
        QType::Txt,
        QType::Caa,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            QType::Soa => "SOA",
            QType::Ns => "NS",
            QType::A => "A",
            QType::Aaaa => "AAAA",
            QType::Cname => "CNAME",
            QType::Mx => "MX",
            QType::Txt => "TXT",
            QType::Caa => "CAA",
            QType::Ds => "DS",
            QType::Dnskey => "DNSKEY",
            QType::Nsec3param => "NSEC3PARAM",
            QType::Cds => "CDS",
            QType::Cdnskey => "CDNSKEY",
        }
    }

    pub fn parse(s: &str) -> Option<QType> {
        [
            QType::Soa,
            QType::Ns,
            QType::A,
            QType::Aaaa,
            QType::Cname,
            QType::Mx,
            QType::Txt,
            QType::Caa,
            QType::Ds,
            QType::Dnskey,
            QType::Nsec3param,
            QType::Cds,
            QType::Cdnskey,
        ]
        .into_iter()
        .find(|t| t.as_str() == s)
    }
}

/// An unusual way of asking, used by the deep probes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Probe {
    /// An ordinary query.
    #[default]
    Plain,
    /// EDNS version 1, which does not exist yet: the answer must be BADVERS.
    EdnsVersion1,
    /// An EDNS option nobody has defined: it must be ignored.
    EdnsUnknownOption,
    /// The "recursion desired" flag is set.
    Recursion,
    /// The query name is sent in mixed upper and lower case.
    MixedCase,
}

impl Probe {
    pub fn is_plain(&self) -> bool {
        *self == Probe::Plain
    }
}

/// Which address families worked from the machine running the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vantage {
    pub ipv4: bool,
    pub ipv6: bool,
}

impl Vantage {
    pub fn can_reach(&self, addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(_) => self.ipv4,
            IpAddr::V6(_) => self.ipv6,
        }
    }
}

/// An address record handed out by a parent alongside a referral.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Glue {
    pub name: String,
    pub address: IpAddr,
}

/// One referral followed on the way from the root to the zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferralStep {
    /// The zone whose server was asked.
    pub from_zone: String,
    /// The zone the referral delegates to.
    pub to_zone: String,
    /// The server that gave the referral.
    pub server_name: Option<String>,
    pub server_address: IpAddr,
    /// The NS set in the referral, sorted.
    pub ns: Vec<String>,
    /// The glue in the referral, sorted.
    pub glue: Vec<Glue>,
}

/// One nameserver hostname of the zone and what is known about its addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsHost {
    pub name: String,
    /// Listed in the parent's delegation.
    pub in_parent: bool,
    /// Listed in the NS set served by at least one authoritative server.
    pub in_child: bool,
    /// Glue addresses the parent gave for this name.
    pub glue: Vec<IpAddr>,
    /// Addresses found by resolving the name from the root.
    pub resolved: Vec<IpAddr>,
    /// Set when the name is an alias; holds the first CNAME target.
    pub cname: Option<String>,
    /// Why resolving the name failed, when it did.
    pub resolve_error: Option<String>,
}

impl NsHost {
    /// Every address known for this host, glue and resolved, sorted and unique.
    pub fn addresses(&self) -> Vec<IpAddr> {
        let set: BTreeSet<IpAddr> = self.glue.iter().chain(&self.resolved).copied().collect();
        set.into_iter().collect()
    }
}

/// The SOA record as one server returned it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Soa {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
}

/// What one server said in one response.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResponseObs {
    /// Response code mnemonic, for example `NOERROR` or `REFUSED`.
    pub rcode: String,
    /// The AA flag.
    pub authoritative: bool,
    /// The TC flag.
    pub truncated: bool,
    /// The response carried an EDNS OPT record.
    pub opt_present: bool,
    /// Size of the response in bytes.
    pub size: usize,
    /// The zone's SOA from the answer section, if present.
    pub soa: Option<Soa>,
    /// The zone's NS targets from the answer section, sorted.
    pub ns: Vec<String>,
}

impl ResponseObs {
    /// An authoritative, successful answer.
    pub fn is_authoritative_answer(&self) -> bool {
        self.authoritative && self.rcode == "NOERROR"
    }
}

/// The result of one query to one server.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    Response(ResponseObs),
    Timeout,
    NetError { message: String },
    Malformed { message: String },
}

impl Outcome {
    pub fn response(&self) -> Option<&ResponseObs> {
        match self {
            Outcome::Response(r) => Some(r),
            _ => None,
        }
    }

    /// A short label for evidence and terminal output.
    pub fn label(&self) -> String {
        match self {
            Outcome::Response(r) => {
                let mut s = r.rcode.clone();
                if r.authoritative {
                    s.push_str(" aa");
                }
                if r.truncated {
                    s.push_str(" tc");
                }
                s
            }
            Outcome::Timeout => "timeout".to_string(),
            Outcome::NetError { message } => format!("network error: {message}"),
            Outcome::Malformed { message } => format!("malformed response: {message}"),
        }
    }
}

/// One query sent to one address of one nameserver, and its outcome.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServerProbe {
    pub ns_name: String,
    pub address: IpAddr,
    pub qtype: QType,
    pub transport: Transport,
    pub edns: bool,
    pub outcome: Outcome,
}

/// One server's answer for one name and type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecordAnswer {
    /// Response code mnemonic.
    pub rcode: String,
    /// The AA flag.
    pub authoritative: bool,
    /// The lowest TTL in the record set, when there are records.
    pub ttl: Option<u32>,
    /// The record data in canonical text form, sorted and unique. Names are
    /// lowercase. Empty when the server has no such records.
    pub rdata: Vec<String>,
}

/// The result of asking one server for one name and type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecordOutcome {
    Answer(RecordAnswer),
    Timeout,
    NetError { message: String },
    Malformed { message: String },
}

impl RecordOutcome {
    pub fn answer(&self) -> Option<&RecordAnswer> {
        match self {
            RecordOutcome::Answer(a) => Some(a),
            _ => None,
        }
    }
}

/// One record set as one nameserver address served it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecordObservation {
    pub name: String,
    pub qtype: QType,
    pub ns_name: String,
    pub address: IpAddr,
    pub transport: Transport,
    pub outcome: RecordOutcome,
}

/// The DS set for the zone, as one server of the parent zone served it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentDs {
    pub parent_zone: String,
    pub server_name: Option<String>,
    pub server_address: IpAddr,
    /// `None` when the parent gave no usable answer; then `error` says why.
    /// An empty list means the parent has no DS for the zone.
    pub records: Option<Vec<Ds>>,
    pub error: Option<String>,
}

/// The DNSSEC data one nameserver address served for the zone apex.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServerDnssec {
    pub ns_name: String,
    pub address: IpAddr,
    /// `None` when the server gave no authoritative answer. An empty list
    /// means it has no DNSKEY for the zone.
    pub dnskeys: Option<Vec<Dnskey>>,
    /// Signatures over the DNSKEY set.
    pub dnskey_sigs: Vec<Rrsig>,
    /// Signatures over the SOA record; `None` when the server gave no
    /// authoritative SOA answer to the signed query.
    pub soa_sigs: Option<Vec<Rrsig>>,
    /// Whether a signature over the DNSKEY set verifies with a published
    /// key: `valid`, `invalid`, or `untried` when none could be tried.
    /// `None` when there was nothing to verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnskey_sig_status: Option<String>,
    /// The same for the SOA record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soa_sig_status: Option<String>,
}

/// What was observed about the zone's DNSSEC setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnssecObservation {
    /// The parent's DS set; `None` when no parent referral was seen.
    pub parent_ds: Option<ParentDs>,
    pub servers: Vec<ServerDnssec>,
}

/// The result of resolving one name and type from the root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lookup {
    pub name: String,
    pub qtype: QType,
    /// `answer`, `nodata`, `nxdomain` or `failed`.
    pub status: String,
    /// Record data in canonical text form, sorted.
    pub rdata: Vec<String>,
    /// The CNAME target, when the name is an alias.
    pub cname: Option<String>,
    /// For `nodata` and `nxdomain`: the zone whose server said so.
    pub enclosing: Option<String>,
    /// For `failed`: why.
    pub error: Option<String>,
}

impl Lookup {
    pub fn exists(&self) -> bool {
        self.status == "answer"
    }

    /// The server answered, and there is nothing there.
    pub fn is_empty_answer(&self) -> bool {
        matches!(self.status.as_str(), "nodata" | "nxdomain")
    }

    /// The name does not exist, and the server that said so belongs to a
    /// top-level domain: the domain itself is not delegated, which means it
    /// is unregistered or has expired. Returns that domain.
    pub fn unregistered_domain(&self) -> Option<String> {
        if self.status != "nxdomain" {
            return None;
        }
        let tld = self.enclosing.as_deref()?;
        if tld == "." || tld.matches('.').count() != 1 {
            return None;
        }
        let rest = self.name.strip_suffix(tld)?.trim_end_matches('.');
        let label = rest.rsplit('.').next().filter(|l| !l.is_empty())?;
        Some(format!("{label}.{tld}"))
    }
}

/// One DNS lookup an SPF record causes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpfLookup {
    /// `include`, `redirect`, `a`, `mx`, `exists` or `ptr`.
    pub mechanism: String,
    pub domain: String,
    /// 0 for the zone's own record, 1 for a record it includes, and so on.
    pub depth: usize,
    /// For `include` and `redirect`: the lookup of the target's SPF record.
    pub target: Option<Lookup>,
}

/// The zone's SPF setup, followed through its includes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpfObservation {
    /// Every TXT record at the apex that starts with `v=spf1`.
    pub records: Vec<String>,
    /// The lookups evaluating the (first) record causes, in order.
    pub lookups: Vec<SpfLookup>,
    /// True when following includes was cut short.
    pub truncated: bool,
}

/// The zone's MTA-STS record and the policy file it points at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtaSts {
    /// The `_mta-sts` TXT record.
    pub record: String,
    pub policy_url: String,
    /// HTTP status of the policy fetch; `None` when the fetch failed.
    pub http_status: Option<u16>,
    pub error: Option<String>,
    pub version: Option<String>,
    pub mode: Option<String>,
    pub max_age: Option<String>,
    /// The `mx:` patterns in the policy.
    pub mx_patterns: Vec<String>,
}

/// What a mail exchanger or alias target resolves to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetResolution {
    /// The record that names the target.
    pub owner: String,
    /// `MX` or `CNAME`.
    pub rtype: String,
    pub target: String,
    /// The address lookup of the target.
    pub lookup: Lookup,
    /// True when an AAAA lookup found addresses although A did not.
    pub has_ipv6_only: bool,
}

/// What a hosting service answered for a hostname that is an alias of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceProbe {
    /// The hostname in the zone.
    pub owner: String,
    /// The alias target that belongs to the service.
    pub target: String,
    pub service: String,
    pub url: String,
    /// HTTP status; `None` when the fetch failed.
    pub status: Option<u16>,
    pub error: Option<String>,
    /// True when the answer is the service's "nobody has claimed this".
    pub unclaimed: bool,
}

/// Mail and policy records, and where mail and alias targets lead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyObservation {
    pub apex_txt: Lookup,
    pub dmarc: Lookup,
    pub caa: Lookup,
    pub mx: Lookup,
    pub spf: Option<SpfObservation>,
    pub mta_sts: Option<MtaSts>,
    /// Where each MX target and each collected CNAME leads, and each
    /// nameserver hostname outside the zone that has no address (`NS`).
    pub targets: Vec<TargetResolution>,
    /// The lookup of `*.<zone>`: what a name nobody created resolves to.
    /// `None` in observations built before it was collected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wildcard: Option<Lookup>,
    /// What known hosting services answered for the aliases that point at
    /// them. Filled in by `run`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ServiceProbe>,
}

/// The answer to one deep probe.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProbeAnswer {
    /// The response code; `None` when there was no usable response.
    pub rcode: Option<String>,
    /// The response carried an EDNS OPT record.
    pub opt_present: bool,
    /// Why there was no usable response.
    pub error: Option<String>,
}

/// An NSEC3PARAM record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Nsec3Param {
    pub algorithm: u8,
    pub iterations: u16,
    /// The salt in lowercase hex; empty for no salt.
    pub salt: String,
}

/// The answer to a signed query for a name that should not exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denial {
    pub qname: String,
    pub rcode: String,
    /// The name got an answer after all (a wildcard matches it).
    pub answered: bool,
    /// The NSEC records given as proof: owner and next name.
    pub nsec: Vec<(String, String)>,
    /// How many NSEC3 records were given as proof.
    pub nsec3: usize,
    /// A signature over an NSEC or NSEC3 record came with them.
    pub signed: bool,
}

/// What the deep probes found at one nameserver address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerDeep {
    pub ns_name: String,
    pub address: IpAddr,
    pub edns_version: ProbeAnswer,
    pub edns_option: ProbeAnswer,
    /// The RA flag on the answer to a query that asked for recursion.
    pub recursion_available: Option<bool>,
    /// The answer repeated the query name in the case it was sent in.
    pub case_preserved: Option<bool>,
    /// A zone transfer was started for us. `None` when not tried.
    pub axfr_allowed: Option<bool>,
    /// `None` when the server gave no authoritative answer.
    pub nsec3param: Option<Vec<Nsec3Param>>,
    pub cds: Option<Vec<crate::dnssec::Ds>>,
    pub cdnskey: Option<Vec<crate::dnssec::Dnskey>>,
    /// `None` when the server gave no authoritative answer.
    #[serde(default)]
    pub denial: Option<Denial>,
}

/// The network that announces a nameserver address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressOrigin {
    pub address: IpAddr,
    /// The autonomous system numbers announcing it; empty when unknown.
    pub asns: Vec<u32>,
    /// The announced prefix the address falls in.
    pub prefix: Option<String>,
}

/// What a deep run collects on top of a light one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeepObservation {
    pub servers: Vec<ServerDeep>,
    /// The address lookup of the primary named in the SOA record.
    pub mname: Option<Lookup>,
    /// The mail domain of the SOA contact, and its MX and address lookups.
    pub rname_domain: Option<String>,
    pub rname_mx: Option<Lookup>,
    pub rname_address: Option<Lookup>,
    /// The DNSKEY set of the zone's previous stored run, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_dnskeys: Option<Vec<crate::dnssec::Dnskey>>,
    /// Which network announces each nameserver address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub origins: Vec<AddressOrigin>,
}

/// Everything recorded about one zone in one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneObservation {
    pub zone: String,
    pub started_at_unix: u64,
    pub vantage: Vantage,
    /// Referrals followed from the root, in order. When the last step
    /// delegates to `zone`, it is the parent's view of the delegation.
    pub delegation_path: Vec<ReferralStep>,
    /// Nameserver hostnames, from the parent and from the zone itself.
    pub ns_hosts: Vec<NsHost>,
    /// Every apex query sent to every nameserver address.
    pub probes: Vec<ServerProbe>,
    /// Record sets per name, type and server. Filled in by `run`, which
    /// stores a snapshot; empty for a plain `check`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<RecordObservation>,
    /// DNSSEC data: the parent's DS set and each server's keys and
    /// signatures. `None` in observations built before it was collected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnssec: Option<DnssecObservation>,
    /// Mail and policy records and alias targets. `None` in observations
    /// built before they were collected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyObservation>,
    /// The deep probes. `None` for a light run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deep: Option<DeepObservation>,
}

impl ZoneObservation {
    /// The parent's delegation for the zone, when one was observed.
    ///
    /// It is absent when the servers of an ancestor zone answer for the zone
    /// themselves, so no referral is ever seen (the root zone is one example).
    pub fn parent(&self) -> Option<&ReferralStep> {
        self.delegation_path
            .last()
            .filter(|s| s.to_zone == self.zone)
    }

    /// Probes sent to one address.
    pub fn probes_for(&self, address: IpAddr) -> impl Iterator<Item = &ServerProbe> {
        self.probes.iter().filter(move |p| p.address == address)
    }
}

/// True when `ancestor` is `name` or a parent of it. Both are normalised names.
pub fn is_ancestor_or_equal(ancestor: &str, name: &str) -> bool {
    if ancestor == "." || ancestor == name {
        return true;
    }
    name.len() > ancestor.len()
        && name.ends_with(ancestor)
        && name.as_bytes()[name.len() - ancestor.len() - 1] == b'.'
}

/// The parent of a normalised name; the root is its own parent.
pub fn parent_name(name: &str) -> &str {
    if name == "." {
        return ".";
    }
    match name.find('.') {
        Some(i) if i + 1 < name.len() => &name[i + 1..],
        _ => ".",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestry() {
        assert!(is_ancestor_or_equal(".", "example.com."));
        assert!(is_ancestor_or_equal("com.", "example.com."));
        assert!(is_ancestor_or_equal("example.com.", "example.com."));
        assert!(!is_ancestor_or_equal("ample.com.", "example.com."));
        assert!(!is_ancestor_or_equal("example.com.", "com."));
        assert!(!is_ancestor_or_equal("org.", "example.com."));
    }

    #[test]
    fn parents() {
        assert_eq!(parent_name("www.example.com."), "example.com.");
        assert_eq!(parent_name("com."), ".");
        assert_eq!(parent_name("."), ".");
    }

    #[test]
    fn outcome_json_is_tagged() {
        let json = serde_json::to_string(&Outcome::Timeout).unwrap();
        assert_eq!(json, r#"{"kind":"timeout"}"#);
        let r = Outcome::Response(ResponseObs {
            rcode: "NOERROR".into(),
            authoritative: true,
            truncated: false,
            opt_present: true,
            size: 100,
            soa: None,
            ns: vec![],
        });
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.starts_with(r#"{"kind":"response","rcode":"NOERROR""#));
        assert_eq!(serde_json::from_str::<Outcome>(&json).unwrap(), r);
    }
}
