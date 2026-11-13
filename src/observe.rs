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

/// How a query was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Udp,
    Tcp,
}

/// The record types Phase 0 asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum QType {
    Soa,
    Ns,
    A,
    Aaaa,
}

impl QType {
    pub fn as_str(self) -> &'static str {
        match self {
            QType::Soa => "SOA",
            QType::Ns => "NS",
            QType::A => "A",
            QType::Aaaa => "AAAA",
        }
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
