//! The iterative resolver.
//!
//! Starts at the root hints and follows referrals down, one server at a time.
//! Unlike a normal resolver it keeps the intermediate answers: every referral,
//! the NS set in it and the glue that came with it.
//!
//! Recursion is never requested and no recursive resolver is ever asked.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};

use super::ResolveError;
use super::hints::root_servers;
use super::transport::{Client, QuerySpec, RawOutcome, record_type};
use crate::observe::{
    Glue, Lookup, QType, ReferralStep, Transport, Vantage, is_ancestor_or_equal, parent_name,
};

/// Upper bound on referrals followed for one name.
const MAX_REFERRALS: usize = 24;
/// Upper bound on nested lookups of nameserver addresses.
const MAX_DEPTH: usize = 4;
/// How many servers of one zone are tried before giving up on it.
const MAX_SERVERS_TRIED: usize = 4;

/// A lowercase, fully qualified form of a name.
pub(crate) fn norm(name: &Name) -> String {
    let mut s = printable(&name.to_ascii().to_ascii_lowercase());
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

/// Make text from the network safe to print and store.
///
/// DNS data is chosen by whoever runs the zone or its nameservers. Control
/// characters (which include the escape character that starts terminal
/// control sequences) and Unicode direction overrides are replaced with a
/// visible escape, so a record cannot rewrite or hide terminal output.
pub(crate) fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        // Direction overrides, and characters that are invisible or
        // break a line without being control characters.
        let direction_override = matches!(
            c,
            '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{2060}'..='\u{2069}'
                | '\u{061c}'
                | '\u{feff}'
        );
        if c.is_control() {
            // DNS presentation style: backslash and three decimal digits.
            out.push_str(&format!("\\{:03}", c as u32));
        } else if direction_override {
            out.push_str(&format!("\\u{{{:04x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// The standard mnemonic for a response code.
pub(crate) fn rcode_name(rcode: ResponseCode) -> String {
    match u16::from(rcode) {
        0 => "NOERROR".to_string(),
        1 => "FORMERR".to_string(),
        2 => "SERVFAIL".to_string(),
        3 => "NXDOMAIN".to_string(),
        4 => "NOTIMP".to_string(),
        5 => "REFUSED".to_string(),
        9 => "NOTAUTH".to_string(),
        16 => "BADVERS".to_string(),
        n => format!("RCODE{n}"),
    }
}

/// Parse a response and check it answers the question that was asked.
pub(crate) fn parse_response(spec: &QuerySpec, wire: &[u8]) -> Result<Message, String> {
    let msg = Message::from_vec(wire).map_err(|e| printable(&e.to_string()))?;
    if msg.metadata.message_type != MessageType::Response {
        return Err("not a response".to_string());
    }
    // Some servers drop the question on errors such as FORMERR; accept
    // that, but an answer without its question could be an answer to
    // anything.
    match msg.queries.first() {
        Some(q) if norm(q.name()) != spec.qname || q.query_type() != record_type(spec.qtype) => {
            return Err("response is for a different question".to_string());
        }
        None if msg.metadata.response_code == hickory_proto::op::ResponseCode::NoError => {
            return Err("response has no question section".to_string());
        }
        _ => {}
    }
    Ok(msg)
}

/// One nameserver of a zone and the addresses known for it.
#[derive(Debug, Clone)]
struct NsEntry {
    name: String,
    addrs: Vec<IpAddr>,
}

/// How a walk ended.
enum Terminal {
    /// A response with records in the answer section.
    Answer(Message),
    /// A referral to the name that was asked about (only with `stop_at_cut`).
    Delegation,
    NxDomain {
        enclosing: Option<String>,
    },
    NoData {
        enclosing: Option<String>,
    },
}

struct Walk {
    steps: Vec<ReferralStep>,
    terminal: Terminal,
}

/// What one usable response from a zone's server means.
enum Reply {
    Terminal(Terminal),
    Referral {
        cut: String,
        ns: Vec<String>,
        glue: Vec<Glue>,
    },
}

/// The result of resolving a hostname to addresses.
#[derive(Debug, Default, Clone)]
pub struct HostResolution {
    pub addresses: Vec<IpAddr>,
    pub cname: Option<String>,
    pub error: Option<String>,
}

/// What the walk towards a zone found.
#[derive(Debug)]
pub struct DelegationOutcome {
    /// Referrals from the root down. The last one delegates to the zone,
    /// unless `undelegated_ns` is set.
    pub path: Vec<ReferralStep>,
    /// Set when an ancestor's servers answered for the zone themselves, so no
    /// referral to the zone exists. Holds the NS set they answered with.
    pub undelegated_ns: Option<Vec<String>>,
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub struct Resolver {
    client: Arc<Client>,
    vantage: Vantage,
    /// Zone cut -> its nameservers, learned from referrals.
    cache: Mutex<HashMap<String, Vec<NsEntry>>>,
    /// Hostnames being resolved right now, to break dependency loops.
    visiting: Mutex<HashSet<String>>,
}

impl Resolver {
    pub fn new(client: Arc<Client>, vantage: Vantage) -> Self {
        let roots = root_servers()
            .into_iter()
            .map(|(name, addrs)| NsEntry { name, addrs })
            .collect();
        Self {
            client,
            vantage,
            cache: Mutex::new(HashMap::from([(".".to_string(), roots)])),
            visiting: Mutex::new(HashSet::new()),
        }
    }

    /// Walk from the root to `zone` and record every referral on the way.
    pub async fn find_delegation(&self, zone: &str) -> Result<DelegationOutcome, ResolveError> {
        let walk = self.walk(zone, QType::Ns, true, 0).await?;
        match walk.terminal {
            Terminal::Delegation => Ok(DelegationOutcome {
                path: walk.steps,
                undelegated_ns: None,
            }),
            Terminal::Answer(msg) => {
                let mut ns: Vec<String> = msg
                    .answers
                    .iter()
                    .filter(|r| norm(&r.name) == zone)
                    .filter_map(|r| match &r.data {
                        RData::NS(ns) => Some(norm(&ns.0)),
                        _ => None,
                    })
                    .collect();
                if ns.is_empty() {
                    // A CNAME or similar: the name exists but is not a zone.
                    return Err(ResolveError::NotAZone {
                        name: zone.to_string(),
                        enclosing: None,
                    });
                }
                ns.sort();
                ns.dedup();
                Ok(DelegationOutcome {
                    path: walk.steps,
                    undelegated_ns: Some(ns),
                })
            }
            Terminal::NxDomain { .. } => Err(ResolveError::ZoneNotFound {
                zone: zone.to_string(),
            }),
            Terminal::NoData { enclosing } => Err(ResolveError::NotAZone {
                name: zone.to_string(),
                enclosing,
            }),
        }
    }

    /// Resolve a hostname to its addresses, from the root, following CNAMEs.
    pub fn resolve_host(&self, name: String, depth: usize) -> BoxFuture<'_, HostResolution> {
        Box::pin(async move {
            let mut res = HostResolution::default();
            if depth > MAX_DEPTH {
                res.error = Some("nameserver address lookups nested too deeply".to_string());
                return res;
            }
            if !self.visiting.lock().expect("lock").insert(name.clone()) {
                res.error = Some("resolution loop".to_string());
                return res;
            }
            for qtype in [QType::A, QType::Aaaa] {
                match self.walk(&name, qtype, false, depth).await {
                    Ok(Walk {
                        terminal: Terminal::Answer(msg),
                        ..
                    }) => {
                        let (addrs, target) = follow_answer(&msg, &name);
                        let found = !addrs.is_empty();
                        res.addresses.extend(addrs);
                        if target != name {
                            res.cname.get_or_insert(first_cname(&msg, &name));
                            if !found {
                                // The alias target lives elsewhere; resolve it
                                // for both families and stop.
                                let sub = self.resolve_host(target, depth + 1).await;
                                res.addresses.extend(sub.addresses);
                                res.error = sub.error;
                                break;
                            }
                        }
                    }
                    Ok(Walk {
                        terminal: Terminal::NxDomain { .. },
                        ..
                    }) => {
                        res.error = Some("NXDOMAIN".to_string());
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => res.error = Some(e.to_string()),
                }
            }
            self.visiting.lock().expect("lock").remove(&name);
            res.addresses.sort();
            res.addresses.dedup();
            if !res.addresses.is_empty() {
                res.error = None;
            } else if res.error.is_none() {
                res.error = Some("no address records".to_string());
            }
            res
        })
    }

    /// Resolve one name and type from the root and say what was found.
    /// A CNAME at the name is reported, and followed inside the same answer.
    pub async fn lookup(&self, name: &str, qtype: QType) -> Lookup {
        let mut out = Lookup {
            name: name.to_string(),
            qtype,
            status: "failed".to_string(),
            rdata: Vec::new(),
            cname: None,
            enclosing: None,
            error: None,
        };
        match self.walk(name, qtype, false, 0).await {
            Ok(Walk {
                terminal: Terminal::Answer(msg),
                ..
            }) => {
                let mut owner = name.to_string();
                for _ in 0..8 {
                    let next = msg.answers.iter().find_map(|rec| match &rec.data {
                        RData::CNAME(c) if norm(&rec.name) == owner => Some(norm(&c.0)),
                        _ => None,
                    });
                    match next {
                        Some(next) if next != owner => {
                            out.cname.get_or_insert(next.clone());
                            owner = next;
                        }
                        _ => break,
                    }
                }
                let wanted = record_type(qtype);
                out.rdata = msg
                    .answers
                    .iter()
                    .filter(|rec| rec.record_type() == wanted && norm(&rec.name) == owner)
                    .map(|rec| super::probe::rdata_text(&rec.data))
                    .collect();
                out.rdata.sort();
                out.rdata.dedup();
                out.status = if out.rdata.is_empty() && out.cname.is_none() {
                    "nodata"
                } else {
                    "answer"
                }
                .to_string();
            }
            Ok(Walk {
                terminal: Terminal::NxDomain { enclosing },
                ..
            }) => {
                out.status = "nxdomain".to_string();
                out.enclosing = enclosing;
            }
            Ok(Walk {
                terminal: Terminal::NoData { enclosing },
                ..
            }) => {
                out.status = "nodata".to_string();
                out.enclosing = enclosing;
            }
            Ok(_) => out.error = Some("unexpected referral".to_string()),
            Err(e) => out.error = Some(e.to_string()),
        }
        out
    }

    /// Follow referrals for `qname` until something other than a referral
    /// comes back. With `stop_at_cut`, stop at the referral that delegates
    /// `qname` itself, without asking the child.
    async fn walk(
        &self,
        qname: &str,
        qtype: QType,
        stop_at_cut: bool,
        depth: usize,
    ) -> Result<Walk, ResolveError> {
        let (mut zone, mut entries) = self.closest_cached(qname, stop_at_cut);
        let mut steps = Vec::new();
        for _ in 0..MAX_REFERRALS {
            let (reply, server_name, server_address) =
                self.ask_zone(&zone, &entries, qname, qtype, depth).await?;
            match reply {
                Reply::Terminal(terminal) => return Ok(Walk { steps, terminal }),
                Reply::Referral { cut, ns, glue } => {
                    entries = ns
                        .iter()
                        .map(|name| NsEntry {
                            name: name.clone(),
                            addrs: glue
                                .iter()
                                .filter(|g| &g.name == name)
                                .map(|g| g.address)
                                .collect(),
                        })
                        .collect();
                    self.cache
                        .lock()
                        .expect("lock")
                        .insert(cut.clone(), entries.clone());
                    steps.push(ReferralStep {
                        from_zone: zone,
                        to_zone: cut.clone(),
                        server_name: Some(server_name),
                        server_address,
                        ns,
                        glue,
                    });
                    if stop_at_cut && cut == qname {
                        return Ok(Walk {
                            steps,
                            terminal: Terminal::Delegation,
                        });
                    }
                    zone = cut;
                }
            }
        }
        Err(ResolveError::TooManyReferrals {
            name: qname.to_string(),
        })
    }

    /// The deepest zone cut already known on the way to `qname`.
    fn closest_cached(&self, qname: &str, stop_at_cut: bool) -> (String, Vec<NsEntry>) {
        let cache = self.cache.lock().expect("lock");
        let mut name = if stop_at_cut {
            parent_name(qname)
        } else {
            qname
        };
        loop {
            if let Some(entries) = cache.get(name) {
                return (name.to_string(), entries.clone());
            }
            // The root is always cached, so this ends.
            name = parent_name(name);
        }
    }

    /// Ask the servers of `zone` in turn until one gives a usable reply.
    async fn ask_zone(
        &self,
        zone: &str,
        entries: &[NsEntry],
        qname: &str,
        qtype: QType,
        depth: usize,
    ) -> Result<(Reply, String, IpAddr), ResolveError> {
        let mut candidates = self.candidates(entries);
        if candidates.is_empty() && depth < MAX_DEPTH {
            // A glueless delegation: resolve nameserver names until one works.
            for entry in entries.iter().take(3) {
                let res = self.resolve_host(entry.name.clone(), depth + 1).await;
                if res.addresses.is_empty() {
                    continue;
                }
                let resolved = [NsEntry {
                    name: entry.name.clone(),
                    addrs: res.addresses,
                }];
                candidates = self.candidates(&resolved);
                if !candidates.is_empty() {
                    break;
                }
            }
        }
        if candidates.is_empty() {
            return Err(ResolveError::ServersFailed {
                zone: zone.to_string(),
                detail: "no nameserver address could be found".to_string(),
            });
        }
        let mut errors = Vec::new();
        for (name, addr) in candidates.into_iter().take(MAX_SERVERS_TRIED) {
            match self.ask(addr, qname, qtype).await {
                Ok(msg) => match classify(msg, zone, qname) {
                    Ok(reply) => return Ok((reply, name, addr)),
                    Err(why) => errors.push(format!("{addr}: {why}")),
                },
                Err(why) => errors.push(format!("{addr}: {why}")),
            }
        }
        Err(ResolveError::ServersFailed {
            zone: zone.to_string(),
            detail: errors.join("; "),
        })
    }

    /// Addresses to try, reachable families only, IPv4 before IPv6.
    fn candidates(&self, entries: &[NsEntry]) -> Vec<(String, IpAddr)> {
        let mut out: Vec<(String, IpAddr)> = entries
            .iter()
            .flat_map(|e| e.addrs.iter().map(|a| (e.name.clone(), *a)))
            .filter(|(_, a)| self.vantage.can_reach(a))
            .collect();
        out.sort_by_key(|(_, a)| a.is_ipv6());
        out
    }

    /// One question to one server: UDP with EDNS, without EDNS if the server
    /// rejects it, and TCP if the answer is truncated.
    async fn ask(&self, server: IpAddr, qname: &str, qtype: QType) -> Result<Message, String> {
        let mut spec = QuerySpec {
            server,
            transport: Transport::Udp,
            qname: qname.to_string(),
            qtype,
            edns: true,
            dnssec: false,
            probe: Default::default(),
        };
        let mut msg = self.send(&spec).await?;
        if msg.metadata.response_code == ResponseCode::FormErr {
            spec.edns = false;
            msg = self.send(&spec).await?;
        }
        if msg.metadata.truncation {
            spec.transport = Transport::Tcp;
            msg = self.send(&spec).await?;
        }
        Ok(msg)
    }

    async fn send(&self, spec: &QuerySpec) -> Result<Message, String> {
        match self.client.exchange(spec).await {
            RawOutcome::Response { wire } => parse_response(spec, &wire),
            RawOutcome::Timeout => Err("timeout".to_string()),
            RawOutcome::NetError { message } => Err(message),
        }
    }
}

/// Decide what a response from a server of `zone` means for `qname`.
/// `Err` means the server is no use and the next one should be tried.
fn classify(msg: Message, zone: &str, qname: &str) -> Result<Reply, String> {
    let rcode = msg.metadata.response_code;
    let aa = msg.metadata.authoritative;
    match rcode {
        ResponseCode::NXDomain if aa => {
            return Ok(Reply::Terminal(Terminal::NxDomain {
                enclosing: soa_owner(&msg),
            }));
        }
        ResponseCode::NoError => {}
        other => return Err(rcode_name(other)),
    }
    if !msg.answers.is_empty() {
        return Ok(Reply::Terminal(Terminal::Answer(msg)));
    }
    let mut ns = Vec::new();
    let mut cut: Option<String> = None;
    for rec in &msg.authorities {
        if let RData::NS(target) = &rec.data {
            let owner = norm(&rec.name);
            if cut.get_or_insert_with(|| owner.clone()) == &owner {
                ns.push(norm(&target.0));
            }
        }
    }
    if let Some(cut) = cut {
        // A real referral points strictly downwards, towards the name asked.
        if cut != zone && is_ancestor_or_equal(zone, &cut) && is_ancestor_or_equal(&cut, qname) {
            ns.sort();
            ns.dedup();
            let mut glue: Vec<Glue> = msg
                .additionals
                .iter()
                .filter_map(|rec| {
                    let address = match &rec.data {
                        RData::A(a) => IpAddr::V4(a.0),
                        RData::AAAA(a) => IpAddr::V6(a.0),
                        _ => return None,
                    };
                    let name = norm(&rec.name);
                    ns.contains(&name).then_some(Glue { name, address })
                })
                .collect();
            glue.sort();
            glue.dedup();
            return Ok(Reply::Referral { cut, ns, glue });
        }
    }
    if aa {
        return Ok(Reply::Terminal(Terminal::NoData {
            enclosing: soa_owner(&msg),
        }));
    }
    Err("not authoritative and no referral (lame)".to_string())
}

/// The owner of the SOA in the authority section of a negative answer.
fn soa_owner(msg: &Message) -> Option<String> {
    msg.authorities
        .iter()
        .find(|r| r.record_type() == RecordType::SOA)
        .map(|r| norm(&r.name))
}

/// Collect the addresses for `name` in an answer, following any CNAME chain
/// inside the same response. Returns the addresses and the last name reached.
fn follow_answer(msg: &Message, name: &str) -> (Vec<IpAddr>, String) {
    let mut target = name.to_string();
    for _ in 0..8 {
        let next = msg.answers.iter().find_map(|rec| match &rec.data {
            RData::CNAME(c) if norm(&rec.name) == target => Some(norm(&c.0)),
            _ => None,
        });
        match next {
            Some(next) if next != target => target = next,
            _ => break,
        }
    }
    let addrs = msg
        .answers
        .iter()
        .filter(|rec| norm(&rec.name) == target)
        .filter_map(|rec| match &rec.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect();
    (addrs, target)
}

fn first_cname(msg: &Message, name: &str) -> String {
    msg.answers
        .iter()
        .find_map(|rec| match &rec.data {
            RData::CNAME(c) if norm(&rec.name) == name => Some(norm(&c.0)),
            _ => None,
        })
        .unwrap_or_default()
}
