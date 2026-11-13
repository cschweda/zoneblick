//! Hand-built DNS worlds for offline tests.
//!
//! A [`World`] is a set of canned responses, built with real DNS messages and
//! turned into a [`Fixture`] that the replay client answers from. Zones live
//! under `example.`, which is reserved (RFC 2606), and servers use the
//! documentation address ranges (RFC 5737, RFC 3849).

#![allow(dead_code)]

use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::op::{Edns, Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use zoneblick::observe::{QType, Transport, ZoneObservation};
use zoneblick::resolver::{
    Client, Exchange, Fixture, QuerySpec, RawOutcome, ResolveError, observe_zone,
};

pub const ROOT_V4: &str = "198.41.0.4";
pub const ROOT_V6: &str = "2001:503:ba3e::2:30";
pub const TLD_SERVER: &str = "192.0.2.1";
pub const STARTED_AT: u64 = 1_700_000_000;

/// The three ways a query can be sent: (transport, edns).
const VARIANTS: [(Transport, bool); 3] = [
    (Transport::Udp, true),
    (Transport::Udp, false),
    (Transport::Tcp, true),
];

pub fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

pub fn ns(owner: &str, target: &str) -> Record {
    Record::from_rdata(name(owner), 3600, RData::NS(NS(name(target))))
}

pub fn addr(owner: &str, ip: &str) -> Record {
    let rdata = match ip.parse::<IpAddr>().unwrap() {
        IpAddr::V4(v4) => RData::A(A(v4)),
        IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
    };
    Record::from_rdata(name(owner), 3600, rdata)
}

pub fn cname(owner: &str, target: &str) -> Record {
    Record::from_rdata(name(owner), 3600, RData::CNAME(CNAME(name(target))))
}

pub fn mx(owner: &str, preference: u16, target: &str) -> Record {
    Record::from_rdata(
        name(owner),
        3600,
        RData::MX(MX::new(preference, name(target))),
    )
}

pub fn txt(owner: &str, text: &str) -> Record {
    Record::from_rdata(
        name(owner),
        3600,
        RData::TXT(TXT::new(vec![text.to_string()])),
    )
}

pub fn soa(owner: &str, serial: u32) -> Record {
    let mname = format!("ns1.{owner}");
    let rname = format!("hostmaster.{owner}");
    let rdata = SOA::new(
        name(&mname),
        name(&rname),
        serial,
        7200,
        3600,
        1209600,
        3600,
    );
    Record::from_rdata(name(owner), 3600, RData::SOA(rdata))
}

fn record_type(qtype: QType) -> RecordType {
    match qtype {
        QType::Soa => RecordType::SOA,
        QType::Ns => RecordType::NS,
        QType::A => RecordType::A,
        QType::Aaaa => RecordType::AAAA,
        QType::Cname => RecordType::CNAME,
        QType::Mx => RecordType::MX,
        QType::Txt => RecordType::TXT,
        QType::Caa => RecordType::CAA,
    }
}

#[derive(Default)]
pub struct World {
    exchanges: Vec<Exchange>,
}

impl World {
    /// A world where the root answers over IPv4 only.
    pub fn new() -> Self {
        let mut w = World::default();
        w.answer(ROOT_V4, ".", QType::Ns, &[ns(".", "a.root-servers.net.")]);
        w
    }

    /// Also let the root answer over IPv6, so IPv6 counts as working.
    pub fn with_ipv6(mut self) -> Self {
        self.answer(ROOT_V6, ".", QType::Ns, &[ns(".", "a.root-servers.net.")]);
        self
    }

    /// Set the raw outcome for one exact query. A later call replaces an
    /// earlier one for the same query.
    pub fn outcome(
        &mut self,
        server: &str,
        transport: Transport,
        edns: bool,
        qname: &str,
        qtype: QType,
        outcome: RawOutcome,
    ) {
        let query = QuerySpec {
            server: server.parse().unwrap(),
            transport,
            qname: qname.to_string(),
            qtype,
            edns,
        };
        self.exchanges.retain(|e| e.query != query);
        self.exchanges.push(Exchange { query, outcome });
    }

    /// Answer a query with a message, for one transport and EDNS setting.
    /// The reply carries an OPT record exactly when the query did.
    pub fn reply_on(
        &mut self,
        server: &str,
        transport: Transport,
        edns: bool,
        qname: &str,
        qtype: QType,
        build: impl Fn(&mut Message),
    ) {
        let mut msg = Message::response(0, OpCode::Query);
        msg.add_query(Query::query(name(qname), record_type(qtype)));
        if edns {
            let mut opt = Edns::new();
            opt.set_max_payload(1232);
            msg.set_edns(opt);
        }
        build(&mut msg);
        let wire = msg.to_vec().unwrap();
        self.outcome(
            server,
            transport,
            edns,
            qname,
            qtype,
            RawOutcome::Response { wire },
        );
    }

    /// Answer a query the same way however it is sent.
    pub fn reply(&mut self, server: &str, qname: &str, qtype: QType, build: impl Fn(&mut Message)) {
        for (transport, edns) in VARIANTS {
            self.reply_on(server, transport, edns, qname, qtype, &build);
        }
    }

    /// An authoritative answer.
    pub fn answer(&mut self, server: &str, qname: &str, qtype: QType, answers: &[Record]) {
        self.reply(server, qname, qtype, |m| {
            m.metadata.authoritative = true;
            m.add_answers(answers.to_vec());
        });
    }

    /// An authoritative "no such data" answer from `zone`.
    pub fn nodata(&mut self, server: &str, qname: &str, qtype: QType, zone: &str) {
        self.reply(server, qname, qtype, |m| {
            m.metadata.authoritative = true;
            m.add_authority(soa(zone, 1));
        });
    }

    /// An authoritative NXDOMAIN from `zone`.
    pub fn nxdomain(&mut self, server: &str, qname: &str, qtype: QType, zone: &str) {
        self.reply(server, qname, qtype, |m| {
            m.metadata.authoritative = true;
            m.metadata.response_code = ResponseCode::NXDomain;
            m.add_authority(soa(zone, 1));
        });
    }

    /// A referral: NS records in the authority section, glue in additional.
    pub fn referral(
        &mut self,
        server: &str,
        qname: &str,
        qtype: QType,
        ns_records: &[Record],
        glue: &[Record],
    ) {
        self.reply(server, qname, qtype, |m| {
            m.add_authorities(ns_records.to_vec());
            m.add_additionals(glue.to_vec());
        });
    }

    /// The server answers every listed question with this response code.
    pub fn rcode(&mut self, server: &str, qname: &str, qtypes: &[QType], rcode: ResponseCode) {
        for qtype in qtypes {
            self.reply(server, qname, *qtype, |m| m.metadata.response_code = rcode);
        }
    }

    /// The root delegates `example.` to one server, with glue.
    pub fn delegate_tld(&mut self, qname: &str, qtype: QType) {
        self.referral(
            ROOT_V4,
            qname,
            qtype,
            &[ns("example.", "ns.nic.example.")],
            &[addr("ns.nic.example.", TLD_SERVER)],
        );
    }

    /// A healthy authoritative server for `zone`: SOA and NS at the apex.
    pub fn serve_apex(&mut self, server: &str, zone: &str, serial: u32, ns_names: &[&str]) {
        self.answer(server, zone, QType::Soa, &[soa(zone, serial)]);
        let records: Vec<Record> = ns_names.iter().map(|n| ns(zone, n)).collect();
        self.answer(server, zone, QType::Ns, &records);
    }

    /// Address records for a host, as served by `server` from `zone`.
    pub fn serve_host(&mut self, server: &str, zone: &str, host: &str, ips: &[&str]) {
        for (qtype, want_v6) in [(QType::A, false), (QType::Aaaa, true)] {
            let records: Vec<Record> = ips
                .iter()
                .filter(|ip| ip.contains(':') == want_v6)
                .map(|ip| addr(host, ip))
                .collect();
            if records.is_empty() {
                self.nodata(server, host, qtype, zone);
            } else {
                self.answer(server, host, qtype, &records);
            }
        }
    }

    /// Everything a server says about one name: the given records, and
    /// "no such data" for every other type a stored run asks about.
    pub fn serve_name(&mut self, server: &str, zone: &str, owner: &str, records: &[Record]) {
        for qtype in QType::SWEEP {
            let matching: Vec<Record> = records
                .iter()
                .filter(|r| r.record_type() == record_type(qtype))
                .cloned()
                .collect();
            if matching.is_empty() {
                self.nodata(server, owner, qtype, zone);
            } else {
                self.answer(server, owner, qtype, &matching);
            }
        }
    }

    pub fn fixture(&self, zone: &str) -> Fixture {
        self.fixture_at(zone, STARTED_AT)
    }

    pub fn fixture_at(&self, zone: &str, started_at_unix: u64) -> Fixture {
        Fixture {
            version: Fixture::VERSION,
            zone: zone.to_string(),
            started_at_unix,
            exchanges: self.exchanges.clone(),
        }
    }

    /// Run the real resolver and prober against this world.
    pub async fn observe(&self, zone: &str) -> Result<ZoneObservation, ResolveError> {
        observe_fixture(&self.fixture(zone)).await
    }
}

pub async fn observe_fixture(fixture: &Fixture) -> Result<ZoneObservation, ResolveError> {
    let client = Arc::new(Client::replay(fixture));
    observe_zone(client, &fixture.zone, fixture.started_at_unix).await
}

pub const NS1: &str = "198.51.100.1";
pub const NS2: &str = "198.51.100.2";
pub const NS3: &str = "203.0.113.3";

/// A healthy zone `good.example.` with two nameservers in different networks.
pub fn good_world() -> World {
    let zone = "good.example.";
    let names = ["ns1.good.example.", "ns2.good.example."];
    let servers = [NS1, NS3];
    let mut w = World::new();
    w.delegate_tld(zone, QType::Ns);
    w.referral(
        TLD_SERVER,
        zone,
        QType::Ns,
        &[ns(zone, names[0]), ns(zone, names[1])],
        &[addr(names[0], servers[0]), addr(names[1], servers[1])],
    );
    for server in servers {
        w.serve_apex(server, zone, 2024111301, &names);
        w.serve_host(server, zone, names[0], &[servers[0]]);
        w.serve_host(server, zone, names[1], &[servers[1]]);
    }
    w
}

/// The deliberately inconsistent zone `broken.example.`:
///
/// - `ns1` and `ns2` serve different SOA serials
/// - `ns3` is listed by the parent and the zone but refuses every query (lame)
pub fn broken_world() -> World {
    let zone = "broken.example.";
    let names = [
        "ns1.broken.example.",
        "ns2.broken.example.",
        "ns3.broken.example.",
    ];
    let servers = [NS1, NS2, NS3];
    let mut w = World::new();
    w.delegate_tld(zone, QType::Ns);
    let ns_records: Vec<Record> = names.iter().map(|n| ns(zone, n)).collect();
    let glue: Vec<Record> = names.iter().zip(servers).map(|(n, s)| addr(n, s)).collect();
    w.referral(TLD_SERVER, zone, QType::Ns, &ns_records, &glue);
    for (server, serial) in [(NS1, 2024111301), (NS2, 2024111302)] {
        w.serve_apex(server, zone, serial, &names);
        for (host, ip) in names.iter().zip(servers) {
            w.serve_host(server, zone, host, &[ip]);
        }
    }
    w.rcode(NS3, zone, &[QType::Soa, QType::Ns], ResponseCode::Refused);
    w
}

pub const DRIFT_ZONE: &str = "drift.example.";
/// The names `run` is asked to check in the drift worlds.
pub const DRIFT_NAMES: [&str; 4] = ["www", "api", "shop", "staging"];

/// `drift.example.` at two points in time, for diff tests.
///
/// Between `after = false` and `after = true`:
///
/// - `api` (CNAME) points at a different target, on both servers
/// - `staging` (A) appears
/// - the apex TXT record disappears
/// - `shop` (A) changes on ns1 only, so the servers now disagree
/// - `www` (A) and the apex MX do not change
/// - the SOA serial moves on
pub fn drift_world(after: bool) -> World {
    let zone = DRIFT_ZONE;
    let names = ["ns1.drift.example.", "ns2.drift.example."];
    let servers = [NS1, NS3];
    let mut w = World::new();
    w.delegate_tld(zone, QType::Ns);
    w.referral(
        TLD_SERVER,
        zone,
        QType::Ns,
        &[ns(zone, names[0]), ns(zone, names[1])],
        &[addr(names[0], servers[0]), addr(names[1], servers[1])],
    );
    let serial = if after { 2026111302 } else { 2026111301 };
    for server in servers {
        w.serve_apex(server, zone, serial, &names);
        w.serve_host(server, zone, names[0], &[servers[0]]);
        w.serve_host(server, zone, names[1], &[servers[1]]);

        let mut apex = vec![mx(zone, 10, "mail.drift.example.")];
        if !after {
            apex.push(txt(zone, "v=spf1 mx -all"));
        }
        w.serve_name(server, zone, zone, &apex);
        w.serve_name(
            server,
            zone,
            "www.drift.example.",
            &[addr("www.drift.example.", "192.0.2.10")],
        );
        let api_target = if after {
            "new-app.hosting.example."
        } else {
            "app.hosting.example."
        };
        w.serve_name(
            server,
            zone,
            "api.drift.example.",
            &[cname("api.drift.example.", api_target)],
        );
        let shop_ip = if after && server == NS1 {
            "192.0.2.99"
        } else {
            "192.0.2.20"
        };
        w.serve_name(
            server,
            zone,
            "shop.drift.example.",
            &[addr("shop.drift.example.", shop_ip)],
        );
        let staging = if after {
            vec![addr("staging.drift.example.", "192.0.2.50")]
        } else {
            vec![]
        };
        w.serve_name(server, zone, "staging.drift.example.", &staging);
    }
    w
}
