//! The proofs of concept of the third security audit, for the checks that
//! look outward, kept as tests of the fixes: each asserted the fault and
//! now asserts that it is gone.

#![allow(unused, clippy::all)]

//! Red team A: proofs of concept against the 0.15.0 outward probes.

mod common;

use std::sync::Arc;

use common::*;

use zoneblick::checks::{Severity, run_all};
use zoneblick::observe::{
    DeepObservation, QType, RecordObservation, RecordOutcome, ServedTls, Subzone, SubzoneServer,
    Transport,
};
use zoneblick::resolver::{Client, RawOutcome, add_deep, observe_zone};

const ZONE: &str = "good.example.";

async fn light(w: &World) -> (Arc<Client>, zoneblick::observe::ZoneObservation) {
    let fixture = w.fixture(ZONE);
    let client = Arc::new(Client::replay(&fixture).with_recording());
    let obs = observe_zone(client.clone(), ZONE, fixture.started_at_unix)
        .await
        .unwrap();
    (client, obs)
}

fn record(name: &str) -> RecordObservation {
    RecordObservation {
        name: name.to_string(),
        qtype: QType::A,
        ns_name: "ns1.good.example.".to_string(),
        address: NS1.parse().unwrap(),
        transport: Transport::Udp,
        outcome: RecordOutcome::Timeout,
    }
}

// ---------------------------------------------------------------------
// 1. One answer adds far more than MAX_SUBZONES delegated names.

#[tokio::test]
async fn one_ns_answer_gives_one_delegated_name() {
    let mut w = good_world();
    let depth = 40;
    let labels: Vec<String> = (1..=depth).map(|i| format!("a{i}")).collect();
    let deep_name = format!("{}.{ZONE}", labels.join("."));
    // Every ancestor of the deep name, inside the zone.
    let mut cuts = Vec::new();
    for i in 0..depth {
        cuts.push(format!("{}.{ZONE}", labels[i..].join(".")));
    }
    // One authoritative answer that carries NS records for every one of them,
    // six nameservers each, all in a domain that is not registered.
    let mut records = Vec::new();
    for (c, cut) in cuts.iter().enumerate() {
        for n in 0..6 {
            let target = format!("ns{n}.gone{c}.example.");
            records.push(ns(cut, &target));
            for qtype in [QType::A, QType::Aaaa] {
                w.delegate_tld(&target, qtype);
                w.nxdomain(TLD_SERVER, &target, qtype, "example.");
            }
        }
    }
    for cut in &cuts {
        w.answer(NS1, cut, QType::Ns, &records);
    }
    let (client, mut obs) = light(&w).await;
    obs.records.push(record(&deep_name));
    let before = client.queries_sent();
    add_deep(client.clone(), &mut obs).await;
    let deep = obs.deep.as_ref().unwrap();
    let servers: usize = deep.subzones.iter().map(|s| s.servers.len()).sum();
    let findings: Vec<_> = run_all(&obs)
        .into_iter()
        .filter(|f| f.check_id == "TKO-07")
        .collect();
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    // One answer names one delegation, the one nearest the zone, and
    // its servers are capped.
    assert_eq!(deep.subzones.len(), 1);
    assert!(servers <= 6 && findings.len() <= 6);
}

// ---------------------------------------------------------------------
// 3. A lookalike's MX answer is stored and quoted without any limit.

#[tokio::test]
async fn a_lookalike_cannot_fill_the_run_with_mx_records() {
    let mut w = good_world();
    let look = "g0od.example.";
    let evil = "45.0.0.9";
    w.delegate_tld(look, QType::Ns);
    w.delegate_tld(look, QType::Mx);
    for qtype in [QType::Ns, QType::Mx] {
        w.referral(
            TLD_SERVER,
            look,
            qtype,
            &[ns(look, "ns.g0od.example.")],
            &[addr("ns.g0od.example.", evil)],
        );
    }
    w.answer(evil, look, QType::Ns, &[ns(look, "ns.g0od.example.")]);
    // A long tail that every MX target shares; on the wire it is sent once.
    let tail = format!("{}.g0od.example.", vec!["x".repeat(60); 3].join("."));
    // Built by hand, with compression pointers as a real server sends them.
    let _ = &tail;
    let mut wire: Vec<u8> = vec![0, 0, 0x84, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["g0od", "example"] {
        wire.push(label.len() as u8);
        wire.extend(label.as_bytes());
    }
    wire.extend([0, 0, 15, 0, 1]);
    let mut count: u16 = 0;
    let mut tail_at: Option<usize> = None;
    loop {
        let label = format!("m{count}");
        let mut exchange = vec![label.len() as u8];
        exchange.extend(label.as_bytes());
        match tail_at {
            None => {
                tail_at = Some(wire.len() + 14 + exchange.len());
                for _ in 0..3 {
                    exchange.push(60);
                    exchange.extend([b'x'; 60]);
                }
                exchange.extend([0xc0, 12]);
            }
            Some(at) => exchange.extend([0xc0 | (at >> 8) as u8, at as u8]),
        }
        if wire.len() + 14 + exchange.len() > 65_535 {
            break;
        }
        wire.extend([0xc0, 12, 0, 15, 0, 1, 0, 0, 1, 0]);
        wire.extend(((exchange.len() + 2) as u16).to_be_bytes());
        wire.extend([0, 10]);
        wire.extend(exchange);
        count += 1;
    }
    wire[6..8].copy_from_slice(&count.to_be_bytes());
    let wire_len = wire.len();
    w.reply_on(evil, Transport::Udp, true, look, QType::Mx, |m| {
        m.metadata.truncation = true;
    });
    w.outcome(
        evil,
        Transport::Tcp,
        true,
        look,
        QType::Mx,
        RawOutcome::Response { wire },
    );
    let (client, mut obs) = light(&w).await;
    add_deep(client, &mut obs).await;
    let deep = obs.deep.as_ref().unwrap();
    let l = deep.lookalikes.iter().find(|l| l.domain == look).unwrap();
    let stored: usize = l.mx.iter().map(String::len).sum();
    let finding = run_all(&obs)
        .into_iter()
        .find(|f| f.check_id == "LAL-01" && f.name == look)
        .unwrap();
    let evidence = serde_json::to_string(&finding.evidence).unwrap().len();
    assert!(stored < 2_000 && evidence < 2_000, "{stored} {evidence}");
}

// ---------------------------------------------------------------------
// 4. A nameserver name bends the RDAP address.

#[tokio::test]
async fn a_nameserver_name_cannot_bend_the_rdap_address() {
    let zone = ZONE;
    let hostile = hickory_proto::rr::Name::from_labels(vec![
        b"bank".as_ref(),
        b"example?x".as_ref(),
        b"example".as_ref(),
    ])
    .unwrap();
    let mut hostile_ns = ns(zone, "placeholder.example.");
    hostile_ns.data = hickory_proto::rr::RData::NS(hickory_proto::rr::rdata::NS(hostile));
    let set = [
        ns(zone, "ns1.good.example."),
        ns(zone, "ns2.good.example."),
        hostile_ns,
    ];
    let mut w = good_world();
    w.referral(
        TLD_SERVER,
        zone,
        QType::Ns,
        &set,
        &[
            addr("ns1.good.example.", NS1),
            addr("ns2.good.example.", NS3),
        ],
    );
    for server in [NS1, NS3] {
        w.answer(server, zone, QType::Ns, &set);
    }
    w.http(
        zoneblick::registration::BOOTSTRAP_URL,
        200,
        r#"{"services":[[["example"],["https://rdap.registry.test/"]]]}"#,
    );
    // What the registry says about bank.example, a domain the zone has
    // nothing to do with.
    w.http(
        "https://rdap.registry.test/domain/bank.example?x.example",
        200,
        r#"{"objectClassName":"domain","status":["client hold"]}"#,
    );
    let (client, mut obs) = light(&w).await;
    add_deep(client.clone(), &mut obs).await;
    let urls: Vec<String> = client
        .take_http_recording()
        .into_iter()
        .map(|e| e.url)
        .filter(|u| u.contains("rdap.registry.test"))
        .collect();
    for u in &urls {
        if let Ok(p) = reqwest::Url::parse(u) {}
    }
    let found: Vec<_> = run_all(&obs)
        .into_iter()
        .filter(|f| f.check_id == "REG-05")
        .map(|f| (f.severity, f.summary))
        .collect();
    // The name with a "?" in it is never put into an address.
    assert!(urls.iter().all(|u| !u.contains('?') && !u.contains('\\')));
}

// ---------------------------------------------------------------------
// 5. A finding that gets worse opens no alert, and a mute covers the worse form.

fn tls_obs(
    base: &zoneblick::observe::ZoneObservation,
    at: u64,
    not_after: u64,
    sub_status: &str,
) -> zoneblick::observe::ZoneObservation {
    let mut obs = base.clone();
    obs.started_at_unix = at;
    let mut deep = DeepObservation::default();
    deep.served_tls = vec![ServedTls {
        role: "web".to_string(),
        host: "www.good.example.".to_string(),
        address: Some("8.8.4.4".parse().unwrap()),
        starttls: None,
        not_after_unix: Some(not_after),
        names: vec!["www.good.example".to_string()],
        error: None,
    }];
    deep.subzones = vec![Subzone {
        name: "shop.good.example.".to_string(),
        servers: vec![
            SubzoneServer {
                ns_name: "ns1.hoster.example.".to_string(),
                address: Some("8.8.4.4".parse().unwrap()),
                status: "authoritative".to_string(),
                detail: None,
            },
            SubzoneServer {
                ns_name: "ns2.hoster.example.".to_string(),
                address: Some("8.8.8.8".parse().unwrap()),
                status: sub_status.to_string(),
                detail: Some("REFUSED".to_string()),
            },
        ],
    }];
    if sub_status == "all-refused" {
        for s in &mut deep.subzones[0].servers {
            s.status = "refused".to_string();
        }
    }
    obs.deep = Some(deep);
    obs
}

#[tokio::test]
async fn a_finding_that_gets_worse_alerts_again() {
    let (_, base) = light(&good_world()).await;
    let day = 86_400;
    let t0 = base.started_at_unix;
    let expiry = t0 + 10 * day;
    let mut store = zoneblick::store::Store::open_in_memory().unwrap();
    let run = |store: &mut zoneblick::store::Store, at: u64, sub: &str| {
        let obs = tls_obs(&base, at, expiry, sub);
        zoneblick::runner::store_observation(store, obs, Vec::new(), 0, at, "test", &[]).unwrap()
    };
    let show = |label: &str, o: &zoneblick::runner::RunOutcome| {
        let f: Vec<_> = o
            .report
            .findings
            .iter()
            .filter(|f| matches!(f.check_id.as_str(), "TLS-01" | "TKO-07"))
            .map(|f| format!("{:?} {} {}", f.severity, f.check_id, f.summary))
            .collect();
        let alert = zoneblick::alerts::compose(o);
    };
    // Day 0: the certificate has 10 days left (notice); one of two
    // nameservers of shop refuses it (warning).
    let first = run(&mut store, t0, "refused");
    show("day 0", &first);
    // Day 11: the certificate has run out (critical); every nameserver of
    // shop refuses it (critical: takeover).
    let second = run(&mut store, t0 + 11 * day, "all-refused");
    show("day 11", &second);
    let alert = zoneblick::alerts::compose(&second);
    let alert = alert.expect("the step up to critical is reported");
    assert_eq!(alert.severity, Severity::Critical);
    assert!(alert.text.contains("OPENED TKO-07") && alert.text.contains("OPENED TLS-01"));
    assert!(
        second
            .report
            .findings
            .iter()
            .filter(|f| matches!(f.check_id.as_str(), "TLS-01" | "TKO-07"))
            .all(|f| f.severity == Severity::Critical)
    );
}

// ---------------------------------------------------------------------
// 6. Parsers and helpers under random input; the address rules.

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn helpers_survive_random_text() {
    use zoneblick::checks::exposure::{dmarc_weaknesses, spf_weaknesses};
    use zoneblick::resolver::exposure::*;
    use zoneblick::resolver::smtp::{certificate_covers, certificate_info};
    let alphabet: Vec<char> = "abclmow01i-._*=;:,!@/ \t\"\\mailto:rua=ruf=ip4:v=spf1v=DMARC1+all?pct=sp=noneé漢\u{202e}\u{0}Z T23-"
        .chars()
        .collect();
    let mut rng = Rng(0x9e3779b97f4a7c15);
    for _ in 0..200_000 {
        let len = rng.below(40);
        let text: String = (0..len)
            .map(|_| alphabet[rng.below(alphabet.len())])
            .collect();
        let _ = report_domains(&text);
        let _ = spf_addresses(&text);
        let _ = lookalike_labels(&text);
        let _ = lookalike_candidates(&text);
        let _ = lookalike_candidates(&format!("{text}."));
        let _ = parse_route_status(&text);
        let _ = spf_weaknesses(&text);
        let _ = dmarc_weaknesses(&text, "zone.example.", &[]);
        let _ = zoneblick::registration::parse_rfc3339(&text);
        let _ = certificate_covers(&[text.clone()], &text);
        let _ = certificate_info(text.as_bytes());
    }
    // Timestamps with the right shape and hostile digits.
    for _ in 0..200_000 {
        let mut b = *b"2027-08-13T04:00:00+00:00";
        for _ in 0..rng.below(4) + 1 {
            let i = rng.below(b.len());
            b[i] = b"0123456789-+:TZ. \xc3\xa9"[rng.below(18)];
        }
        if let Ok(s) = std::str::from_utf8(&b) {
            let _ = zoneblick::registration::parse_rfc3339(s);
        }
    }
}

#[test]
fn address_rules() {
    use zoneblick::resolver::policy::not_public;
    let internal = [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "100.100.100.200",
        "0.0.0.0",
        "0.1.2.3",
        "255.255.255.255",
        "240.0.0.1",
        "224.0.0.1",
        "192.0.0.8",
        "198.18.0.1",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "fd00:ec2::254",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "::127.0.0.1",
        "::10.0.0.1",
        "64:ff9b::7f00:1",
        "64:ff9b:1::a00:1",
        "2002:7f00:1::",
        "2001:0:1::1",
        "ff02::1",
        "fec0::1",
        "::ffff:0:10.0.0.1",
    ];
    let mut missed = Vec::new();
    for a in internal {
        if not_public(a.parse().unwrap()).is_none() {
            missed.push(a);
        }
    }
    assert!(
        missed.is_empty(),
        "count as public though they are not: {missed:?}"
    );
    for a in ["8.8.8.8", "1.1.1.1", "2606:4700::1111"] {
        assert!(not_public(a.parse().unwrap()).is_none(), "{a}");
    }
}
