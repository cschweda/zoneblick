//! The proofs of concept of the third security audit, for the resolver
//! and the store, kept as tests of the fixes.

#![allow(unused, clippy::all)]

//! Red-team D: proofs against the core paths. Offline only.
#![allow(unused_imports)]

mod common;

use std::sync::Arc;

use common::*;
use hickory_proto::op::{Message, OpCode, Query};
use hickory_proto::rr::rdata::MX;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use zoneblick::checks::run_all;
use zoneblick::observe::{QType, Transport};
use zoneblick::resolver::{Client, RawOutcome, observe_zone_records};
use zoneblick::runner::store_observation;
use zoneblick::store::Store;

const ZONE: &str = "drift.example.";
const WWW: &str = "www.drift.example.";

async fn stored(world: &World, store: &mut Store, names: &[&str]) -> zoneblick::runner::RunOutcome {
    let obs = world.observe_records(ZONE, names).await.unwrap();
    let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    store_observation(store, obs, names, 0, STARTED_AT + 10, "test", &[]).unwrap()
}

// F1: the record changes, and the servers answer it without the AA bit.

// Same, with an odd response code in place of the AA trick.

/// How names with odd bytes come out as text.
#[tokio::test]
async fn names_with_odd_bytes_come_out_escaped() {
    let mut w = drift_world(false);
    let labels: Vec<&[u8]> = vec![
        b"a b",
        b"<!channel>",
        b"=1+1",
        b"x,y\"z",
        b"n\nl",
        b"e\x1b[31m",
        b"d.t",
        b"h\xffi",
        b"@at",
        b"back\\slash",
        b"`tick`",
        b"\xe2\x80\xae",
    ];
    let mut recs = Vec::new();
    for (i, l) in labels.iter().enumerate() {
        let target = Name::from_labels(vec![*l, b"evil", b"example"]).unwrap();
        recs.push(Record::from_rdata(
            name(ZONE),
            300,
            RData::MX(MX::new(i as u16, target)),
        ));
    }
    for server in [NS1, NS3] {
        w.answer(server, ZONE, QType::Mx, &recs);
    }
    let obs = w.observe_records(ZONE, &[]).await.unwrap();
    for rec in obs
        .records
        .iter()
        .filter(|r| r.qtype == QType::Mx && r.address.to_string() == NS1)
    {
        if let Some(a) = rec.outcome.answer() {
            for r in &a.rdata {
                assert!(!r.chars().any(|c| c.is_control()), "{r:?}");
            }
        }
    }
}

/// F: `plan` says "Nothing" for a file that adds a wildcard, a delegation,
// and records of types it does not compare.

// F: lint is quadratic in the number of CNAME names.

/// A 64 KB answer whose MX targets share one long suffix through
/// compression pointers.
fn bloated_mx(qname: &str, seed: u8) -> Vec<u8> {
    let mut msg = Message::response(0, OpCode::Query);
    msg.metadata.authoritative = true;
    msg.add_query(Query::query(name(qname), RecordType::MX));
    let mut wire = msg.to_vec().unwrap();
    let mut suffix = Vec::new();
    for len in [63usize, 63, 63, 57] {
        suffix.push(len as u8);
        suffix.extend(std::iter::repeat(b'a' + seed % 26).take(len));
    }
    suffix.push(0);
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut count: u16 = 0;
    let mut suffix_at = 0usize;
    loop {
        let label = [
            alphabet[(count as usize) % 36],
            alphabet[(count as usize / 36) % 36],
            alphabet[(count as usize / 1296) % 36],
        ];
        let mut rdata = vec![0, 10, 3];
        rdata.extend(label);
        if count == 0 {
            // owner(2)+type(2)+class(2)+ttl(4)+rdlen(2)+pref(2)+label(4)
            suffix_at = wire.len() + 18;
            rdata.extend(&suffix);
        } else {
            rdata.extend([0xC0 | (suffix_at >> 8) as u8, suffix_at as u8]);
        }
        if wire.len() + 12 + rdata.len() > 65_000 {
            break;
        }
        wire.extend([0xC0, 0x0C, 0, 15, 0, 1, 0, 0, 1, 44]);
        wire.extend((rdata.len() as u16).to_be_bytes());
        wire.extend(rdata);
        count += 1;
    }
    wire[6..8].copy_from_slice(&count.to_be_bytes());
    wire
}

/// F: one 64 KB answer becomes most of a megabyte of stored text, per
/// name, per server; nothing caps the records of an answer.
#[tokio::test]
async fn bloated_answers_are_cut_to_size_before_they_are_stored() {
    let names = [
        "www.drift.example.",
        "api.drift.example.",
        "shop.drift.example.",
    ];
    let mut w = drift_world(false);
    for (s, server) in [NS1, NS3].into_iter().enumerate() {
        for (n, qname) in names.iter().enumerate() {
            w.reply_on(server, Transport::Udp, true, qname, QType::Mx, |m| {
                m.metadata.authoritative = true;
                m.metadata.truncation = true;
            });
            let wire = bloated_mx(qname, (s * 7 + n) as u8);
            assert!(wire.len() <= 65_535);
            w.outcome(
                server,
                Transport::Tcp,
                true,
                qname,
                QType::Mx,
                RawOutcome::Response { wire },
            );
        }
    }
    let obs = w.observe_records(ZONE, &names).await.unwrap();
    let mut per_answer = Vec::new();
    for rec in obs
        .records
        .iter()
        .filter(|r| r.qtype == QType::Mx && r.name != ZONE)
    {
        let Some(a) = rec.outcome.answer() else {
            println!(
                "{} {:?}",
                rec.name,
                format!("{:?}", rec.outcome)
                    .chars()
                    .take(200)
                    .collect::<String>()
            );
            continue;
        };
        per_answer.push((
            a.rdata.len(),
            a.rdata.iter().map(String::len).sum::<usize>(),
        ));
    }
    assert_eq!(per_answer.len(), 6);
    // 3,000 records and most of a megabyte arrive; 64 records and 16 KB stay.
    assert!(
        per_answer
            .iter()
            .all(|(n, bytes)| *n <= 64 && *bytes <= 16 * 1024),
        "{per_answer:?}"
    );
    let json = serde_json::to_string(&obs).unwrap().len();
    let dir = std::env::temp_dir().join(format!("zb-redteam-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("z.db");
    let mut store = Store::open(&db).unwrap();
    let t = std::time::Instant::now();
    let names_v: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    let out = store_observation(&mut store, obs, names_v, 0, STARTED_AT + 5, "test", &[]).unwrap();
    drop(store);
    let size: u64 = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().metadata().unwrap().len())
        .sum();
    assert!(json < 1_000_000 && size < 2_000_000, "{json} {size}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same with the most servers a zone may list: 26 names x 8 addresses.
#[tokio::test]
async fn bloated_answers_from_every_server_stay_within_the_run_limit() {
    let zone = "big.example.";
    let ns_names: Vec<String> = (0..26).map(|i| format!("ns{i}.big.example.")).collect();
    let ip = |i: usize, j: usize| format!("198.51.{}.{}", 100 + i, 10 + j);
    let mut w = World::new();
    w.delegate_tld(zone, QType::Ns);
    let ns_recs: Vec<Record> = ns_names.iter().map(|n| ns(zone, n)).collect();
    let mut glue = Vec::new();
    for (i, n) in ns_names.iter().enumerate() {
        for j in 0..8 {
            glue.push(addr(n, &ip(i, j)));
        }
    }
    w.referral(TLD_SERVER, zone, QType::Ns, &ns_recs, &glue);
    w.no_ds(zone);
    let refs: Vec<&str> = ns_names.iter().map(String::as_str).collect();
    let names = ["a.big.example.", "b.big.example."];
    let first = ip(0, 0);
    for i in 0..26 {
        for j in 0..8 {
            let server = ip(i, j);
            w.serve_apex(&server, zone, 1, &refs);
            if server == first {
                // Address lookups of the nameserver names go to the first server.
                for (k, n) in ns_names.iter().enumerate() {
                    let ips: Vec<String> = (0..8).map(|j| ip(k, j)).collect();
                    let ips: Vec<&str> = ips.iter().map(String::as_str).collect();
                    w.serve_host(&server, zone, n, &ips);
                }
            }
            for qname in names.iter().copied().chain([zone]) {
                w.reply_on(&server, Transport::Udp, true, qname, QType::Mx, |m| {
                    m.metadata.authoritative = true;
                    m.metadata.truncation = true;
                });
                let wire = bloated_mx(qname, (i * 8 + j) as u8);
                w.outcome(
                    &server,
                    Transport::Tcp,
                    true,
                    qname,
                    QType::Mx,
                    RawOutcome::Response { wire },
                );
            }
        }
    }
    let fixture = w.fixture(zone);
    let client = Arc::new(Client::replay(&fixture));
    let names_v: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    let t = std::time::Instant::now();
    let obs = observe_zone_records(client.clone(), zone, STARTED_AT, &names_v)
        .await
        .unwrap();
    let servers: std::collections::BTreeSet<_> = obs.records.iter().map(|r| r.address).collect();
    let text: usize = obs
        .records
        .iter()
        .filter_map(|r| r.outcome.answer())
        .map(|a| a.rdata.iter().map(String::len).sum::<usize>())
        .sum();
    let targets = obs.policy.as_ref().map(|p| p.targets.len()).unwrap_or(0);
    // 208 servers, each answering with all it can: what is held stays
    // far below what the same answers used to add up to (519 MB).
    assert_eq!(servers.len(), 208);
    assert!(text <= 32 * 1024 * 1024, "{text}");
    assert!(targets <= 200, "{targets}");
    let _ = (t, &client);
}
