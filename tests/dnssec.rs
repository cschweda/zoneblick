//! DNSSEC collection and the SEC checks, end to end and offline: DS, DNSKEY
//! and RRSIG records travel as real wire data through the resolver.

mod common;

use common::*;
use zoneblick::checks::{Evidence, Severity, run_all};

#[tokio::test]
async fn a_signed_zone_is_parsed_and_clean() {
    let obs = signed_world(true).observe(SIGNED_ZONE).await.unwrap();
    let d = obs.dnssec.as_ref().unwrap();

    let parent = d.parent_ds.as_ref().unwrap();
    assert_eq!(parent.parent_zone, "example.");
    let ds = parent.records.as_ref().unwrap();
    assert_eq!(ds.len(), 1);
    assert_eq!((ds[0].algorithm, ds[0].digest_type), (15, 2));

    assert_eq!(d.servers.len(), 2);
    for server in &d.servers {
        let keys = server.dnskeys.as_ref().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys.iter().filter(|k| k.is_ksk()).count(), 1);
        assert!(keys.iter().any(|k| k.key_tag == ds[0].key_tag));
        assert_eq!(server.dnskey_sigs.len(), 1);
        assert_eq!(server.dnskey_sigs[0].type_covered, "DNSKEY");
        let soa_sigs = server.soa_sigs.as_ref().unwrap();
        assert_eq!(soa_sigs.len(), 1);
        assert_eq!(soa_sigs[0].signer, SIGNED_ZONE);
        assert_eq!(soa_sigs[0].expiration as u64, STARTED_AT + 20 * 86_400);
        // The test zone is really signed, and the signatures verify.
        assert_eq!(server.dnskey_sig_status.as_deref(), Some("valid"));
        assert_eq!(server.soa_sig_status.as_deref(), Some("valid"));
    }
    assert_eq!(run_all(&obs), []);
}

#[tokio::test]
async fn a_ds_that_matches_no_key_is_critical() {
    let obs = signed_world(false).observe(SIGNED_ZONE).await.unwrap();
    let findings = run_all(&obs);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].check_id, "SEC-01");
    assert_eq!(findings[0].severity, Severity::Critical);
    match &findings[0].evidence {
        Evidence::DsWithoutKey { ds, servers } => {
            assert_eq!(ds.len(), 1);
            assert_eq!(servers.len(), 2);
        }
        other => panic!("unexpected evidence: {other:?}"),
    }
}

#[tokio::test]
async fn signatures_near_expiry_are_reported() {
    // The same zone, observed nineteen days later: one day of validity left.
    let fixture = signed_world(true).fixture_at(SIGNED_ZONE, STARTED_AT + 19 * 86_400);
    let obs = observe_fixture(&fixture).await.unwrap();
    let findings = run_all(&obs);
    let ids: Vec<(&str, Severity)> = findings
        .iter()
        .map(|f| (f.check_id.as_str(), f.severity))
        .collect();
    assert_eq!(
        ids,
        [("SEC-02", Severity::Warning), ("SEC-02", Severity::Warning)]
    );

    // And after they run out.
    let fixture = signed_world(true).fixture_at(SIGNED_ZONE, STARTED_AT + 21 * 86_400);
    let obs = observe_fixture(&fixture).await.unwrap();
    let findings = run_all(&obs);
    assert!(
        findings
            .iter()
            .all(|f| f.check_id == "SEC-02" && f.severity == Severity::Critical)
    );
    assert_eq!(findings.len(), 2);
}

#[tokio::test]
async fn an_unsigned_zone_reports_no_dnssec_findings() {
    let obs = good_world().observe("good.example.").await.unwrap();
    let d = obs.dnssec.as_ref().unwrap();
    assert_eq!(
        d.parent_ds.as_ref().unwrap().records.as_deref(),
        Some(&[][..])
    );
    assert!(
        d.servers
            .iter()
            .all(|s| s.dnskeys.as_deref() == Some(&[][..]))
    );
    assert_eq!(run_all(&obs), []);
}

#[tokio::test]
async fn a_signature_that_does_not_verify_is_critical() {
    // The zone serves a different SOA serial than the one that was signed.
    let mut world = signed_world(true);
    for server in [NS1, NS3] {
        for transport in [
            zoneblick::observe::Transport::Udp,
            zoneblick::observe::Transport::Tcp,
        ] {
            world.reply_signed(
                server,
                transport,
                SIGNED_ZONE,
                zoneblick::observe::QType::Soa,
                |m| {
                    m.metadata.authoritative = true;
                    m.add_answer(soa(SIGNED_ZONE, 2024111399));
                    m.add_answer(raw(
                        SIGNED_ZONE,
                        hickory_proto::rr::RecordType::RRSIG,
                        rrsig_rdata(
                            6,
                            2,
                            false,
                            STARTED_AT - 86_400,
                            STARTED_AT + 20 * 86_400,
                            SIGNED_ZONE,
                            &[soa_canonical(SIGNED_ZONE, 2024111301)],
                        ),
                    ));
                },
            );
        }
    }
    let obs = world.observe(SIGNED_ZONE).await.unwrap();
    for server in &obs.dnssec.as_ref().unwrap().servers {
        assert_eq!(server.dnskey_sig_status.as_deref(), Some("valid"));
        assert_eq!(server.soa_sig_status.as_deref(), Some("invalid"));
    }
    let findings = run_all(&obs);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(
        (findings[0].check_id.as_str(), findings[0].severity),
        ("SEC-11", Severity::Critical)
    );
    assert!(
        matches!(&findings[0].evidence, Evidence::ZoneDetail { details }
        if details.len() == 2 && details[0].contains("the SOA record"))
    );
}

/// [`signed_world`] with the levels above it signed too: a root key (seed
/// 10) that the returned trust anchor points at, and a key for `example.`
/// (seed 20). `ds_signer` is the seed of the key that signs the DS set for
/// the zone at its parent; 20 is the right one. The zone also serves
/// `www`, signed correctly on the first nameserver and wrongly on the
/// second.
fn chained_world(ds_signer: u8) -> (World, Vec<zoneblick::dnssec::Ds>) {
    use hickory_proto::rr::RecordType;
    use zoneblick::observe::{QType, Transport};

    let zone = SIGNED_ZONE;
    let (inception, expiration) = (STARTED_AT - 10 * 86_400, STARTED_AT + 20 * 86_400);
    let root_key = dnskey_rdata(10, true);
    let tld_key = dnskey_rdata(20, true);
    let zone_ksk = dnskey_rdata(1, true);
    let tld_ds = ds_rdata("example.", &tld_key);
    let zone_ds = ds_rdata(zone, &zone_ksk);
    let www = "www.signed.example.";
    let www_rdata = vec![192, 0, 2, 80];

    let mut w = signed_world(true);
    for server in [NS1, NS3] {
        w.serve_name(server, zone, www, &[addr(www, "192.0.2.80")]);
    }
    for transport in [Transport::Udp, Transport::Tcp] {
        w.reply_signed(ROOT_V4, transport, ".", QType::Dnskey, |m| {
            m.metadata.authoritative = true;
            m.add_answer(raw(".", RecordType::DNSKEY, root_key.clone()));
            m.add_answer(raw(
                ".",
                RecordType::RRSIG,
                rrsig_for(
                    ".",
                    48,
                    10,
                    true,
                    inception,
                    expiration,
                    ".",
                    std::slice::from_ref(&root_key),
                ),
            ));
        });
        w.reply_signed(ROOT_V4, transport, "example.", QType::Ds, |m| {
            m.metadata.authoritative = true;
            m.add_answer(raw("example.", RecordType::DS, tld_ds.clone()));
            m.add_answer(raw(
                "example.",
                RecordType::RRSIG,
                rrsig_for(
                    "example.",
                    43,
                    10,
                    true,
                    inception,
                    expiration,
                    ".",
                    std::slice::from_ref(&tld_ds),
                ),
            ));
        });
        w.reply_signed(TLD_SERVER, transport, "example.", QType::Dnskey, |m| {
            m.metadata.authoritative = true;
            m.add_answer(raw("example.", RecordType::DNSKEY, tld_key.clone()));
            m.add_answer(raw(
                "example.",
                RecordType::RRSIG,
                rrsig_for(
                    "example.",
                    48,
                    20,
                    true,
                    inception,
                    expiration,
                    "example.",
                    std::slice::from_ref(&tld_key),
                ),
            ));
        });
        w.reply_signed(TLD_SERVER, transport, zone, QType::Ds, |m| {
            m.metadata.authoritative = true;
            m.add_answer(raw(zone, RecordType::DS, zone_ds.clone()));
            m.add_answer(raw(
                zone,
                RecordType::RRSIG,
                rrsig_for(
                    zone,
                    43,
                    ds_signer,
                    true,
                    inception,
                    expiration,
                    "example.",
                    std::slice::from_ref(&zone_ds),
                ),
            ));
        });
        for (server, signer) in [(NS1, 2), (NS3, 77)] {
            w.reply_signed(server, transport, www, QType::A, |m| {
                m.metadata.authoritative = true;
                m.add_answer(addr(www, "192.0.2.80"));
                // Signed under the zone's ZSK tag; on the second server
                // the signature is made with another key.
                let mut sig = rrsig_for(
                    www,
                    1,
                    signer,
                    false,
                    inception,
                    expiration,
                    zone,
                    std::slice::from_ref(&www_rdata),
                );
                let tag = zoneblick::dnssec::key_tag(&dnskey_rdata(2, false)).to_be_bytes();
                sig[16..18].copy_from_slice(&tag);
                m.add_answer(raw(www, RecordType::RRSIG, sig));
            });
        }
    }
    let anchor = zoneblick::dnssec::parse_ds(&ds_rdata(".", &root_key)).unwrap();
    (w, vec![anchor])
}

async fn chained(
    ds_signer: u8,
) -> (
    zoneblick::observe::ZoneObservation,
    Vec<zoneblick::observe::ChainLink>,
    Vec<zoneblick::observe::RecordSignature>,
) {
    use zoneblick::resolver::chain::{chain_of_trust, record_signatures};
    let (world, anchors) = chained_world(ds_signer);
    let fixture = world.fixture(SIGNED_ZONE);
    let client = std::sync::Arc::new(zoneblick::resolver::Client::replay(&fixture));
    let obs = zoneblick::resolver::observe_zone_records(
        client.clone(),
        SIGNED_ZONE,
        fixture.started_at_unix,
        &["www.signed.example.".to_string()],
    )
    .await
    .unwrap();
    let chain = chain_of_trust(&client, &obs, &anchors).await;
    let sigs = record_signatures(&client, &obs).await;
    (obs, chain, sigs)
}

#[tokio::test]
async fn the_chain_of_trust_is_followed_from_the_anchor() {
    let (_, chain, _) = chained(20).await;
    let got: Vec<(&str, &str)> = chain
        .iter()
        .map(|l| (l.zone.as_str(), l.status.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            (".", "secure"),
            ("example.", "secure"),
            ("signed.example.", "secure")
        ],
        "{chain:?}"
    );

    // With the built-in anchors the test root is not trusted.
    let (world, _) = chained_world(20);
    let fixture = world.fixture(SIGNED_ZONE);
    let client = zoneblick::resolver::Client::replay(&fixture);
    let obs = observe_fixture(&fixture).await.unwrap();
    let chain = zoneblick::resolver::chain::chain_of_trust(
        &client,
        &obs,
        &zoneblick::resolver::chain::root_anchors(),
    )
    .await;
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].status, "bogus");
    assert!(
        chain[0]
            .detail
            .as_ref()
            .unwrap()
            .contains("no key of . matches"),
        "{chain:?}"
    );
}

#[tokio::test]
async fn a_ds_set_signed_by_the_wrong_key_breaks_the_chain() {
    let (mut obs, chain, sigs) = chained(55).await;
    let last = chain.last().unwrap();
    assert_eq!(
        (last.zone.as_str(), last.status.as_str()),
        (SIGNED_ZONE, "bogus")
    );
    // Key 55 is not in the parent's key set: nobody can validate the DS set.
    assert_eq!(chain.len(), 3, "{chain:?}");
    assert!(
        last.detail.as_ref().unwrap().contains("does not publish"),
        "{chain:?}"
    );

    // The record check: valid on the first server, invalid on the second.
    let www: Vec<(&str, &str)> = sigs
        .iter()
        .filter(|s| s.name == "www.signed.example." && s.rtype == "A")
        .map(|s| (s.address.to_string().leak() as &str, s.status.as_str()))
        .collect();
    assert_eq!(www, [(NS1, "valid"), (NS3, "invalid")], "{sigs:?}");

    // Both become findings of a deep run.
    obs.deep = Some(zoneblick::observe::DeepObservation {
        servers: vec![],
        mname: None,
        rname_domain: None,
        rname_mx: None,
        rname_address: None,
        previous_dnskeys: None,
        origins: vec![],
        chain,
        record_signatures: sigs,
        mail_tls: Vec::new(),
        registration: None,
    });
    let findings = run_all(&obs);
    let got: Vec<(&str, Severity, &str)> = findings
        .iter()
        .filter(|f| matches!(f.check_id.as_str(), "SEC-12" | "SEC-13"))
        .map(|f| (f.check_id.as_str(), f.severity, f.name.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            ("SEC-12", Severity::Critical, "www.signed.example."),
            ("SEC-13", Severity::Critical, SIGNED_ZONE),
        ],
        "{findings:#?}"
    );
    let sec12 = findings.iter().find(|f| f.check_id == "SEC-12").unwrap();
    let Evidence::RecordDetail { rtype, details } = &sec12.evidence else {
        panic!("{:?}", sec12.evidence)
    };
    assert_eq!(rtype, "A");
    assert_eq!(details.len(), 1);
    assert!(details[0].contains(NS3), "{details:?}");
}

/// [`chained_world`], but the parent has no DS record for the zone and
/// answers with `proof`: the records of its authority section.
async fn chain_without_ds(
    proof: impl Fn(u64, u64) -> Vec<hickory_proto::rr::Record>,
) -> zoneblick::observe::ChainLink {
    use zoneblick::observe::{QType, Transport};
    let (mut world, anchors) = chained_world(20);
    let (inception, expiration) = (STARTED_AT - 10 * 86_400, STARTED_AT + 20 * 86_400);
    for transport in [Transport::Udp, Transport::Tcp] {
        world.reply_signed(TLD_SERVER, transport, SIGNED_ZONE, QType::Ds, |m| {
            m.metadata.authoritative = true;
            m.authorities.extend(proof(inception, expiration));
        });
    }
    let fixture = world.fixture(SIGNED_ZONE);
    let client = zoneblick::resolver::Client::replay(&fixture);
    let obs = observe_fixture(&fixture).await.unwrap();
    let chain = zoneblick::resolver::chain::chain_of_trust(&client, &obs, &anchors).await;
    assert_eq!(chain.len(), 3, "{chain:?}");
    assert_eq!(chain[1].status, "secure");
    chain.into_iter().next_back().unwrap()
}

/// An NSEC record at the zone's name in the parent: the next name, and a
/// type list of NS, RRSIG and NSEC, with or without DS.
fn nsec_rdata(with_ds: bool) -> Vec<u8> {
    let mut rdata = zoneblick::verify::name_wire("signee.example.");
    // Window 0, six bytes: NS is bit 2, DS bit 43, RRSIG 46, NSEC 47.
    rdata.extend([0, 6, 0x20, 0, 0, 0, 0, if with_ds { 0x13 } else { 0x03 }]);
    rdata
}

#[tokio::test]
async fn a_missing_ds_record_must_be_proven_by_the_parent() {
    use hickory_proto::rr::RecordType;
    let signed_nsec = |with_ds: bool, seed: u8| {
        move |inception: u64, expiration: u64| {
            let nsec = nsec_rdata(with_ds);
            vec![
                raw(SIGNED_ZONE, RecordType::NSEC, nsec.clone()),
                raw(
                    SIGNED_ZONE,
                    RecordType::RRSIG,
                    rrsig_for(
                        SIGNED_ZONE,
                        47,
                        seed,
                        true,
                        inception,
                        expiration,
                        "example.",
                        std::slice::from_ref(&nsec),
                    ),
                ),
            ]
        }
    };
    // Signed by the parent's key, and the type list has no DS: proven.
    let link = chain_without_ds(signed_nsec(false, 20)).await;
    assert_eq!(link.status, "insecure", "{link:?}");
    assert!(
        link.detail
            .unwrap()
            .contains("proves that it has no DS record")
    );

    // The same record signed by a key the parent does not publish.
    let link = chain_without_ds(signed_nsec(false, 55)).await;
    assert_eq!(link.status, "bogus", "{link:?}");
    assert!(link.detail.unwrap().contains("not validly signed"));

    // A record whose type list does have DS proves nothing.
    let link = chain_without_ds(signed_nsec(true, 20)).await;
    assert_eq!(link.status, "unknown", "{link:?}");

    // No proof at all: an answer anyone on the path could have made.
    let link = chain_without_ds(|_, _| Vec::new()).await;
    assert_eq!(link.status, "unknown", "{link:?}");
    assert!(link.detail.unwrap().contains("no proof that there is none"));

    // A record signed for a wildcard and expanded to this name says
    // nothing about the name itself: its signature does not count.
    let link = chain_without_ds(|inception, expiration| {
        let nsec = nsec_rdata(false);
        let mut sig = rrsig_for(
            SIGNED_ZONE,
            47,
            20,
            true,
            inception,
            expiration,
            "example.",
            std::slice::from_ref(&nsec),
        );
        sig[3] = 1;
        vec![
            raw(SIGNED_ZONE, RecordType::NSEC, nsec),
            raw(SIGNED_ZONE, RecordType::RRSIG, sig),
        ]
    })
    .await;
    assert_eq!(link.status, "bogus", "{link:?}");

    // A record without the NS bit is not about a delegation.
    let link = chain_without_ds(|inception, expiration| {
        let mut nsec = zoneblick::verify::name_wire("signee.example.");
        nsec.extend([0, 6, 0, 0, 0, 0, 0, 0x03]);
        vec![
            raw(SIGNED_ZONE, RecordType::NSEC, nsec.clone()),
            raw(
                SIGNED_ZONE,
                RecordType::RRSIG,
                rrsig_for(
                    SIGNED_ZONE,
                    47,
                    20,
                    true,
                    inception,
                    expiration,
                    "example.",
                    std::slice::from_ref(&nsec),
                ),
            ),
        ]
    })
    .await;
    assert_eq!(link.status, "unknown", "{link:?}");

    // An unsigned record.
    let link =
        chain_without_ds(|_, _| vec![raw(SIGNED_ZONE, RecordType::NSEC, nsec_rdata(false))]).await;
    assert_eq!(link.status, "bogus", "{link:?}");
    assert!(link.detail.unwrap().contains("not signed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupted_signed_answers_never_crash_the_chain_or_make_it_secure() {
    use zoneblick::resolver::chain::{chain_of_trust, record_signatures};
    use zoneblick::resolver::{Client, RawOutcome, observe_zone_records};
    let (world, anchors) = chained_world(20);
    let fixture = world.fixture(SIGNED_ZONE);
    // The exchanges that carry signed data: only these are damaged, so
    // that every run gets as far as the chain.
    let signed: Vec<usize> = fixture
        .exchanges
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            // What the chain reads: key sets and DS sets, over UDP.
            e.query.dnssec
                && e.query.transport == zoneblick::observe::Transport::Udp
                && matches!(
                    e.query.qtype,
                    zoneblick::observe::QType::Dnskey | zoneblick::observe::QType::Ds
                )
        })
        .map(|(i, _)| i)
        .collect();
    assert!(signed.len() >= 5, "{}", signed.len());
    let mut seed: u64 = 0x00c0_ffee_1234_5678;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let (mut runs, mut all_secure) = (0, 0);
    for _ in 0..400 {
        let mut hostile = fixture.clone();
        let mut damaged = false;
        for _ in 0..1 + next() % 3 {
            let at = signed[(next() % signed.len() as u64) as usize];
            if let RawOutcome::Response { wire } = &mut hostile.exchanges[at].outcome {
                match next() % 4 {
                    0 => wire.truncate((next() % (wire.len() as u64 + 1)) as usize),
                    _ => {
                        // Flip bytes in the second half, where the record
                        // data and signatures are.
                        for _ in 0..1 + next() % 4 {
                            let half = wire.len() / 2;
                            let i = half + (next() % (wire.len() - half).max(1) as u64) as usize;
                            let before = wire[i];
                            wire[i] = next() as u8;
                            damaged |= wire[i] != before;
                        }
                    }
                }
            }
        }
        let client = std::sync::Arc::new(Client::replay(&hostile));
        let Ok(obs) = observe_zone_records(
            client.clone(),
            SIGNED_ZONE,
            hostile.started_at_unix,
            &["www.signed.example.".to_string()],
        )
        .await
        else {
            continue;
        };
        let chain = chain_of_trust(&client, &obs, &anchors).await;
        let sigs = record_signatures(&client, &obs).await;
        runs += 1;
        // Statuses are always one of the known words.
        for link in &chain {
            assert!(
                ["secure", "insecure", "bogus", "unknown"].contains(&link.status.as_str()),
                "{link:?}"
            );
        }
        for s in &sigs {
            assert!(
                ["valid", "invalid", "expired", "unsigned", "untried"].contains(&s.status.as_str()),
                "{s:?}"
            );
        }
        if damaged && chain.len() == 3 && chain.iter().all(|l| l.status == "secure") {
            all_secure += 1;
        }
    }
    assert!(runs > 200, "{runs} runs reached the chain");
    // A flipped byte can land where it does not matter: a TTL in the
    // message, or the key set of the second nameserver, which the chain
    // does not ask. But a fully secure verdict must not be the usual
    // result of damaged keys, DS records and signatures.
    assert!(
        all_secure * 3 < runs,
        "{all_secure} of {runs} damaged runs were all secure"
    );
}
