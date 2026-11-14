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
