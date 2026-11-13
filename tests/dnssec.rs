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
