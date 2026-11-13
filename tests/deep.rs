//! The deep probes and checks, end to end and offline.

mod common;

use std::sync::Arc;

use common::*;
use hickory_proto::op::ResponseCode;
use zoneblick::checks::{Severity, run_all};
use zoneblick::observe::{Probe, QType, Transport};
use zoneblick::resolver::{Client, add_deep, observe_zone};

const ZONE: &str = "good.example.";

/// `good.example.`, where the first nameserver answers the deep probes
/// (well for EDNS, badly for recursion and case) and the second does not.
fn deep_world() -> World {
    let mut w = good_world();
    w.reply_probe(NS1, ZONE, Probe::EdnsVersion1, ZONE, |m| {
        m.metadata.response_code = ResponseCode::BADVERS;
    });
    w.reply_probe(NS1, ZONE, Probe::EdnsUnknownOption, ZONE, |m| {
        m.metadata.authoritative = true;
    });
    w.reply_probe(NS1, ZONE, Probe::Recursion, ZONE, |m| {
        m.metadata.recursion_available = true;
    });
    // Sent as "GoOd.ExAmPlE.", repeated in lower case.
    w.reply_probe(NS1, ZONE, Probe::MixedCase, ZONE, |_| {});
    for qtype in [QType::Nsec3param, QType::Cds, QType::Cdnskey] {
        w.reply_signed(NS1, Transport::Udp, ZONE, qtype, |m| {
            m.metadata.authoritative = true;
        });
    }
    // The deep run resolves the SOA primary from the root again.
    w.delegate_tld("ns1.good.example.", QType::A);
    w.referral(
        TLD_SERVER,
        "ns1.good.example.",
        QType::A,
        &[ns(ZONE, "ns1.good.example."), ns(ZONE, "ns2.good.example.")],
        &[
            addr("ns1.good.example.", NS1),
            addr("ns2.good.example.", NS3),
        ],
    );
    w
}

#[tokio::test]
async fn a_deep_run_collects_the_probes_and_reports() {
    let fixture = deep_world().fixture(ZONE);
    let client = Arc::new(Client::replay(&fixture));
    let mut obs = observe_zone(client.clone(), ZONE, fixture.started_at_unix)
        .await
        .unwrap();
    assert!(run_all(&obs).is_empty(), "light run is clean");
    add_deep(client, &mut obs).await;

    let deep = obs.deep.as_ref().unwrap();
    assert_eq!(deep.servers.len(), 2);
    let first = deep
        .servers
        .iter()
        .find(|s| s.address.to_string() == NS1)
        .unwrap();
    assert_eq!(first.edns_version.rcode.as_deref(), Some("BADVERS"));
    assert_eq!(
        (
            first.edns_option.rcode.as_deref(),
            first.edns_option.opt_present
        ),
        (Some("NOERROR"), true)
    );
    assert_eq!(first.recursion_available, Some(true));
    assert_eq!(first.case_preserved, Some(false));
    // A replayed run cannot try a transfer.
    assert_eq!(first.axfr_allowed, None);
    assert_eq!(first.nsec3param.as_deref(), Some(&[][..]));
    let second = deep
        .servers
        .iter()
        .find(|s| s.address.to_string() == NS3)
        .unwrap();
    assert_eq!(second.edns_version.rcode, None);
    assert_eq!(second.nsec3param, None);
    // The primary in the SOA is ns1, which resolves.
    assert_eq!(deep.mname.as_ref().unwrap().status, "answer");
    assert_eq!(deep.rname_domain.as_deref(), Some("good.example."));

    let found: Vec<(String, Severity, String)> = run_all(&obs)
        .into_iter()
        .map(|f| (f.check_id, f.severity, f.name))
        .collect();
    let expect = |id: &str, severity: Severity, name: &str| {
        assert!(
            found.contains(&(id.to_string(), severity, name.to_string())),
            "{id} {name} missing from {found:?}"
        );
    };
    // The test addresses are documentation addresses.
    expect("NET-02", Severity::Warning, "ns1.good.example.");
    expect("NET-02", Severity::Warning, "ns2.good.example.");
    expect("NSB-01", Severity::Warning, "ns2.good.example.");
    expect("NSB-03", Severity::Warning, "ns1.good.example.");
    expect("NSB-04", Severity::Notice, "ns1.good.example.");
    assert_eq!(found.len(), 5, "{found:?}");
}
