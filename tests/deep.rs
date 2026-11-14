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

/// A hosting company's nameserver, on an address that counts as public.
const HOSTER: &str = "8.8.4.4";

/// `good.example.` with `shop` delegated to a hosting company's
/// nameserver, which answers `rcode` when asked for the delegated name.
fn delegated_world(rcode: ResponseCode) -> World {
    let mut w = deep_world();
    let sub = "shop.good.example.";
    let cut = [ns(sub, "ns.hoster.example.")];
    // The zone's own server hands out the delegation.
    for name in [sub, "www.shop.good.example."] {
        w.referral(NS1, name, QType::Ns, &cut, &[]);
    }
    // The hosting company's nameserver resolves from the root.
    w.delegate_tld("ns.hoster.example.", QType::A);
    w.referral(
        TLD_SERVER,
        "ns.hoster.example.",
        QType::A,
        &[ns("hoster.example.", "ns.hoster.example.")],
        &[addr("ns.hoster.example.", HOSTER)],
    );
    w.answer(
        HOSTER,
        "ns.hoster.example.",
        QType::A,
        &[addr("ns.hoster.example.", HOSTER)],
    );
    if rcode == ResponseCode::NoError {
        w.answer(HOSTER, sub, QType::Soa, &[soa(sub, 1)]);
    } else {
        w.rcode(HOSTER, sub, &[QType::Soa], rcode);
    }
    w
}

/// Run a deep check of the delegated world, as `run` would after
/// collecting records for a name under the delegation.
async fn delegated_findings(rcode: ResponseCode) -> Vec<(Severity, String)> {
    let fixture = delegated_world(rcode).fixture(ZONE);
    let client = Arc::new(Client::replay(&fixture));
    let mut obs = observe_zone(client.clone(), ZONE, fixture.started_at_unix)
        .await
        .unwrap();
    obs.records.push(zoneblick::observe::RecordObservation {
        name: "www.shop.good.example.".to_string(),
        qtype: QType::A,
        ns_name: "ns1.good.example.".to_string(),
        address: NS1.parse().unwrap(),
        transport: Transport::Udp,
        outcome: zoneblick::observe::RecordOutcome::Timeout,
    });
    add_deep(client, &mut obs).await;
    let deep = obs.deep.as_ref().unwrap();
    assert_eq!(deep.subzones.len(), 1, "{:?}", deep.subzones);
    assert_eq!(deep.subzones[0].name, "shop.good.example.");
    assert_eq!(deep.subzones[0].servers[0].ns_name, "ns.hoster.example.");
    run_all(&obs)
        .into_iter()
        .filter(|f| f.check_id == "TKO-07")
        .map(|f| (f.severity, f.summary))
        .collect()
}

#[tokio::test]
async fn a_delegation_to_a_host_that_refuses_the_name_is_a_takeover_risk() {
    let found = delegated_findings(ResponseCode::Refused).await;
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, Severity::Critical);
    assert!(
        found[0]
            .1
            .starts_with("shop.good.example. is delegated to nameservers that do not serve it")
    );
    let found = delegated_findings(ResponseCode::ServFail).await;
    assert_eq!(found[0].0, Severity::Critical);
}

#[tokio::test]
async fn a_delegation_that_is_served_is_no_finding() {
    assert!(delegated_findings(ResponseCode::NoError).await.is_empty());
}

/// Needs the network. Run with `cargo test -- --ignored`.
///
/// Spamhaus and SpamCop keep test entries that are always listed, and
/// RIPE announces a prefix that is invalid on purpose. These show that the
/// real services answer in the form the probes read.
#[tokio::test]
#[ignore = "uses the live network"]
async fn live_blocklists_and_route_validation_answer_as_expected() {
    use zoneblick::observe::Vantage;
    use zoneblick::resolver::exposure::{blocklist_answer, parse_route_status, route_url};
    use zoneblick::resolver::iterate::Resolver;
    use zoneblick::resolver::{HttpOutcome, NetConfig};

    let client = Arc::new(Client::live(NetConfig::default()));
    let resolver = Resolver::new(
        client.clone(),
        Vantage {
            ipv4: true,
            ipv6: false,
        },
    );
    // 127.0.0.2 is the test address every list has on it.
    for (name, expect) in [
        ("2.0.0.127.zen.spamhaus.org.", "127.0.0.2"),
        ("2.0.0.127.bl.spamcop.net.", "127.0.0.2"),
        ("dbltest.com.dbl.spamhaus.org.", "127.0.1.2"),
    ] {
        let lookup = resolver.lookup(name, QType::A).await;
        let (codes, error) = blocklist_answer(&lookup);
        assert!(error.is_none(), "{name}: {error:?}");
        assert!(codes.iter().any(|c| c == expect), "{name}: {codes:?}");
    }
    // An address that is on no list.
    let lookup = resolver
        .lookup("1.0.0.127.zen.spamhaus.org.", QType::A)
        .await;
    assert_eq!(blocklist_answer(&lookup), (vec![], None));

    // RIPE's routing beacon 93.175.147.0/24 has an authorisation for
    // another network on purpose; 193.0.0.0/21 from AS3333 is RIPE's own.
    for (asn, prefix, expect) in [
        (12654, "93.175.147.0/24", "invalid_asn"),
        (3333, "193.0.0.0/21", "valid"),
    ] {
        let outcome = client
            .http_get_with(
                &route_url(asn, prefix),
                256 * 1024,
                std::time::Duration::from_secs(20),
            )
            .await;
        let HttpOutcome::Response { status: 200, body } = outcome else {
            panic!("no answer for {prefix}: {outcome:?}");
        };
        assert_eq!(parse_route_status(&body).as_deref(), Ok(expect), "{prefix}");
    }
}
