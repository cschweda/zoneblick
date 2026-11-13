//! The iterative resolver and prober, run offline against hand-built worlds.

mod common;

use common::*;
use zoneblick::observe::{Outcome, QType, Transport};
use zoneblick::resolver::ResolveError;

#[tokio::test]
async fn records_the_delegation_path_and_glue() {
    let obs = good_world().observe("good.example").await.unwrap();
    assert_eq!(obs.zone, "good.example.");
    assert!(obs.vantage.ipv4 && !obs.vantage.ipv6);

    let path = &obs.delegation_path;
    assert_eq!(path.len(), 2);
    assert_eq!(
        (path[0].from_zone.as_str(), path[0].to_zone.as_str()),
        (".", "example.")
    );
    assert_eq!(path[0].server_name.as_deref(), Some("a.root-servers.net."));
    assert_eq!(path[0].ns, ["ns.nic.example."]);
    assert_eq!(path[1].from_zone, "example.");
    assert_eq!(path[1].server_address.to_string(), TLD_SERVER);

    let parent = obs.parent().unwrap();
    assert_eq!(parent.ns, ["ns1.good.example.", "ns2.good.example."]);
    assert_eq!(parent.glue.len(), 2);

    assert_eq!(obs.ns_hosts.len(), 2);
    for host in &obs.ns_hosts {
        assert!(host.in_parent && host.in_child);
        assert_eq!(host.glue, host.resolved);
        assert!(host.cname.is_none() && host.resolve_error.is_none());
    }
}

#[tokio::test]
async fn keeps_each_servers_answers_separate() {
    let obs = broken_world().observe("broken.example.").await.unwrap();
    // Three servers, five apex queries each.
    assert_eq!(obs.probes.len(), 15);
    let serial = |server: &str| {
        obs.probes_for(server.parse().unwrap())
            .find(|p| p.qtype == QType::Soa && p.transport == Transport::Udp && p.edns)
            .and_then(|p| p.outcome.response())
            .and_then(|r| r.soa.as_ref())
            .map(|s| s.serial)
    };
    assert_eq!(serial(NS1), Some(2024111301));
    assert_eq!(serial(NS2), Some(2024111302));
    assert_eq!(serial(NS3), None);
    for probe in obs.probes_for(NS3.parse().unwrap()) {
        let r = probe.outcome.response().unwrap();
        assert_eq!(r.rcode, "REFUSED");
        assert!(!r.authoritative);
    }
}

#[tokio::test]
async fn follows_a_glueless_delegation() {
    // good.example. is delegated to a nameserver in another zone, no glue.
    let zone = "good.example.";
    let host = "ns.provider.example.";
    let mut w = World::new();
    for q in [zone, host] {
        for qtype in [QType::Ns, QType::A, QType::Aaaa] {
            w.delegate_tld(q, qtype);
        }
    }
    w.referral(TLD_SERVER, zone, QType::Ns, &[ns(zone, host)], &[]);
    for qtype in [QType::A, QType::Aaaa] {
        w.referral(
            TLD_SERVER,
            host,
            qtype,
            &[ns("provider.example.", "ns.provider.example.")],
            &[addr("ns.provider.example.", NS2)],
        );
    }
    w.serve_host(NS2, "provider.example.", host, &[NS2]);
    w.serve_apex(NS2, zone, 7, &[host]);

    let obs = w.observe(zone).await.unwrap();
    let parent = obs.parent().unwrap();
    assert!(parent.glue.is_empty());
    assert_eq!(obs.ns_hosts.len(), 1);
    assert!(obs.ns_hosts[0].glue.is_empty());
    assert_eq!(
        obs.ns_hosts[0].resolved,
        [NS2.parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(obs.probes.len(), 5);
}

#[tokio::test]
async fn records_a_cname_nameserver() {
    let zone = "good.example.";
    let mut w = good_world();
    // ns2 is an alias inside the zone.
    for server in [NS1, NS3] {
        for qtype in [QType::A, QType::Aaaa] {
            w.answer(
                server,
                "ns2.good.example.",
                qtype,
                &[cname("ns2.good.example.", "real.good.example.")],
            );
        }
        w.serve_host(server, zone, "real.good.example.", &[NS3]);
    }
    let obs = w.observe(zone).await.unwrap();
    let ns2 = obs
        .ns_hosts
        .iter()
        .find(|h| h.name == "ns2.good.example.")
        .unwrap();
    assert_eq!(ns2.cname.as_deref(), Some("real.good.example."));
    assert_eq!(ns2.resolved, [NS3.parse::<std::net::IpAddr>().unwrap()]);
}

#[tokio::test]
async fn retries_over_tcp_when_a_referral_is_truncated() {
    let zone = "good.example.";
    let mut w = good_world();
    w.reply_on(TLD_SERVER, Transport::Udp, true, zone, QType::Ns, |m| {
        m.metadata.truncation = true;
    });
    let obs = w.observe(zone).await.unwrap();
    assert_eq!(obs.parent().unwrap().ns.len(), 2);
}

#[tokio::test]
async fn nonexistent_zone_is_reported() {
    let mut w = World::new();
    w.delegate_tld("missing.example.", QType::Ns);
    w.nxdomain(TLD_SERVER, "missing.example.", QType::Ns, "example.");
    let err = w.observe("missing.example.").await.unwrap_err();
    assert!(matches!(err, ResolveError::ZoneNotFound { .. }), "{err}");
}

#[tokio::test]
async fn a_name_inside_a_zone_is_not_a_zone() {
    let mut w = good_world();
    let name = "www.good.example.";
    w.delegate_tld(name, QType::Ns);
    w.referral(
        TLD_SERVER,
        name,
        QType::Ns,
        &[ns("good.example.", "ns1.good.example.")],
        &[addr("ns1.good.example.", NS1)],
    );
    w.nodata(NS1, name, QType::Ns, "good.example.");
    match w.observe(name).await.unwrap_err() {
        ResolveError::NotAZone { enclosing, .. } => {
            assert_eq!(enclosing.as_deref(), Some("good.example."));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test]
async fn fails_when_no_nameserver_answers() {
    let zone = "good.example.";
    let mut w = World::new();
    w.delegate_tld(zone, QType::Ns);
    w.referral(
        TLD_SERVER,
        zone,
        QType::Ns,
        &[ns(zone, "ns1.good.example.")],
        &[addr("ns1.good.example.", NS1)],
    );
    // NS1 has no recorded exchanges at all, so every query to it fails.
    let err = w.observe(zone).await.unwrap_err();
    assert!(
        matches!(err, ResolveError::NoServerReachable { .. }),
        "{err}"
    );
}

#[tokio::test]
async fn fails_without_any_network() {
    let w = World::default();
    let err = w.observe("good.example.").await.unwrap_err();
    assert!(matches!(err, ResolveError::NoNetwork), "{err}");
}

#[tokio::test]
async fn a_timeout_is_kept_as_a_timeout() {
    let zone = "good.example.";
    let mut w = good_world();
    w.outcome(
        NS3,
        Transport::Tcp,
        true,
        zone,
        QType::Soa,
        zoneblick::resolver::RawOutcome::Timeout,
    );
    let obs = w.observe(zone).await.unwrap();
    let probe = obs
        .probes_for(NS3.parse().unwrap())
        .find(|p| p.qtype == QType::Soa && p.transport == Transport::Tcp)
        .unwrap();
    assert_eq!(probe.outcome, Outcome::Timeout);
}
