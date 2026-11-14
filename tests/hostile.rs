//! Red-team tests: everything zoneblick reads from the network is treated
//! as written by an attacker. Recorded answers are corrupted at random and
//! fed back through the whole pipeline, and the parsers of raw data are
//! given random bytes. Nothing here may panic or run away; wrong answers
//! must come out as errors or findings.

mod common;

use std::sync::Arc;

use common::*;
use zoneblick::checks::run_all;
use zoneblick::output::{Report, human, json, sarif};
use zoneblick::resolver::{
    Client, Fixture, HttpOutcome, RawOutcome, add_deep, add_dkim_selectors, observe_zone_records,
};

/// A small deterministic generator, so a failure can be repeated.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max + 1);
        (0..len).map(|_| self.next() as u8).collect()
    }
    /// Text with the characters parsers care about over-represented.
    fn text(&mut self, max: usize) -> String {
        const SPICE: &[&str] = &[
            "\"",
            "\\",
            ";",
            "(",
            ")",
            "=",
            " ",
            "\n",
            "\t",
            ".",
            "*",
            "@",
            "$ORIGIN ",
            "IN ",
            "TXT ",
            "A ",
            "v=DKIM1",
            "p=",
            "<",
            ">",
            "&",
            "{",
            "}",
            "[",
            "]",
            ",",
            ":",
            "0",
            "9",
            "-",
            "T",
            "Z",
            "+",
            "é",
            "\u{1b}[31m",
            "\u{0}",
            "%",
            "/",
        ];
        let mut out = String::new();
        for _ in 0..self.below(max + 1) {
            if self.below(3) == 0 {
                out.push((b'a' + self.below(26) as u8) as char);
            } else {
                out.push_str(SPICE[self.below(SPICE.len())]);
            }
        }
        out
    }
}

fn corrupt(rng: &mut Rng, wire: &mut Vec<u8>) {
    match rng.below(10) {
        // Cut the message short.
        0 => wire.truncate(rng.below(wire.len() + 1)),
        // Replace it with noise.
        1 => *wire = rng.bytes(600),
        // Leave it alone.
        2 | 3 => {}
        // Flip a few bytes: lengths, counts, pointers and types all move.
        _ => {
            for _ in 0..1 + rng.below(6) {
                if !wire.is_empty() {
                    let at = rng.below(wire.len());
                    wire[at] = rng.next() as u8;
                }
            }
        }
    }
}

fn hostile_copy(fixture: &Fixture, rng: &mut Rng) -> Fixture {
    let mut f = fixture.clone();
    // A few answers per run, so that most runs get past the first steps
    // and the damage lands in every part of the pipeline over time.
    for _ in 0..1 + rng.below(4) {
        let at = rng.below(f.exchanges.len());
        if let Some(RawOutcome::Response { wire }) = f.exchanges.get_mut(at).map(|e| &mut e.outcome)
        {
            corrupt(rng, wire);
        }
    }
    for http in &mut f.http {
        if let HttpOutcome::Response { status, body } = &mut http.outcome {
            match rng.below(4) {
                0 => *body = rng.text(400),
                1 => body.truncate(rng.below(body.len() + 1).min(body.len())),
                2 => *status = (rng.next() % 600) as u16,
                _ => {}
            }
            // Truncating may split a character; keep the body valid text.
            while !body.is_char_boundary(body.len()) {
                body.pop();
            }
        }
    }
    f
}

/// Run everything a deep stored run does over a fixture and render every
/// output format. Errors are fine; panics are not.
async fn whole_pipeline(fixture: &Fixture, names: &[String]) -> bool {
    let client = Arc::new(Client::replay(fixture));
    let Ok(mut obs) = observe_zone_records(
        client.clone(),
        &fixture.zone,
        fixture.started_at_unix,
        names,
    )
    .await
    else {
        return false;
    };
    add_dkim_selectors(client.clone(), &mut obs, &["s1".to_string()]).await;
    add_deep(client, &mut obs).await;
    let findings = run_all(&obs);
    let report = Report::new(obs, findings);
    let _ = human::render(&report, true);
    let _ = json::render(&report);
    let _ = sarif::render(&report);
    true
}

fn file_fixture(name: &str) -> Fixture {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupted_answers_never_crash_a_run() {
    let names = |zone: &str, hosts: &[&str]| -> Vec<String> {
        hosts.iter().map(|h| format!("{h}.{zone}")).collect()
    };
    let cases: Vec<(Fixture, Vec<String>)> = vec![
        (file_fixture("good.example.json"), vec![]),
        (file_fixture("broken.example.json"), vec![]),
        (file_fixture("example.com.json"), vec![]),
        (
            file_fixture("drift.example.after.json"),
            names("drift.example.", &["www", "api", "shop", "staging"]),
        ),
        (
            policy_world().fixture(POLICY_ZONE),
            names(POLICY_ZONE, &["app"]),
        ),
        (
            exposed_world().fixture(POLICY_ZONE),
            names(POLICY_ZONE, &["app"]),
        ),
        (signed_world(true).fixture(SIGNED_ZONE), vec![]),
        (signed_world(false).fixture(SIGNED_ZONE), vec![]),
    ];
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    let (mut runs, mut completed) = (0, 0);
    for (fixture, names) in &cases {
        // The clean fixture first, so a failure below is about corruption.
        assert!(whole_pipeline(fixture, names).await, "{}", fixture.zone);
        for _ in 0..400 {
            let hostile = hostile_copy(fixture, &mut rng);
            // A run on hostile data must also end: no endless referral or
            // alias chase.
            let done = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                whole_pipeline(&hostile, names),
            )
            .await
            .expect("a run over hostile answers must finish");
            runs += 1;
            completed += usize::from(done);
        }
    }
    // Most corrupted runs must get as far as the checks and the renderers,
    // or this test would only exercise the first few queries.
    assert!(completed * 2 > runs, "{completed} of {runs} runs completed");
}

#[test]
fn parsers_of_raw_data_survive_random_input() {
    use zoneblick::dnssec::{Dnskey, parse_dnskey, parse_ds, parse_rrsig};
    let mut rng = Rng(0x0bad_cafe_dead_beef);
    for _ in 0..20_000 {
        let bytes = rng.bytes(120);
        let _ = parse_ds(&bytes);
        let _ = parse_rrsig(&bytes);
        let key = parse_dnskey(&bytes);
        // A signature of any shape, checked against a key of any shape.
        let keys: Vec<Dnskey> = key.into_iter().collect();
        let sig = rng.bytes(150);
        let set = vec![rng.bytes(40), rng.bytes(40)];
        for rtype in [1u16, 6, 43, 48] {
            let mut rrsig = sig.clone();
            if rrsig.len() > 18 {
                rrsig[0..2].copy_from_slice(&rtype.to_be_bytes());
                if let Some(k) = keys.first() {
                    // Aim the signature at the key, so verification is tried.
                    rrsig[2] = k.algorithm;
                    rrsig[16..18].copy_from_slice(&k.key_tag.to_be_bytes());
                }
            }
            let _ =
                zoneblick::verify::verify_rrset("www.example.test.", rtype, &set, &[&rrsig], &keys);
        }
    }
}

#[test]
fn parsers_of_text_survive_random_input() {
    let mut rng = Rng(0x7e57_7e57_7e57_7e57);
    let zone = "example.org.";
    for _ in 0..20_000 {
        let text = rng.text(60);
        let _ = zoneblick::zonefile::parse(zone, &text);
        for rtype in zoneblick::zonefile::COMPARED {
            let _ = zoneblick::zonefile::comparable(rtype, &text);
        }
        let _ = zoneblick::registration::parse_rfc3339(&text);
        let _ = zoneblick::registration::parse_bootstrap(&text, "org");
        let _ = zoneblick::registration::parse_rdap(zone, "https://rdap.example/", &text);
        let _ = zoneblick::discover::parse_ct(zone, &text);
        let _ = zoneblick::discover::parse_ct_certificates(zone, &text);
        let _ = zoneblick::discover::parse_digitalocean(zone, &text);
        let _ = zoneblick::providers::parse_cloudflare_zone(&text);
        let _ = zoneblick::providers::parse_cloudflare_records(zone, &text);
        let _ = zoneblick::providers::parse_gandi(zone, &text);
        let _ = zoneblick::providers::parse_hetzner(zone, &text);
        let _ = zoneblick::providers::parse_route53_zone(zone, &text);
        let _ = zoneblick::providers::parse_route53_records(zone, &text);
        let _ = zoneblick::providers::parse_aws_credentials(&text);
        let _ = zoneblick::config::Config::parse(&text);
        let _ = zoneblick::config::parse_duration(&text);
        for signature in zoneblick::signatures::SIGNATURES {
            let _ = signature.matches(404, &text);
        }
    }
    // Structured but hostile: valid JSON and XML shapes with wrong types.
    for body in [
        r#"{"services":[[[1,2],"x"],[["org"],[null,7,"https://x"]]]}"#,
        r#"{"status":[1,{},null],"events":[{"eventAction":"expiration","eventDate":99}],"entities":[{"roles":"registrar","vcardArray":[1]}],"nameservers":[{"ldhName":7}]}"#,
        r#"[{"not_after":"9999-99-99T99:99:99","name_value":7,"issuer_name":[]}]"#,
        r#"{"result":[{"id":7}],"result_info":{"total_pages":-1}}"#,
        "<HostedZone><Id><Name></Id></Name></HostedZone><ResourceRecordSet><Name>",
    ] {
        let _ = zoneblick::registration::parse_bootstrap(body, "org");
        let _ = zoneblick::registration::parse_rdap(zone, "u", body);
        let _ = zoneblick::discover::parse_ct_certificates(zone, body);
        let _ = zoneblick::providers::parse_cloudflare_zone(body);
        let _ = zoneblick::providers::parse_cloudflare_records(zone, body);
        let _ = zoneblick::providers::parse_route53_zone(zone, body);
        let _ = zoneblick::providers::parse_route53_records(zone, body);
    }
}

#[tokio::test]
async fn record_data_cannot_carry_control_characters_into_output() {
    use zoneblick::observe::QType;
    // A DMARC record that tries to drive the terminal: an escape sequence
    // that sets the window title, one that clears the screen, a bell, and
    // a carriage return to overwrite the line.
    let evil = "v=DMARC1; p=none; \u{1b}]0;owned\u{7}\u{1b}[2J\rCLEAN <img src=x onerror=alert(1)>";
    let mut world = policy_world();
    for server in [NS1, NS3] {
        world.serve_name(
            server,
            POLICY_ZONE,
            "_dmarc.policy.example.",
            &[txt("_dmarc.policy.example.", evil)],
        );
        // And a mail server name with an escape in a label.
        world.answer(
            server,
            POLICY_ZONE,
            QType::Mx,
            &[mx(POLICY_ZONE, 10, "mx.policy.example.")],
        );
    }
    let obs = world.observe(POLICY_ZONE).await.unwrap();
    let findings = run_all(&obs);
    assert!(findings.iter().any(|f| f.check_id == "POL-02"));
    let report = Report::new(obs, findings);
    for (what, text) in [
        ("text", human::render(&report, false)),
        ("json", json::render(&report)),
        ("sarif", sarif::render(&report)),
    ] {
        let bad: Vec<char> = text
            .chars()
            .filter(|c| c.is_control() && *c != '\n')
            .collect();
        assert!(
            bad.is_empty(),
            "{what} output holds control characters: {bad:?}"
        );
        // The visible part of the record is still reported (SARIF holds
        // the summaries only, not the evidence).
        assert!(what == "sarif" || text.contains("CLEAN"), "{what}");
    }
    // With colour on, the only escape sequences are zoneblick's own.
    let coloured = human::render(&report, true);
    for (i, _) in coloured.match_indices('\u{1b}') {
        let rest = &coloured[i + 1..];
        let end = rest.find('m').expect("a colour sequence ends in m");
        assert!(
            rest.starts_with('[') && rest[1..end].chars().all(|c| c.is_ascii_digit() || c == ';'),
            "unexpected escape sequence: {:?}",
            &rest[..end + 1]
        );
    }
}

#[tokio::test]
async fn a_zone_that_lists_hundreds_of_nameservers_is_cut_short() {
    use zoneblick::observe::QType;
    use zoneblick::resolver::probe::MAX_NS_NAMES;
    // The zone's own servers list 300 extra nameservers, none of which
    // resolves. Chasing each would take minutes against live tarpits.
    let zone = "good.example.";
    let mut world = good_world();
    let mut listed = vec![ns(zone, "ns1.good.example."), ns(zone, "ns2.good.example.")];
    for i in 0..300 {
        listed.push(ns(zone, &format!("ns{i}.tarpit.example.")));
    }
    for server in [NS1, NS3] {
        world.answer(server, zone, QType::Ns, &listed);
    }
    let fixture = world.fixture(zone);
    let client = Arc::new(Client::replay(&fixture));
    let obs = zoneblick::resolver::observe_zone(client.clone(), zone, fixture.started_at_unix)
        .await
        .unwrap();
    assert_eq!(obs.ns_hosts.len(), 302);
    let skipped = obs
        .ns_hosts
        .iter()
        .filter(|h| {
            h.resolve_error
                .as_deref()
                .is_some_and(|e| e.starts_with("not checked: the zone lists more than"))
        })
        .count();
    assert_eq!(skipped, 302 - MAX_NS_NAMES);
    // The query count stays small: a few per name that was followed up.
    assert!(
        client.queries_sent() < 400,
        "{} queries",
        client.queries_sent()
    );
    // And the flood itself is reported.
    let findings = run_all(&obs);
    assert!(
        findings.iter().any(|f| f.check_id == "DEL-01"),
        "{findings:?}"
    );
}

#[test]
fn zoneblick_never_connects_to_this_machine_or_a_metadata_service() {
    use zoneblick::resolver::policy::not_public;
    use zoneblick::resolver::transport::never_contacted;
    let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    for refused in [
        "127.0.0.1",
        "127.9.9.9",
        "169.254.169.254",
        "0.0.0.0",
        "255.255.255.255",
        "224.0.0.251",
        "::1",
        "::",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
    ] {
        assert!(never_contacted(ip(refused)).is_some(), "{refused}");
        assert!(not_public(ip(refused)).is_some(), "{refused}");
    }
    // Private ranges may hold real nameservers of internal zones, so DNS
    // goes there, but pages are fetched from public addresses only.
    for private in [
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.9",
        "100.64.0.1",
        "fd00::5",
        "::ffff:10.0.0.5",
    ] {
        assert!(never_contacted(ip(private)).is_none(), "{private}");
        assert!(not_public(ip(private)).is_some(), "{private}");
    }
    for public in ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"] {
        assert!(never_contacted(ip(public)).is_none() && not_public(ip(public)).is_none());
    }
}

#[test]
fn escapes_in_record_data_stay_escaped_in_drift_evidence() {
    use zoneblick::zonefile::{comparable, parse};
    // The run recorded these with the control characters already written
    // as \DDD. Reading them as zone-file fields must not turn them back.
    for (rtype, recorded) in [
        ("TXT", r#""ok \027[2J\027[H\010::stop-commands::x""#),
        ("CAA", r#"0 issue "ca.example\027]0;owned\007""#),
        ("CNAME", r"evil\027[31m.example.net."),
    ] {
        let shown = comparable(rtype, recorded);
        assert!(!shown.chars().any(|c| c.is_control()), "{rtype}: {shown:?}");
    }
    // The same for a zone file that itself holds escapes.
    let sets = parse("example.org.", "www TXT \"a\\027[2Jb\\010c\"\n").unwrap();
    assert!(
        !sets[0].rdata[0].chars().any(|c| c.is_control()),
        "{sets:?}"
    );
    // Values that differ only in such bytes still compare as different.
    assert_ne!(
        comparable("TXT", r#""a\027b""#),
        comparable("TXT", r#""a\028b""#)
    );
}

#[cfg(unix)]
#[test]
fn a_new_database_is_private_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;
    let path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("private.sqlite");
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    let store = zoneblick::store::Store::open(&path).unwrap();
    store.add_zone("example.org.", 1).unwrap();
    for suffix in ["", "-wal", "-shm"] {
        let file = format!("{}{suffix}", path.display());
        if let Ok(meta) = std::fs::metadata(&file) {
            assert_eq!(meta.permissions().mode() & 0o077, 0, "{file}");
        }
    }
}

#[test]
fn record_names_cannot_bend_a_web_address() {
    use zoneblick::resolver::policy::{not_public, plain_host};
    for good in [
        "www.example.org.",
        "a-b_c.example.org",
        "xn--bcher-kva.example.",
    ] {
        assert!(plain_host(good), "{good}");
    }
    // A name is bytes; these would change the host or path of a URL, or
    // read as an address.
    for bad in [
        "169.254.169.254/x.example.org.",
        "user@127.0.0.1.example.org.",
        "a#b.example.org.",
        "a:80.example.org.",
        "127.0.0.1",
        "2130706433",
        "0x7f.0.0.1",
        "a b.example.org.",
        "",
    ] {
        assert!(!plain_host(bad), "{bad}");
    }
    let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    // IPv6 forms with an IPv4 address inside, and more special IPv4 blocks.
    for refused in [
        "64:ff9b::7f00:1",
        "64:ff9b::a9fe:a9fe",
        "2002:7f00:1::",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "::7f00:1",
        "192.0.0.8",
        "198.18.0.1",
        "192.88.99.1",
    ] {
        assert!(not_public(ip(refused)).is_some(), "{refused}");
    }
    assert!(not_public(ip("2606:4700::6810:84e5")).is_none());
    assert!(not_public(ip("192.0.1.1")).is_none());
}

#[test]
fn the_name_limit_never_drops_a_name_the_user_listed() {
    use std::collections::BTreeSet;
    use zoneblick::serve::{MAX_NAMES_PER_ZONE, cap_names};
    // 1,500 discovered names that sort before the user's own.
    let mut names: Vec<String> = (0..1500).map(|i| format!("a{i:04}.example.org.")).collect();
    let wanted: BTreeSet<String> = ["www.example.org.", "zzz.example.org."]
        .map(String::from)
        .into();
    names.extend(wanted.iter().cloned());
    let dropped = cap_names(&mut names, &wanted);
    assert_eq!(names.len(), MAX_NAMES_PER_ZONE);
    assert_eq!(dropped, 502);
    assert!(wanted.iter().all(|w| names.contains(w)));
    // Under the limit nothing is dropped.
    let mut few = vec!["b.example.org.".to_string(), "a.example.org.".to_string()];
    assert_eq!(cap_names(&mut few, &wanted), 0);
    assert_eq!(few, ["a.example.org.", "b.example.org."]);
}

#[test]
fn certificates_and_tlsa_records_of_any_shape_are_survived() {
    use zoneblick::resolver::smtp::{public_key_info, tlsa_matches};
    let mut rng = Rng(0x7157_a000_dead_0001);
    for _ in 0..20_000 {
        let cert = rng.bytes(300);
        let _ = public_key_info(&cert);
        // DER that starts plausibly and then lies about its lengths.
        let mut nested = vec![0x30, 0x82, rng.next() as u8, rng.next() as u8, 0x30, 0x84];
        nested.extend(rng.bytes(40));
        let _ = public_key_info(&nested);
        let record = format!(
            "{} {} {} {}",
            rng.below(5),
            rng.below(4),
            rng.below(4),
            rng.text(20)
        );
        let _ = tlsa_matches(&record, &[cert, nested]);
        let _ = tlsa_matches(&rng.text(30), &[]);
    }
}

#[test]
fn a_hostile_mail_server_cannot_hang_or_crash_the_certificate_check() {
    use std::io::Write;
    use std::net::TcpListener;
    use zoneblick::resolver::smtp::starttls_certificates;
    // Each server sends its bytes at once and then holds the line open.
    let serve = |bytes: Vec<u8>| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(&bytes);
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        });
        addr
    };
    let mut rng = Rng(0x5a17_0000_0000_0042);
    let mut cases: Vec<Vec<u8>> = vec![
        // A greeting that never ends its line.
        [b"220 ".to_vec(), vec![b'a'; 100_000]].concat(),
        // Continuation lines without end.
        "220-more\r\n".repeat(10_000).into_bytes(),
        // Not text at all.
        vec![0xff; 5000],
        // A code that is not a number, and an empty line.
        b"abc hello\r\n".to_vec(),
        b"\r\n".to_vec(),
        // Unicode where the code should be: must not split a character.
        "é20 hi\r\n".as_bytes().to_vec(),
    ];
    for _ in 0..20 {
        cases.push(rng.bytes(400));
    }
    for bytes in cases {
        let started = std::time::Instant::now();
        let result = starttls_certificates(serve(bytes), "mail.example.test.");
        assert!(result.is_err());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(15),
            "took {:?}",
            started.elapsed()
        );
    }
}

#[test]
fn a_hostile_zone_file_cannot_crash_the_plan_or_inject_into_its_output() {
    use zoneblick::plan::{Plan, lint, outside_targets};
    use zoneblick::zonefile::parse_full;
    let mut rng = Rng(0x91a7_0000_0000_0007);
    let zone = "example.org.";
    for _ in 0..20_000 {
        let text = rng.text(80);
        if let Err(message) = parse_full(zone, &text) {
            assert!(
                !message.chars().any(|c| c.is_control()),
                "{message:?} from {text:?}"
            );
        }
        if let Ok(parsed) = parse_full(zone, &text) {
            let issues = lint(zone, &parsed);
            let _ = outside_targets(zone, &parsed);
            let out = Plan::new(zone, "f", issues, None).render();
            assert!(
                !out.chars().any(|c| c.is_control() && c != '\n'),
                "{out:?} from {text:?}"
            );
        }
    }
    // A pull request's zone file that tries to speak to the CI log: the
    // escapes for a line break and for ESC must stay escapes.
    let evil = "www CNAME a\nwww TXT \"x\\010::error::owned\\027[2J\"\n";
    // In a name, the same escapes make the file unreadable; the message
    // that says so quotes the name and must not carry them either.
    let refused = parse_full(zone, "x\\010::stop-commands::y A 192.0.2.1\n").unwrap_err();
    assert!(!refused.chars().any(|c| c.is_control()), "{refused:?}");
    let refused = parse_full(zone, "$\\010::error::x 1\n").unwrap_err();
    assert!(!refused.chars().any(|c| c.is_control()), "{refused:?}");
    let parsed = parse_full(zone, evil).unwrap();
    let out = Plan::new(zone, "f", lint(zone, &parsed), None).render();
    for line in out.lines() {
        assert!(!line.trim_start().starts_with("::"), "{out}");
    }
    assert!(!out.contains('\u{1b}'));
    // Many names under many wildcards and delegations stay fast.
    let mut big = String::new();
    for i in 0..3000 {
        big.push_str(&format!(
            "n{i} MX 10 t{i}.a.b.c.d\n*.w{i} A 192.0.2.1\ns{i} NS ns.s{i}\n"
        ));
    }
    let started = std::time::Instant::now();
    let parsed = parse_full(zone, &big).unwrap();
    let _ = lint(zone, &parsed);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
}
