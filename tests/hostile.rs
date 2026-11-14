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
