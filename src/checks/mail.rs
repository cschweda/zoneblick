//! Checks on how mail to and from the zone is secured in transit and
//! signed: TLS reporting (`POL-06`), TLSA records for the mail servers
//! (`POL-07`), DKIM keys (`POL-08`) and the BIMI record (`POL-09`).

use super::{Evidence, Finding, Severity};
use crate::observe::{Lookup, MailTransport, PolicyObservation, ZoneObservation};
use crate::resolver::policy::txt_value;

fn mail(obs: &ZoneObservation) -> Option<(&PolicyObservation, &MailTransport)> {
    let policy = obs.policy.as_ref()?;
    Some((policy, policy.mail.as_ref()?))
}

fn finding(
    check_id: &str,
    severity: Severity,
    name: &str,
    summary: String,
    details: Vec<String>,
) -> Finding {
    Finding::new(
        check_id,
        severity,
        name,
        summary,
        Evidence::ZoneDetail { details },
    )
}

/// The `tag=value` pairs of a record such as `v=DKIM1; k=rsa; p=...`.
/// Tag names are lowercased; white space around both is dropped.
fn tags(record: &str) -> Vec<(String, String)> {
    record
        .split(';')
        .filter_map(|part| {
            let (tag, value) = part.split_once('=')?;
            Some((tag.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect()
}

fn tag<'a>(tags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|(tag, _)| tag == name)
        .map(|(_, value)| value.as_str())
}

/// The TXT values of a lookup that start with `prefix`, compared without
/// regard to case.
fn records_with(lookup: &Lookup, prefix: &str) -> Vec<String> {
    lookup
        .rdata
        .iter()
        .map(|r| txt_value(r))
        .filter(|v| v.to_ascii_lowercase().starts_with(prefix))
        .collect()
}

/// POL-06: MTA-STS is published but nobody is told when delivery over TLS
/// fails, or the TLS reporting record cannot be used.
pub fn pol_06_tls_reporting(obs: &ZoneObservation) -> Vec<Finding> {
    let Some((policy, mail)) = mail(obs) else {
        return Vec::new();
    };
    let name = mail.tls_rpt.name.clone();
    let records = records_with(&mail.tls_rpt, "v=tlsrptv1");
    let mut problems = Vec::new();
    match records.as_slice() {
        [] => {
            // Without MTA-STS (or DANE) there is nothing to report on.
            let enforcing = policy.mta_sts.is_some()
                || mail.tlsa.iter().any(|l| l.exists() && !l.rdata.is_empty());
            if enforcing && mail.tls_rpt.is_empty_answer() {
                problems.push(
                    "mail servers are told to require TLS, but there is no TLS reporting record, so failed deliveries go unnoticed"
                        .to_string(),
                );
            }
        }
        [one] => {
            let rua = tags(one)
                .iter()
                .find(|(t, _)| t == "rua")
                .map(|(_, v)| v.clone());
            match rua {
                None => problems.push("the record has no 'rua' address to send reports to".into()),
                Some(rua) => {
                    for address in rua.split(',').map(str::trim) {
                        if !address.starts_with("mailto:") && !address.starts_with("https://") {
                            problems
                                .push(format!("'{address}' is not a mailto: or https: address"));
                        }
                    }
                }
            }
        }
        many => problems.push(format!(
            "there are {} TLS reporting records; receivers ignore all of them",
            many.len()
        )),
    }
    if problems.is_empty() {
        return Vec::new();
    }
    // The first problem is the summary; the rest and the record follow.
    let mut details: Vec<String> = problems[1..].to_vec();
    details.extend(records.iter().map(|r| format!("record: {r}")));
    vec![finding(
        "POL-06",
        Severity::Notice,
        &name,
        format!("TLS reporting for {}: {}", obs.zone, problems[0]),
        details,
    )]
}

/// Why a TLSA record cannot be used for mail, if it cannot (RFC 7672).
fn tlsa_problem(rdata: &str) -> Option<String> {
    let fields: Vec<&str> = rdata.split_whitespace().collect();
    let [usage, selector, matching, data] = fields.as_slice() else {
        return Some("the record is not in the form 'usage selector matching data'".into());
    };
    let number = |text: &str| text.parse::<u8>().ok();
    match number(usage) {
        Some(2 | 3) => {}
        Some(0 | 1) => {
            return Some(format!(
                "usage {usage} ties the certificate to a public authority, which mail servers do not check; use 3 (or 2)"
            ));
        }
        _ => return Some(format!("usage {usage} does not exist")),
    }
    if !matches!(number(selector), Some(0 | 1)) {
        return Some(format!("selector {selector} does not exist"));
    }
    let hex_len = match number(matching) {
        Some(0) => None,
        Some(1) => Some(64),
        Some(2) => Some(128),
        _ => return Some(format!("matching type {matching} does not exist")),
    };
    if !data.chars().all(|c| c.is_ascii_hexdigit()) || data.is_empty() {
        return Some("the certificate data is not hexadecimal".into());
    }
    match hex_len {
        Some(n) if data.len() != n => Some(format!(
            "the digest is {} hex digits long; matching type {matching} needs {n}",
            data.len()
        )),
        _ => None,
    }
}

/// POL-07: a mail server has TLSA records that sending servers cannot
/// use: wrong parameters, or published in a zone that is not signed.
pub fn pol_07_tlsa(obs: &ZoneObservation) -> Vec<Finding> {
    let Some((_, mail)) = mail(obs) else {
        return Vec::new();
    };
    // Whether this zone is chained to its parent with a DS record.
    let chained = obs
        .dnssec
        .as_ref()
        .and_then(|d| d.parent_ds.as_ref())
        .and_then(|p| p.records.as_ref())
        .map(|records| !records.is_empty());
    let mut findings = Vec::new();
    for lookup in mail.tlsa.iter().filter(|l| !l.rdata.is_empty()) {
        let mut details: Vec<String> = lookup
            .rdata
            .iter()
            .filter_map(|r| tlsa_problem(r).map(|why| format!("{r}: {why}")))
            .collect();
        let all_bad = details.len() == lookup.rdata.len();
        let in_zone = crate::observe::is_ancestor_or_equal(&obs.zone, &lookup.name);
        let unsigned = in_zone && chained == Some(false);
        if unsigned {
            details.push(format!(
                "{} is not signed with DNSSEC (no DS record at the parent), so sending servers ignore these records",
                obs.zone
            ));
        }
        if details.is_empty() {
            continue;
        }
        let summary = if unsigned {
            format!(
                "the TLSA records at {} have no effect: the zone is not signed",
                lookup.name
            )
        } else if all_bad {
            format!(
                "no TLSA record at {} can be used by sending mail servers",
                lookup.name
            )
        } else {
            format!(
                "some TLSA records at {} cannot be used by sending mail servers",
                lookup.name
            )
        };
        // Usable records beside bad ones still protect the server.
        let severity = if unsigned || all_bad {
            Severity::Warning
        } else {
            Severity::Notice
        };
        findings.push(finding("POL-07", severity, &lookup.name, summary, details));
    }
    findings
}

/// Decode base64, ignoring white space. `None` when it is not base64.
fn base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.chars().filter(|c| !c.is_whitespace()) {
        let value = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            '=' => continue,
            _ => return None,
        };
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// One DER element: its tag, its content, and what follows it.
fn der(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let len = rest[..count]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | *b as usize);
        (len, &rest[count..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// The size in bits of the RSA key in a DKIM `p=` value: a DER
/// SubjectPublicKeyInfo, or a bare RSAPublicKey.
fn rsa_bits(key: &[u8]) -> Option<usize> {
    let (0x30, outer, _) = der(key)? else {
        return None;
    };
    let (tag, first, rest) = der(outer)?;
    let modulus = match tag {
        // SubjectPublicKeyInfo: algorithm, then the key in a bit string.
        0x30 => {
            let _algorithm = first;
            let (0x03, bits, _) = der(rest)? else {
                return None;
            };
            let (0x30, inner, _) = der(bits.get(1..)?)? else {
                return None;
            };
            let (0x02, modulus, _) = der(inner)? else {
                return None;
            };
            modulus
        }
        // RSAPublicKey: the modulus comes first.
        0x02 => first,
        _ => return None,
    };
    let start = modulus.iter().position(|b| *b != 0)?;
    let significant = &modulus[start..];
    Some(significant.len() * 8 - significant[0].leading_zeros() as usize)
}

/// What is wrong with a DKIM key record, if anything, and how bad it is.
fn dkim_problem(record: &str) -> Option<(Severity, String)> {
    let tags = tags(record);
    let Some(p) = tag(&tags, "p") else {
        return Some((
            Severity::Warning,
            "the record has no 'p' tag, so it holds no key".into(),
        ));
    };
    if p.is_empty() {
        return Some((
            Severity::Warning,
            "the key is revoked (empty 'p' tag): mail signed with this selector fails DKIM".into(),
        ));
    }
    let Some(key) = base64(p) else {
        return Some((Severity::Warning, "the key is not valid base64".into()));
    };
    match tag(&tags, "k")
        .unwrap_or("rsa")
        .to_ascii_lowercase()
        .as_str()
    {
        "rsa" => match rsa_bits(&key) {
            None => Some((
                Severity::Warning,
                "the key cannot be read as an RSA key".into(),
            )),
            Some(bits) if bits < 1024 => Some((
                Severity::Warning,
                format!("the RSA key has {bits} bits; receivers reject keys under 1024 bits"),
            )),
            Some(bits) if bits < 2048 => Some((
                Severity::Notice,
                format!("the RSA key has {bits} bits; 2048 is the recommended minimum"),
            )),
            Some(_) => None,
        },
        "ed25519" => (key.len() != 32).then(|| {
            (
                Severity::Warning,
                format!("the Ed25519 key is {} bytes long, not 32", key.len()),
            )
        }),
        other => Some((
            Severity::Notice,
            format!("key type '{other}' is not one receivers know (rsa, ed25519)"),
        )),
    }
}

/// POL-08: a DKIM key is missing, revoked, unreadable or too short.
pub fn pol_08_dkim(obs: &ZoneObservation) -> Vec<Finding> {
    let Some((_, mail)) = mail(obs) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for d in &mail.dkim {
        let name = &d.lookup.name;
        // Any TXT record under _domainkey is taken as a key record.
        let records: Vec<String> = d.lookup.rdata.iter().map(|r| txt_value(r)).collect();
        if records.is_empty() {
            if d.asked_for && d.lookup.is_empty_answer() {
                findings.push(finding(
                    "POL-08",
                    Severity::Warning,
                    name,
                    format!(
                        "there is no DKIM key for selector '{}': mail signed with it fails DKIM",
                        d.selector
                    ),
                    vec![format!("{name} has no TXT record")],
                ));
            }
            continue;
        }
        let problem = if records.len() > 1 {
            Some((
                Severity::Warning,
                format!(
                    "there are {} records; receivers need exactly one",
                    records.len()
                ),
            ))
        } else {
            dkim_problem(&records[0])
        };
        if let Some((severity, why)) = problem {
            let mut details = Vec::new();
            details.extend(records.iter().map(|r| {
                // Keys are long; the start is enough to recognise one.
                let short: String = r.chars().take(80).collect();
                format!("record: {short}{}", if r.len() > 80 { "..." } else { "" })
            }));
            findings.push(finding(
                "POL-08",
                severity,
                name,
                format!("DKIM selector '{}': {why}", d.selector),
                details,
            ));
        }
    }
    findings
}

/// POL-09: a BIMI record is published but mail clients will not show the
/// logo: DMARC is not enforced, or the record cannot be used.
pub fn pol_09_bimi(obs: &ZoneObservation) -> Vec<Finding> {
    let Some((policy, mail)) = mail(obs) else {
        return Vec::new();
    };
    let records = records_with(&mail.bimi, "v=bimi1");
    let Some(record) = records.first() else {
        return Vec::new();
    };
    let mut problems = Vec::new();
    if records.len() > 1 {
        problems.push(format!("there are {} BIMI records", records.len()));
    }
    let tags = tags(record);
    match tag(&tags, "l") {
        // An empty `l=` is how a zone declines to take part.
        Some("") => return Vec::new(),
        None => problems.push("the record has no 'l' tag with the logo's address".into()),
        Some(logo) => {
            if !logo.starts_with("https://") {
                problems.push(format!(
                    "the logo address '{logo}' is not an https: address"
                ));
            } else if !logo
                .to_ascii_lowercase()
                .split('?')
                .next()
                .unwrap_or("")
                .ends_with(".svg")
            {
                problems.push(format!("the logo '{logo}' is not an SVG file"));
            }
        }
    }
    let dmarc = records_with(&policy.dmarc, "v=dmarc1");
    let enforced = dmarc.first().is_some_and(|r| {
        let tags = self::tags(r);
        let p = tag(&tags, "p").unwrap_or("").to_ascii_lowercase();
        let pct = tag(&tags, "pct").unwrap_or("100");
        matches!(p.as_str(), "quarantine" | "reject") && (p == "reject" || pct == "100")
    });
    if !enforced {
        problems.push(
            "DMARC is not enforced (it needs p=quarantine at pct=100, or p=reject), so mail clients ignore the record"
                .into(),
        );
    }
    if problems.is_empty() {
        return Vec::new();
    }
    let mut details: Vec<String> = problems[1..].to_vec();
    details.push(format!("record: {record}"));
    vec![finding(
        "POL-09",
        Severity::Notice,
        &mail.bimi.name,
        format!(
            "the BIMI record of {} has no effect: {}",
            obs.zone, problems[0]
        ),
        details,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::*;
    use crate::observe::{DkimSelector, QType};

    fn lookup(name: &str, qtype: QType, status: &str, rdata: &[&str]) -> Lookup {
        Lookup {
            name: name.to_string(),
            qtype,
            status: status.to_string(),
            rdata: rdata.iter().map(|r| r.to_string()).collect(),
            cname: None,
            enclosing: None,
            error: None,
        }
    }

    fn txt(name: &str, values: &[&str]) -> Lookup {
        let quoted: Vec<String> = values.iter().map(|v| format!("\"{v}\"")).collect();
        let refs: Vec<&str> = quoted.iter().map(String::as_str).collect();
        let status = if values.is_empty() {
            "nxdomain"
        } else {
            "answer"
        };
        lookup(name, QType::Txt, status, &refs)
    }

    /// A zone with mail, a DMARC policy and nothing else to complain about.
    fn base(dmarc: &str) -> ZoneObservation {
        let mut obs = healthy();
        obs.policy = Some(PolicyObservation {
            apex_txt: txt("example.test.", &[]),
            dmarc: txt("_dmarc.example.test.", &[dmarc]),
            caa: lookup("example.test.", QType::Caa, "nodata", &[]),
            mx: lookup(
                "example.test.",
                QType::Mx,
                "answer",
                &["10 mail.example.test."],
            ),
            spf: None,
            mta_sts: None,
            targets: Vec::new(),
            wildcard: None,
            services: Vec::new(),
            mail: Some(MailTransport {
                tls_rpt: txt("_smtp._tls.example.test.", &[]),
                bimi: txt("default._bimi.example.test.", &[]),
                dkim: Vec::new(),
                tlsa: Vec::new(),
            }),
        });
        obs
    }

    fn mail_of(obs: &mut ZoneObservation) -> &mut MailTransport {
        obs.policy.as_mut().unwrap().mail.as_mut().unwrap()
    }

    fn all(obs: &ZoneObservation) -> Vec<(String, Severity, String)> {
        [
            pol_06_tls_reporting(obs),
            pol_07_tlsa(obs),
            pol_08_dkim(obs),
            pol_09_bimi(obs),
        ]
        .into_iter()
        .flatten()
        .map(|f| (f.check_id, f.severity, f.summary))
        .collect()
    }

    fn rsa_key(bits: usize) -> String {
        // SubjectPublicKeyInfo with a modulus of `bits` bits, top bit set.
        fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            match content.len() {
                n if n < 0x80 => out.push(n as u8),
                n if n < 0x100 => out.extend([0x81, n as u8]),
                n => out.extend([0x82, (n >> 8) as u8, n as u8]),
            }
            out.extend(content);
            out
        }
        let mut modulus = vec![0u8; bits / 8 + 1];
        modulus[1] = 0x80;
        *modulus.last_mut().unwrap() = 1;
        let key = tlv(0x30, &[tlv(0x02, &modulus), tlv(0x02, &[1, 0, 1])].concat());
        let algorithm = tlv(
            0x30,
            &[
                tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1]),
                tlv(0x05, &[]),
            ]
            .concat(),
        );
        let spki = tlv(
            0x30,
            &[algorithm, tlv(0x03, &[vec![0], key].concat())].concat(),
        );
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in spki.chunks(3) {
            let n =
                chunk.iter().fold(0u32, |acc, b| (acc << 8) | *b as u32) << (8 * (3 - chunk.len()));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn key_sizes_are_read() {
        assert_eq!(rsa_bits(&base64(&rsa_key(1024)).unwrap()), Some(1024));
        assert_eq!(rsa_bits(&base64(&rsa_key(2048)).unwrap()), Some(2048));
        assert_eq!(rsa_bits(&base64(&rsa_key(512)).unwrap()), Some(512));
        assert_eq!(rsa_bits(b"not a key"), None);
        assert_eq!(base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64("a GVs\nbG8"), Some(b"hello".to_vec()));
        assert_eq!(base64("not*base64"), None);
    }

    #[test]
    fn a_zone_with_nothing_published_is_silent() {
        assert_eq!(all(&base("v=DMARC1; p=reject")), []);
        // And so is one where the lookups were never made.
        let mut obs = base("v=DMARC1; p=reject");
        obs.policy.as_mut().unwrap().mail = None;
        assert_eq!(all(&obs), []);
    }

    #[test]
    fn tls_reporting() {
        let mut obs = base("v=DMARC1; p=reject");
        mail_of(&mut obs).tlsa = vec![lookup(
            "_25._tcp.mail.example.test.",
            QType::Tlsa,
            "answer",
            &[&format!("3 1 1 {}", "ab".repeat(32))],
        )];
        let found = all(&obs);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            (found[0].0.as_str(), found[0].1),
            ("POL-06", Severity::Notice)
        );
        assert!(
            found[0].2.contains("no TLS reporting record"),
            "{}",
            found[0].2
        );

        mail_of(&mut obs).tls_rpt = txt(
            "_smtp._tls.example.test.",
            &["v=TLSRPTv1; rua=mailto:tls@example.test, https://r.example.test/x"],
        );
        assert_eq!(all(&obs), []);
        mail_of(&mut obs).tls_rpt = txt("_smtp._tls.example.test.", &["v=TLSRPTv1; rua=tls@x"]);
        assert!(all(&obs)[0].2.contains("not a mailto: or https: address"));
        mail_of(&mut obs).tls_rpt = txt("_smtp._tls.example.test.", &["v=TLSRPTv1;"]);
        assert!(all(&obs)[0].2.contains("no 'rua' address"));
    }

    #[test]
    fn tlsa_records() {
        let mut obs = base("v=DMARC1; p=reject");
        mail_of(&mut obs).tls_rpt = txt(
            "_smtp._tls.example.test.",
            &["v=TLSRPTv1; rua=mailto:t@example.test"],
        );
        let good = format!("3 1 1 {}", "ab".repeat(32));
        let short = "3 1 1 abcd".to_string();
        let pkix = format!("1 1 1 {}", "ab".repeat(32));
        let set = |obs: &mut ZoneObservation, records: &[&str]| {
            mail_of(obs).tlsa = vec![lookup(
                "_25._tcp.mail.example.test.",
                QType::Tlsa,
                "answer",
                records,
            )];
        };
        set(&mut obs, &[&good]);
        assert_eq!(all(&obs), []);
        set(&mut obs, &[&good, &short]);
        let found = all(&obs);
        assert_eq!(found[0].1, Severity::Notice);
        assert!(found[0].2.starts_with("some TLSA records"));
        set(&mut obs, &[&short, &pkix]);
        let found = pol_07_tlsa(&obs);
        assert_eq!(found[0].severity, Severity::Warning);
        let Evidence::ZoneDetail { details } = &found[0].evidence else {
            panic!()
        };
        assert!(details[0].contains("needs 64"), "{details:?}");
        assert!(details[1].contains("public authority"), "{details:?}");
        // A mail server in someone else's zone is not judged on signing.
        mail_of(&mut obs).tlsa = vec![lookup(
            "_25._tcp.mx.provider.example.",
            QType::Tlsa,
            "answer",
            &[&good],
        )];
        assert_eq!(all(&obs), []);
    }

    #[test]
    fn dkim_keys() {
        let mut obs = base("v=DMARC1; p=reject");
        let selector = |name: &str, asked_for: bool, values: &[&str]| DkimSelector {
            selector: name.to_string(),
            asked_for,
            lookup: txt(&format!("{name}._domainkey.example.test."), values),
        };
        let strong = format!("v=DKIM1; k=rsa; p={}", rsa_key(2048));
        let weak = format!("v=DKIM1; p={}", rsa_key(512));
        let medium = format!("k=rsa; p={}", rsa_key(1024));
        mail_of(&mut obs).dkim = vec![
            selector("default", false, &[]),
            selector("google", false, &[&strong]),
            selector("s1", false, &[&weak]),
            selector("s2", false, &[&medium]),
            selector("old", true, &["v=DKIM1; p="]),
            selector("gone", true, &[]),
            selector(
                "ed",
                true,
                &["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="],
            ),
        ];
        let found = all(&obs);
        let got: Vec<(Severity, &str)> = found.iter().map(|f| (f.1, f.2.as_str())).collect();
        assert_eq!(got.len(), 4, "{got:?}");
        assert!(
            got[0].0 == Severity::Warning && got[0].1.contains("'s1': the RSA key has 512 bits")
        );
        assert!(
            got[1].0 == Severity::Notice && got[1].1.contains("'s2': the RSA key has 1024 bits")
        );
        assert!(got[2].0 == Severity::Warning && got[2].1.contains("'old': the key is revoked"));
        assert!(
            got[3].0 == Severity::Warning && got[3].1.contains("no DKIM key for selector 'gone'")
        );
    }

    #[test]
    fn bimi_needs_enforced_dmarc() {
        let record = "v=BIMI1; l=https://example.test/logo.svg; a=https://example.test/vmc.pem";
        let with = |dmarc: &str, bimi: &str| {
            let mut obs = base(dmarc);
            mail_of(&mut obs).bimi = txt("default._bimi.example.test.", &[bimi]);
            all(&obs)
        };
        assert_eq!(with("v=DMARC1; p=reject", record), []);
        assert_eq!(with("v=DMARC1; p=quarantine", record), []);
        let found = with("v=DMARC1; p=none", record);
        assert_eq!(found[0].0, "POL-09");
        assert!(
            found[0].2.contains("DMARC is not enforced"),
            "{}",
            found[0].2
        );
        assert!(!with("v=DMARC1; p=quarantine; pct=50", record).is_empty());
        assert!(
            with(
                "v=DMARC1; p=reject",
                "v=BIMI1; l=http://example.test/logo.png"
            )[0]
            .2
            .contains("not an https: address")
        );
        // An empty logo address declines BIMI; that is not a mistake.
        assert_eq!(with("v=DMARC1; p=none", "v=BIMI1; l=; a="), []);
    }
}
