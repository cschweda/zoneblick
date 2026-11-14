//! The certificate checks (`CRT`). They read the certificates that
//! Certificate Transparency logs list for the zone, so they give nothing
//! unless the run read the logs (`--discover ct`).

use std::collections::{BTreeMap, BTreeSet};

use super::{Evidence, Finding, Severity};
use crate::observe::{Certificate, QType, ZoneObservation, is_ancestor_or_equal, parent_name};
use crate::output::utc;
use crate::zonefile::comparable;

/// A name whose newest certificate ends within this many days is reported.
const EXPIRY_NOTICE_DAYS: i64 = 14;
/// ... and as a warning within this many.
const EXPIRY_WARNING_DAYS: i64 = 3;
/// Certificates issued within this many days are compared with CAA. An
/// older one may predate the CAA record.
const RECENT_DAYS: u64 = 30;

/// Certificate authorities by a word in the issuer's name, with the
/// domains each accepts in a CAA record. An issuer not listed here is not
/// judged.
const AUTHORITIES: &[(&str, &[&str])] = &[
    ("let's encrypt", &["letsencrypt.org"]),
    ("google trust services", &["pki.goog"]),
    (
        "digicert",
        &[
            "digicert.com",
            "digicert.ne.jp",
            "cybertrust.ne.jp",
            "symantec.com",
            "thawte.com",
            "geotrust.com",
            "rapidssl.com",
            "digitalcertvalidation.com",
        ],
    ),
    (
        "sectigo",
        &[
            "sectigo.com",
            "comodoca.com",
            "comodo.com",
            "usertrust.com",
            "trust-provider.com",
        ],
    ),
    (
        "comodo",
        &[
            "sectigo.com",
            "comodoca.com",
            "comodo.com",
            "usertrust.com",
            "trust-provider.com",
        ],
    ),
    ("zerossl", &["sectigo.com", "zerossl.com"]),
    (
        "amazon",
        &[
            "amazon.com",
            "amazontrust.com",
            "awstrust.com",
            "amazonaws.com",
        ],
    ),
    ("globalsign", &["globalsign.com"]),
    ("ssl corp", &["ssl.com"]),
    ("buypass", &["buypass.com", "buypass.no"]),
    ("entrust", &["entrust.net"]),
    ("godaddy", &["godaddy.com", "starfieldtech.com"]),
    ("starfield", &["godaddy.com", "starfieldtech.com"]),
    ("certum", &["certum.pl"]),
    ("actalis", &["actalis.it"]),
    ("microsoft", &["microsoft.com"]),
    ("identrust", &["identrust.com"]),
    ("swisssign", &["swisssign.com"]),
    ("hellenic academic", &["harica.gr"]),
];

fn authority(issuer: &str) -> Option<&'static [&'static str]> {
    let issuer = issuer.to_ascii_lowercase();
    AUTHORITIES
        .iter()
        .find(|(word, _)| issuer.contains(word))
        .map(|(_, domains)| *domains)
}

/// The organisation in an issuer name, for messages.
fn issuer_org(issuer: &str) -> String {
    issuer
        .split(", ")
        .find_map(|part| part.strip_prefix("O="))
        .map(|org| org.trim_matches('"').to_string())
        .unwrap_or_else(|| issuer.to_string())
}

/// True when a certificate name covers a hostname: the same name, or a
/// wildcard one label above it.
fn covers(cert_name: &str, host: &str) -> bool {
    cert_name == host
        || cert_name
            .strip_prefix("*.")
            .is_some_and(|parent| host != parent && parent_name(host) == parent)
}

/// The names in the zone that are in use: they have an address or are an
/// alias, by the word of a nameserver.
fn live_names(obs: &ZoneObservation) -> BTreeSet<&str> {
    obs.records
        .iter()
        .filter(|r| matches!(r.qtype, QType::A | QType::Aaaa | QType::Cname))
        .filter(|r| {
            r.outcome
                .answer()
                .is_some_and(|a| a.authoritative && !a.rdata.is_empty())
        })
        .map(|r| r.name.as_str())
        .collect()
}

/// CRT-01: the newest certificate logged for a name in use runs out soon,
/// and no replacement has been issued.
pub fn crt_01_expiry(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(certificates) = &obs.certificates else {
        return Vec::new();
    };
    let now = obs.started_at_unix as i64;
    let mut findings = Vec::new();
    for host in live_names(obs) {
        let Some(newest) = certificates
            .iter()
            .filter(|c| c.names.iter().any(|n| covers(n, host)))
            .max_by_key(|c| c.not_after_unix)
        else {
            continue;
        };
        let seconds = newest.not_after_unix as i64 - now;
        let days = seconds.div_euclid(86_400);
        if days > EXPIRY_NOTICE_DAYS {
            continue;
        }
        let (severity, when) = if seconds <= 0 {
            (Severity::Warning, "has run out".to_string())
        } else {
            let severity = if days <= EXPIRY_WARNING_DAYS {
                Severity::Warning
            } else {
                Severity::Notice
            };
            let when = match days {
                0 => "runs out in less than a day".to_string(),
                1 => "runs out in 1 day".to_string(),
                n => format!("runs out in {n} days"),
            };
            (severity, when)
        };
        findings.push(Finding::new(
            "CRT-01",
            severity,
            host,
            format!("the newest certificate logged for {host} {when}, and no newer one is logged"),
            Evidence::ZoneDetail {
                details: vec![
                    format!("expires: {}", utc(newest.not_after_unix)),
                    format!("issuer: {}", newest.issuer),
                    format!("names: {}", newest.names.join(", ")),
                ],
            },
        ));
    }
    findings
}

/// The CAA record set that governs a name: the first one found going up
/// from the name to the zone apex.
fn governing_caa(obs: &ZoneObservation, name: &str) -> Option<(String, Vec<String>)> {
    let mut by_name: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for rec in obs.records.iter().filter(|r| r.qtype == QType::Caa) {
        if let Some(answer) = rec.outcome.answer().filter(|a| a.authoritative) {
            by_name
                .entry(rec.name.as_str())
                .or_default()
                .extend(answer.rdata.iter().cloned());
        }
    }
    if let Some(policy) = &obs.policy {
        by_name
            .entry(obs.zone.as_str())
            .or_default()
            .extend(policy.caa.rdata.iter().cloned());
    }
    let mut at = name;
    loop {
        if let Some(set) = by_name.get(at).filter(|s| !s.is_empty()) {
            return Some((at.to_string(), set.iter().cloned().collect()));
        }
        if at == obs.zone || at == "." || !is_ancestor_or_equal(&obs.zone, at) {
            return None;
        }
        at = parent_name(at);
    }
}

/// The authority domains a CAA set allows to issue, for a plain or a
/// wildcard name. `None` when the set does not restrict issuing.
fn allowed(set: &[String], wildcard: bool) -> Option<BTreeSet<String>> {
    let mut issue = Vec::new();
    let mut issuewild = Vec::new();
    for record in set {
        let text = comparable("CAA", record);
        let mut parts = text.splitn(3, ' ');
        let (_flags, tag, value) = (parts.next(), parts.next(), parts.next().unwrap_or(""));
        let domain = value
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        match tag {
            Some("issue") => issue.push(domain),
            Some("issuewild") => issuewild.push(domain),
            _ => {}
        }
    }
    let list = if wildcard && !issuewild.is_empty() {
        issuewild
    } else {
        issue
    };
    if list.is_empty() {
        return None;
    }
    // An empty value means "nobody".
    Some(list.into_iter().filter(|d| !d.is_empty()).collect())
}

/// CRT-02: a certificate was issued lately by an authority the CAA
/// records do not name.
pub fn crt_02_caa_mismatch(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(certificates) = &obs.certificates else {
        return Vec::new();
    };
    let since = obs.started_at_unix.saturating_sub(RECENT_DAYS * 86_400);
    // Per certificate name: the issuers that CAA does not allow.
    let mut offending: BTreeMap<String, BTreeSet<(String, String, u64)>> = BTreeMap::new();
    let recent = |c: &&Certificate| c.not_before_unix.is_some_and(|at| at >= since);
    for cert in certificates.iter().filter(recent) {
        let Some(domains) = authority(&cert.issuer) else {
            continue;
        };
        for name in &cert.names {
            let (wildcard, host) = match name.strip_prefix("*.") {
                Some(rest) => (true, rest),
                None => (false, name.as_str()),
            };
            let Some((owner, set)) = governing_caa(obs, host) else {
                continue;
            };
            let Some(allowed) = allowed(&set, wildcard) else {
                continue;
            };
            if domains.iter().any(|d| allowed.contains(*d)) {
                continue;
            }
            offending.entry(name.clone()).or_default().insert((
                issuer_org(&cert.issuer),
                owner,
                cert.not_before_unix.unwrap_or(0),
            ));
        }
    }
    offending
        .into_iter()
        .map(|(name, issuers)| {
            let orgs: BTreeSet<&str> = issuers.iter().map(|(org, _, _)| org.as_str()).collect();
            let orgs: Vec<&str> = orgs.into_iter().collect();
            let mut details: Vec<String> = issuers
                .iter()
                .map(|(org, _, at)| format!("issued {} by {org}", utc(*at)))
                .collect();
            if let Some((_, owner, _)) = issuers.iter().next()
                && let Some((_, set)) = governing_caa(obs, owner)
            {
                details.push(format!("CAA at {owner}: {}", set.join("; ")));
            }
            Finding::new(
                "CRT-02",
                Severity::Warning,
                &name,
                format!(
                    "a certificate for {name} was issued by {}, which the CAA records do not allow",
                    orgs.join(" and ")
                ),
                Evidence::ZoneDetail { details },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::*;
    use crate::observe::{RecordAnswer, RecordObservation, RecordOutcome, Transport};

    const DAY: u64 = 86_400;
    const NOW: u64 = 1_700_000_000;

    fn record(name: &str, qtype: QType, rdata: &[&str]) -> RecordObservation {
        RecordObservation {
            name: name.to_string(),
            qtype,
            ns_name: "ns1.example.test.".to_string(),
            address: V4_A.parse().unwrap(),
            transport: Transport::Udp,
            outcome: RecordOutcome::Answer(RecordAnswer {
                rcode: "NOERROR".to_string(),
                authoritative: true,
                ttl: Some(300),
                rdata: rdata.iter().map(|r| r.to_string()).collect(),
            }),
        }
    }

    fn cert(names: &[&str], issuer: &str, issued_ago: u64, expires_in: i64) -> Certificate {
        let now = NOW;
        Certificate {
            names: names.iter().map(|n| n.to_string()).collect(),
            issuer: issuer.to_string(),
            not_before_unix: Some(now - issued_ago),
            not_after_unix: (now as i64 + expires_in) as u64,
        }
    }

    const LE: &str = "C=US, O=Let's Encrypt, CN=R11";
    const DIGICERT: &str = "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1";

    fn observed(certs: Vec<Certificate>) -> ZoneObservation {
        let mut obs = healthy();
        obs.started_at_unix = NOW;
        obs.records = vec![
            record("example.test.", QType::A, &["192.0.2.1"]),
            record(
                "example.test.",
                QType::Caa,
                &["0 issue \"letsencrypt.org\""],
            ),
            record("www.example.test.", QType::A, &["192.0.2.1"]),
            record("www.example.test.", QType::Caa, &[]),
            record("old.example.test.", QType::A, &[]),
            record("shop.example.test.", QType::Cname, &["shops.example.net."]),
            record(
                "shop.example.test.",
                QType::Caa,
                &[
                    "0 issue \"digicert.com; account=1\"",
                    "0 iodef \"mailto:x@example.test\"",
                ],
            ),
        ];
        obs.certificates = Some(certs);
        obs
    }

    #[test]
    fn expiry_looks_at_the_newest_certificate_of_names_in_use() {
        let day = DAY as i64;
        let obs = observed(vec![
            cert(&["www.example.test."], LE, 80 * DAY, 10 * day),
            cert(&["*.example.test."], LE, 85 * DAY, 2 * day),
            cert(&["example.test."], LE, 30 * DAY, 60 * day),
            cert(&["old.example.test."], LE, 89 * DAY, day),
        ]);
        let found: Vec<(String, Severity, String)> = crt_01_expiry(&obs)
            .into_iter()
            .map(|f| (f.name, f.severity, f.summary))
            .collect();
        // www: 10 days (its own certificate outlives the wildcard).
        // shop: only the wildcard covers it, 2 days. old: not in use.
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].0, "shop.example.test.");
        assert_eq!(found[0].1, Severity::Warning);
        assert!(found[0].2.contains("runs out in 2 days"), "{}", found[0].2);
        assert_eq!(
            (found[1].0.as_str(), found[1].1),
            ("www.example.test.", Severity::Notice)
        );

        // A renewed certificate ends the finding.
        let mut renewed = obs.clone();
        renewed
            .certificates
            .as_mut()
            .unwrap()
            .push(cert(&["*.example.test."], LE, DAY, 89 * day));
        assert!(crt_01_expiry(&renewed).is_empty());
        // No log data, no opinion.
        renewed.certificates = None;
        assert!(crt_01_expiry(&renewed).is_empty());
    }

    #[test]
    fn recent_issuers_are_compared_with_caa() {
        let far = 80 * DAY as i64;
        let obs = observed(vec![
            // Allowed at the apex; www inherits the apex record.
            cert(&["example.test.", "www.example.test."], LE, DAY, far),
            // Not allowed for www.
            cert(&["www.example.test."], DIGICERT, 2 * DAY, far),
            // shop has its own record naming DigiCert: fine there...
            cert(&["shop.example.test."], DIGICERT, 2 * DAY, far),
            // ...and Let's Encrypt is not.
            cert(&["shop.example.test."], LE, 3 * DAY, far),
            // Too old to judge, and an issuer nobody knows.
            cert(
                &["www.example.test."],
                "C=US, O=GlobalSign nv-sa, CN=X",
                40 * DAY,
                far,
            ),
            cert(&["www.example.test."], "O=Some Private CA", DAY, far),
        ]);
        let found: Vec<(String, String)> = crt_02_caa_mismatch(&obs)
            .into_iter()
            .map(|f| (f.name, f.summary))
            .collect();
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].0, "shop.example.test.");
        assert!(
            found[0].1.contains("issued by Let's Encrypt"),
            "{}",
            found[0].1
        );
        assert_eq!(found[1].0, "www.example.test.");
        assert!(
            found[1].1.contains("issued by DigiCert Inc"),
            "{}",
            found[1].1
        );
    }

    #[test]
    fn caa_values() {
        let set =
            |records: &[&str]| -> Vec<String> { records.iter().map(|r| r.to_string()).collect() };
        assert_eq!(allowed(&set(&["0 iodef \"mailto:x@y\""]), false), None);
        assert_eq!(
            allowed(&set(&["0 issue \";\""]), false),
            Some(BTreeSet::new())
        );
        let both = set(&[
            "0 issue \"letsencrypt.org\"",
            "0 issuewild \"digicert.com\"",
        ]);
        assert!(allowed(&both, false).unwrap().contains("letsencrypt.org"));
        assert!(allowed(&both, true).unwrap().contains("digicert.com"));
        assert!(!allowed(&both, true).unwrap().contains("letsencrypt.org"));
        assert!(covers("*.example.test.", "a.example.test."));
        assert!(!covers("*.example.test.", "a.b.example.test."));
        assert!(!covers("*.example.test.", "example.test."));
        assert_eq!(issuer_org(DIGICERT), "DigiCert Inc");
    }
}
