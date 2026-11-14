//! The registration watch: what the registry says about the registered
//! domain a zone is in. It is read over RDAP, the JSON successor of whois:
//! IANA's bootstrap file names the RDAP service of each top-level domain,
//! and that service is asked for the one domain.
//!
//! Both requests name the domain to a third party (IANA sees only that the
//! file was fetched; the registry sees the domain), so this runs only as
//! part of a deep run.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::observe::{Registration, ZoneObservation, is_ancestor_or_equal};
use crate::resolver::iterate::printable;
use crate::resolver::{Client, HttpOutcome, normalise_zone};

/// IANA's list of the RDAP service of every top-level domain.
pub const BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/dns.json";
const BOOTSTRAP_LIMIT: usize = 2 * 1024 * 1024;
const RDAP_LIMIT: usize = 512 * 1024;
const TIMEOUT: Duration = Duration::from_secs(15);

/// The names that may be the registered domain, most likely first: every
/// zone on the delegation path below a top-level domain, down to the zone.
pub fn candidates(obs: &ZoneObservation) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for step in &obs.delegation_path {
        if step.from_zone != "."
            && is_ancestor_or_equal(&step.to_zone, &obs.zone)
            && !out.contains(&step.to_zone)
        {
            out.push(step.to_zone.clone());
        }
    }
    out.truncate(3);
    out
}

/// The RDAP service for a top-level domain, from IANA's bootstrap file.
/// Only `https` services are used.
pub fn parse_bootstrap(body: &str, tld: &str) -> Option<String> {
    let doc: serde_json::Value = serde_json::from_str(body).ok()?;
    let tld = tld.trim_end_matches('.');
    for service in doc["services"].as_array()? {
        let names = service[0].as_array()?;
        if names
            .iter()
            .any(|n| n.as_str().is_some_and(|n| n.eq_ignore_ascii_case(tld)))
        {
            let mut url = service[1]
                .as_array()?
                .iter()
                .filter_map(|u| u.as_str())
                .find(|u| u.starts_with("https://"))?
                .to_string();
            if !url.ends_with('/') {
                url.push('/');
            }
            return Some(url);
        }
    }
    None
}

/// Days since 1970-01-01 of a date in the Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Read a timestamp such as `2027-08-13T04:00:00Z` or
/// `2027-08-13T04:00:00.5+02:00` as seconds since 1970.
pub fn parse_rfc3339(text: &str) -> Option<u64> {
    let text = text.trim();
    let b = text.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    if !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let num = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(fraction.len());
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "" | "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let (h, m) = rest[1..].split_once(':')?;
            sign * (h.parse::<i64>().ok()? * 3600 + m.parse::<i64>().ok()? * 60)
        }
    };
    let secs =
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
    u64::try_from(secs).ok()
}

/// Read an RDAP domain answer.
pub fn parse_rdap(domain: &str, url: &str, body: &str) -> Result<Registration, String> {
    let doc: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("unreadable answer: {e}"))?;
    if !doc.is_object() || doc.get("errorCode").is_some() {
        return Err("the answer is not a domain record".to_string());
    }
    let mut status: Vec<String> = doc["status"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_str())
        .map(|s| printable(&s.to_ascii_lowercase()))
        .collect();
    status.sort();
    status.dedup();

    let expires_unix = doc["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["eventAction"].as_str() == Some("expiration"))
        .find_map(|e| e["eventDate"].as_str().and_then(parse_rfc3339));

    // The registrar's name is the "fn" entry of its contact card.
    let registrar = doc["entities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| {
            e["roles"]
                .as_array()
                .is_some_and(|r| r.iter().any(|v| v.as_str() == Some("registrar")))
        })
        .find_map(|e| {
            e["vcardArray"][1].as_array()?.iter().find_map(|field| {
                (field[0].as_str() == Some("fn"))
                    .then(|| field[3].as_str())
                    .flatten()
            })
        })
        .map(|name| printable(name));

    let nameservers: BTreeSet<String> = doc["nameservers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| n["ldhName"].as_str())
        .filter_map(|n| normalise_zone(n).ok())
        .collect();

    Ok(Registration {
        domain: domain.to_string(),
        url: Some(url.to_string()),
        status,
        expires_unix,
        registrar,
        nameservers: nameservers.into_iter().collect(),
        error: None,
    })
}

/// Ask the registry about the domain a zone is registered under. `None`
/// when the zone is not under a top-level domain (the root, or a
/// top-level domain itself).
pub async fn collect(client: &Client, obs: &ZoneObservation) -> Option<Registration> {
    let candidates = candidates(obs);
    let first = candidates.first()?.clone();
    let failed = |message: String| {
        Some(Registration {
            domain: first.clone(),
            error: Some(printable(&message)),
            ..Registration::default()
        })
    };
    let tld = first.trim_end_matches('.').rsplit('.').next()?.to_string();
    let base = match client
        .http_get_with(BOOTSTRAP_URL, BOOTSTRAP_LIMIT, TIMEOUT)
        .await
    {
        HttpOutcome::Response { status: 200, body } => match parse_bootstrap(&body, &tld) {
            Some(base) => base,
            None => return failed(format!("IANA lists no RDAP service for .{tld}")),
        },
        HttpOutcome::Response { status, .. } => {
            return failed(format!("the RDAP service list answered HTTP {status}"));
        }
        HttpOutcome::Error { message } => {
            return failed(format!("the RDAP service list: {message}"));
        }
    };
    let mut last = String::new();
    for domain in &candidates {
        let url = format!("{base}domain/{}", domain.trim_end_matches('.'));
        match client.http_get_with(&url, RDAP_LIMIT, TIMEOUT).await {
            HttpOutcome::Response { status: 200, body } => match parse_rdap(domain, &url, &body) {
                Ok(registration) => return Some(registration),
                Err(e) => last = e,
            },
            // Not a registered domain; the next candidate may be.
            HttpOutcome::Response { status: 404, .. } => {
                last = format!("the registry has no record of {domain}");
            }
            HttpOutcome::Response { status, .. } => last = format!("RDAP answered HTTP {status}"),
            HttpOutcome::Error { message } => last = format!("RDAP: {message}"),
        }
    }
    failed(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2023-11-14T22:13:20Z"), Some(1_700_000_000));
        assert_eq!(
            parse_rfc3339("2023-11-15T00:13:20.123+02:00"),
            Some(1_700_000_000)
        );
        assert_eq!(parse_rfc3339("2024-02-29T00:00:00Z"), Some(1_709_164_800));
        for bad in [
            "",
            "2023-11-14",
            "2023-13-14T00:00:00Z",
            "yesterday at noon!!",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_bootstrap_file_names_the_service() {
        let body = r#"{"version":"1.0","services":[
            [["net","com"],["https://rdap.verisign.com/com/v1/"]],
            [["org"],["http://plain.example/","https://rdap.example.org/rdap"]]]}"#;
        assert_eq!(
            parse_bootstrap(body, "com.").as_deref(),
            Some("https://rdap.verisign.com/com/v1/")
        );
        assert_eq!(
            parse_bootstrap(body, "ORG").as_deref(),
            Some("https://rdap.example.org/rdap/")
        );
        assert_eq!(parse_bootstrap(body, "test"), None);
        assert_eq!(parse_bootstrap("<html>", "com"), None);
    }

    #[test]
    fn a_domain_record_is_read() {
        let body = r#"{"objectClassName":"domain","ldhName":"EXAMPLE.ORG",
            "status":["client transfer prohibited","Client Delete Prohibited"],
            "events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},
                      {"eventAction":"expiration","eventDate":"2023-11-14T22:13:20Z"}],
            "entities":[{"roles":["abuse"]},{"roles":["registrar"],
                "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar, Inc."]]]}],
            "nameservers":[{"ldhName":"B.NS.EXAMPLE.NET"},{"ldhName":"a.ns.example.net."}]}"#;
        let r = parse_rdap(
            "example.org.",
            "https://rdap.example/domain/example.org",
            body,
        )
        .unwrap();
        assert_eq!(
            r.status,
            ["client delete prohibited", "client transfer prohibited"]
        );
        assert_eq!(r.expires_unix, Some(1_700_000_000));
        assert_eq!(r.registrar.as_deref(), Some("Example Registrar, Inc."));
        assert_eq!(r.nameservers, ["a.ns.example.net.", "b.ns.example.net."]);
        assert!(parse_rdap("example.org.", "u", r#"{"errorCode":404}"#).is_err());
        assert!(parse_rdap("example.org.", "u", "[]").is_err());
    }
}
