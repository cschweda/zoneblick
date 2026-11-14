//! Discovery: finding names in a zone that nobody listed.
//!
//! One source so far: Certificate Transparency logs, read through the
//! public search at crt.sh. Every publicly trusted certificate is logged,
//! so the names on a zone's certificates are a good list of its hosts.
//! The query tells crt.sh which zone is being looked at, so discovery is
//! off unless asked for.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::observe::{Certificate, ZoneObservation, is_ancestor_or_equal};
use crate::resolver::{Client, HttpOutcome, normalise_zone};

/// At most this many discovered names are added per zone.
pub const CT_MAX_NAMES: usize = 200;
/// crt.sh answers can be large, and are often slow.
const CT_BODY_LIMIT: usize = 8 * 1024 * 1024;
const CT_TIMEOUT: Duration = Duration::from_secs(45);

/// The crt.sh search for every unexpired certificate under a zone.
pub fn ct_url(zone: &str) -> String {
    let host = zone.trim_end_matches('.');
    format!("https://crt.sh/?q=%25.{host}&output=json&exclude=expired&deduplicate=Y")
}

/// Read one JSON string starting after its opening quote.
fn json_string(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = text.chars();
    loop {
        match chars.next()? {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                'n' | 'r' | 't' => out.push('\n'),
                other => out.push(other),
            },
            c => out.push(c),
        }
    }
}

/// The names inside `zone` that a crt.sh JSON answer mentions, sorted.
/// Wildcards, the apex and anything that is not a plain hostname are left
/// out. The scan does not need the whole document, so a cut-off answer
/// still gives the names it holds.
pub fn parse_ct(zone: &str, body: &str) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for key in ["\"name_value\":\"", "\"common_name\":\""] {
        let mut rest = body;
        while let Some(at) = rest.find(key) {
            rest = &rest[at + key.len()..];
            let Some(value) = json_string(rest) else {
                break;
            };
            for line in value.lines() {
                let line = line.trim().to_ascii_lowercase();
                let plain = !line.is_empty()
                    && line.len() <= 253
                    && line
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
                if !plain {
                    continue;
                }
                if let Ok(name) = normalise_zone(&line)
                    && name != zone
                    && is_ancestor_or_equal(zone, &name)
                {
                    names.insert(name);
                }
            }
        }
    }
    names.into_iter().take(CT_MAX_NAMES).collect()
}

/// A zone with more logged certificates than this gets no certificate
/// checks.
pub const CT_MAX_CERTIFICATES: usize = 2000;

/// The certificates in a crt.sh JSON answer, with the names inside
/// `zone` each is for. `None` when the answer is not a whole JSON
/// document (crt.sh cuts large answers off) or holds more certificates
/// than [`CT_MAX_CERTIFICATES`], so that half a list is never taken for
/// the whole.
pub fn parse_ct_certificates(zone: &str, body: &str) -> Option<Vec<Certificate>> {
    let doc: serde_json::Value = serde_json::from_str(body).ok()?;
    let mut out = Vec::new();
    for entry in doc.as_array()? {
        let Some(not_after_unix) = entry["not_after"]
            .as_str()
            .and_then(crate::registration::parse_rfc3339)
        else {
            continue;
        };
        let mut names: BTreeSet<String> = BTreeSet::new();
        for field in ["name_value", "common_name"] {
            for line in entry[field].as_str().unwrap_or("").lines() {
                let line = line.trim().to_ascii_lowercase();
                let (wild, host) = match line.strip_prefix("*.") {
                    Some(rest) => (true, rest),
                    None => (false, line.as_str()),
                };
                let plain = !host.is_empty()
                    && host.len() <= 253
                    && host
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
                if !plain {
                    continue;
                }
                if let Ok(name) = normalise_zone(host)
                    && is_ancestor_or_equal(zone, &name)
                {
                    names.insert(if wild { format!("*.{name}") } else { name });
                }
            }
        }
        if names.is_empty() {
            continue;
        }
        out.push(Certificate {
            names: names.into_iter().collect(),
            issuer: crate::resolver::iterate::printable(
                entry["issuer_name"].as_str().unwrap_or(""),
            ),
            not_before_unix: entry["not_before"]
                .as_str()
                .and_then(crate::registration::parse_rfc3339),
            not_after_unix,
        });
        // Part of a list must not pass for the whole: a renewal or an
        // unexpected issuer could be in the part that was dropped.
        if out.len() > CT_MAX_CERTIFICATES {
            return None;
        }
    }
    out.sort();
    out.dedup();
    Some(out)
}

/// What Certificate Transparency logs hold for a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtFound {
    /// The hostnames named on the zone's certificates.
    pub names: Vec<String>,
    /// The unexpired certificates themselves; `None` when the answer was
    /// cut short.
    pub certificates: Option<Vec<Certificate>>,
}

/// Ask crt.sh for the unexpired certificates of a zone.
pub async fn ct_fetch(client: &Client, zone: &str) -> Result<CtFound, String> {
    match client
        .http_get_with(&ct_url(zone), CT_BODY_LIMIT, CT_TIMEOUT)
        .await
    {
        HttpOutcome::Error { message } => Err(format!("crt.sh: {message}")),
        HttpOutcome::Response { status: 200, body } => Ok(CtFound {
            names: parse_ct(zone, &body),
            certificates: parse_ct_certificates(zone, &body),
        }),
        HttpOutcome::Response { status, .. } => Err(format!("crt.sh answered HTTP {status}")),
    }
}

/// Ask crt.sh for the names on a zone's certificates.
pub async fn ct_names(client: &Client, zone: &str) -> Result<Vec<String>, String> {
    ct_fetch(client, zone).await.map(|found| found.names)
}

/// At most this many names are taken from a DNS provider's record list.
pub const PROVIDER_MAX_NAMES: usize = 500;

/// The DigitalOcean API address for one page of a domain's records.
pub fn digitalocean_url(zone: &str, page: usize) -> String {
    let host = zone.trim_end_matches('.');
    format!("https://api.digitalocean.com/v2/domains/{host}/records?per_page=200&page={page}")
}

/// The names in one page of DigitalOcean's record list, and whether
/// another page follows. Names there are relative to the zone; `@` is the
/// apex.
pub fn parse_digitalocean(zone: &str, body: &str) -> Result<(Vec<String>, bool), String> {
    let doc: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("unreadable answer: {e}"))?;
    let records = doc["domain_records"]
        .as_array()
        .ok_or("the answer has no record list")?;
    let mut names = BTreeSet::new();
    for record in records {
        let (Some(rtype), Some(name)) = (record["type"].as_str(), record["name"].as_str()) else {
            continue;
        };
        let plain = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if !plain || !matches!(rtype, "A" | "AAAA" | "CNAME" | "MX" | "TXT") {
            continue;
        }
        if let Ok(full) = crate::resolver::name_in_zone(zone, name)
            && full != zone
        {
            names.insert(full);
        }
    }
    let more = doc["links"]["pages"]["next"].is_string();
    Ok((names.into_iter().collect(), more))
}

/// Ask DigitalOcean, which hosts the zone, for the names in it. The token
/// needs only read access.
pub async fn digitalocean_names(
    client: &Client,
    zone: &str,
    token: &str,
) -> Result<Vec<String>, String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for page in 1..=10 {
        let outcome = client
            .http_get_auth(
                &digitalocean_url(zone, page),
                Some(token),
                4 * 1024 * 1024,
                Duration::from_secs(20),
            )
            .await;
        let body = match outcome {
            HttpOutcome::Error { message } => return Err(format!("DigitalOcean: {message}")),
            HttpOutcome::Response { status: 200, body } => body,
            HttpOutcome::Response { status: 401, .. } => {
                return Err("DigitalOcean refused the token".to_string());
            }
            HttpOutcome::Response { status: 404, .. } => {
                return Err(format!("DigitalOcean has no domain {zone} on this account"));
            }
            HttpOutcome::Response { status, .. } => {
                return Err(format!("DigitalOcean answered HTTP {status}"));
            }
        };
        let (found, more) = parse_digitalocean(zone, &body)?;
        names.extend(found);
        if !more || names.len() >= PROVIDER_MAX_NAMES {
            break;
        }
    }
    Ok(names.into_iter().take(PROVIDER_MAX_NAMES).collect())
}

/// The environment variable `zoneblick run` reads the DigitalOcean token from.
pub const DIGITALOCEAN_TOKEN_ENV: &str = "ZONEBLICK_DIGITALOCEAN_TOKEN";

/// The addresses of the nameservers that answered in a run.
pub fn servers_of(obs: &ZoneObservation) -> Vec<IpAddr> {
    let set: BTreeSet<IpAddr> = obs
        .probes
        .iter()
        .filter(|p| p.outcome.response().is_some())
        .map(|p| p.address)
        .collect();
    set.into_iter().collect()
}

/// At most this many names are taken from a zone transfer.
pub const AXFR_MAX_NAMES: usize = 500;
const AXFR_BYTE_LIMIT: usize = 32 * 1024 * 1024;
const AXFR_TIMEOUT: Duration = Duration::from_secs(20);

/// Ask the zone's nameservers for a zone transfer (AXFR), one after
/// another until one allows it, and return the names in the zone that
/// have address, alias, mail or text records. Most servers refuse
/// transfers to strangers; that is the expected answer, reported as an
/// error here.
pub async fn axfr_names(zone: &str, servers: &[IpAddr]) -> Result<Vec<String>, String> {
    let mut last = "there is no nameserver to ask".to_string();
    for address in servers {
        if let Some(why) = crate::resolver::transport::never_contacted(*address) {
            last = format!("{address}: not asked, a {why} address");
            continue;
        }
        let addr = SocketAddr::new(*address, 53);
        last = match tokio::time::timeout(AXFR_TIMEOUT, axfr_from(zone, addr)).await {
            Ok(Ok(names)) => return Ok(names),
            Ok(Err(e)) => format!("{address}: {e}"),
            Err(_) => format!("{address}: timed out"),
        };
    }
    Err(last)
}

/// Whether a server starts a zone transfer for us. Only the first message
/// is read; nothing of the zone is kept.
pub async fn axfr_allowed(zone: &str, address: IpAddr) -> bool {
    if crate::resolver::transport::never_contacted(address).is_some() {
        return false;
    }
    let attempt = async {
        let name = Name::from_ascii(zone).ok()?;
        let mut query = Message::query();
        query.metadata.recursion_desired = false;
        query.add_query(Query::query(name, RecordType::AXFR));
        let wire = query.to_vec().ok()?;
        let mut stream = TcpStream::connect(SocketAddr::new(address, 53))
            .await
            .ok()?;
        stream
            .write_all(&(wire.len() as u16).to_be_bytes())
            .await
            .ok()?;
        stream.write_all(&wire).await.ok()?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.ok()?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut buf).await.ok()?;
        let msg = Message::from_vec(&buf).ok()?;
        Some(
            msg.metadata.response_code == ResponseCode::NoError
                && msg
                    .answers
                    .first()
                    .is_some_and(|rec| rec.record_type() == RecordType::SOA),
        )
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(8), attempt).await,
        Ok(Some(true))
    )
}

/// One zone transfer from one server.
pub async fn axfr_from(zone: &str, addr: SocketAddr) -> Result<Vec<String>, String> {
    let name = Name::from_ascii(zone).map_err(|e| e.to_string())?;
    let mut query = Message::query();
    query.metadata.recursion_desired = false;
    query.add_query(Query::query(name, RecordType::AXFR));
    let wire = query.to_vec().map_err(|e| e.to_string())?;

    let io = |e: std::io::Error| e.to_string();
    let mut stream = TcpStream::connect(addr).await.map_err(io)?;
    stream
        .write_all(&(wire.len() as u16).to_be_bytes())
        .await
        .map_err(io)?;
    stream.write_all(&wire).await.map_err(io)?;

    let mut names: BTreeSet<String> = BTreeSet::new();
    let (mut soa_seen, mut total) = (0, 0);
    while soa_seen < 2 {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.map_err(io)?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut buf).await.map_err(io)?;
        total += buf.len();
        if total > AXFR_BYTE_LIMIT {
            return Err("the transfer is too large".to_string());
        }
        let msg = Message::from_vec(&buf)
            .map_err(|e| crate::resolver::iterate::printable(&e.to_string()))?;
        if msg.metadata.message_type != MessageType::Response
            || msg.metadata.id != query.metadata.id
        {
            return Err("unexpected answer".to_string());
        }
        if msg.metadata.response_code != ResponseCode::NoError {
            return Err(format!(
                "transfer refused ({})",
                crate::resolver::iterate::rcode_name(msg.metadata.response_code)
            ));
        }
        if msg.answers.is_empty() {
            return Err("transfer refused (empty answer)".to_string());
        }
        for rec in &msg.answers {
            let rtype = rec.record_type();
            if rtype == RecordType::SOA {
                soa_seen += 1;
            }
            if !matches!(
                rtype,
                RecordType::A
                    | RecordType::AAAA
                    | RecordType::CNAME
                    | RecordType::MX
                    | RecordType::TXT
            ) {
                continue;
            }
            let owner = crate::resolver::iterate::norm(&rec.name);
            let plain = owner
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
            if plain && owner != zone && is_ancestor_or_equal(zone, &owner) {
                names.insert(owner);
            }
        }
    }
    Ok(names.into_iter().take(AXFR_MAX_NAMES).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_read_from_a_crt_sh_answer() {
        let body = r#"[{"issuer_ca_id":1,"common_name":"www.example.org","name_value":"www.example.org\nexample.org\n*.example.org"},
            {"common_name":"Mail.Example.Org","name_value":"mail.example.org\nother.example.net\nbad name.example.org\nadmin@example.org"},
            {"common_name":"api.example.org","name_value":"api.exam"#;
        assert_eq!(
            parse_ct("example.org.", body),
            ["api.example.org.", "mail.example.org.", "www.example.org."]
        );
        assert!(parse_ct("example.org.", "not json at all").is_empty());
    }

    #[test]
    fn certificates_are_read_from_a_crt_sh_answer() {
        let body = r#"[{"issuer_name":"C=US, O=Let's Encrypt, CN=R11","common_name":"www.example.org",
              "name_value":"www.example.org\nexample.org","not_before":"2023-11-01T00:00:00","not_after":"2023-11-14T22:13:20"},
            {"issuer_name":"C=US, O=DigiCert Inc, CN=X","common_name":"*.Example.org",
              "name_value":"*.example.org\nother.example.net","not_before":"bad","not_after":"2024-02-29T00:00:00"},
            {"issuer_name":"x","common_name":"other.example.net","name_value":"other.example.net","not_after":"2024-02-29T00:00:00"},
            {"issuer_name":"x","common_name":"a.example.org","name_value":"a.example.org","not_after":"never"}]"#;
        let certs = parse_ct_certificates("example.org.", body).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].names, ["*.example.org."]);
        assert_eq!(
            (certs[0].not_before_unix, certs[0].not_after_unix),
            (None, 1_709_164_800)
        );
        assert_eq!(certs[1].names, ["example.org.", "www.example.org."]);
        assert_eq!(certs[1].issuer, "C=US, O=Let's Encrypt, CN=R11");
        assert_eq!(certs[1].not_after_unix, 1_700_000_000);
        // More certificates than the limit: no list rather than part of one.
        let entry = r#"{"issuer_name":"x","common_name":"a.example.org","name_value":"a.example.org","not_after":"2024-02-29T00:00:00"}"#;
        let many = format!("[{}]", vec![entry; CT_MAX_CERTIFICATES + 1].join(","));
        assert!(parse_ct_certificates("example.org.", &many).is_none());
        // A cut-off answer gives names but no certificate list.
        let cut = &body[..body.len() - 40];
        assert!(parse_ct_certificates("example.org.", cut).is_none());
        assert!(!parse_ct("example.org.", cut).is_empty());
    }

    #[test]
    fn the_search_url_names_the_zone() {
        assert_eq!(
            ct_url("example.org."),
            "https://crt.sh/?q=%25.example.org&output=json&exclude=expired&deduplicate=Y"
        );
    }

    #[test]
    fn names_are_read_from_a_digitalocean_answer() {
        let body = r#"{"domain_records":[
            {"id":1,"type":"NS","name":"@","data":"ns1.digitalocean.com"},
            {"id":2,"type":"A","name":"@","data":"192.0.2.1"},
            {"id":3,"type":"A","name":"www","data":"192.0.2.1"},
            {"id":4,"type":"CNAME","name":"Shop.EU","data":"shops.example.net."},
            {"id":5,"type":"A","name":"*","data":"192.0.2.1"},
            {"id":6,"type":"SRV","name":"_sip._tcp","data":"sip.example.org"},
            {"id":7,"type":"TXT","name":"_dmarc","data":"v=DMARC1; p=none"}],
            "links":{"pages":{"next":"https://api.digitalocean.com/v2/domains/example.org/records?page=2"}},
            "meta":{"total":300}}"#;
        let (names, more) = parse_digitalocean("example.org.", body).unwrap();
        assert_eq!(
            names,
            [
                "_dmarc.example.org.",
                "shop.eu.example.org.",
                "www.example.org."
            ]
        );
        assert!(more);
        let (names, more) =
            parse_digitalocean("example.org.", r#"{"domain_records":[],"links":{}}"#).unwrap();
        assert!(names.is_empty() && !more);
        assert!(parse_digitalocean("example.org.", r#"{"id":"unauthorized"}"#).is_err());
        assert!(parse_digitalocean("example.org.", "<html>").is_err());
        assert_eq!(
            digitalocean_url("example.org.", 2),
            "https://api.digitalocean.com/v2/domains/example.org/records?per_page=200&page=2"
        );
    }
}
