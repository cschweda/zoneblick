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

use crate::observe::{ZoneObservation, is_ancestor_or_equal};
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

/// Ask crt.sh for the names on a zone's certificates.
pub async fn ct_names(client: &Client, zone: &str) -> Result<Vec<String>, String> {
    match client
        .http_get_with(&ct_url(zone), CT_BODY_LIMIT, CT_TIMEOUT)
        .await
    {
        HttpOutcome::Error { message } => Err(format!("crt.sh: {message}")),
        HttpOutcome::Response { status: 200, body } => Ok(parse_ct(zone, &body)),
        HttpOutcome::Response { status, .. } => Err(format!("crt.sh answered HTTP {status}")),
    }
}

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
        let msg = Message::from_vec(&buf).map_err(|e| e.to_string())?;
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
    fn the_search_url_names_the_zone() {
        assert_eq!(
            ct_url("example.org."),
            "https://crt.sh/?q=%25.example.org&output=json&exclude=expired&deduplicate=Y"
        );
    }
}
