//! Discovery through the API of the DNS host: the names a zone holds, read
//! from the account that hosts it. Every request is a read; a token needs
//! read access to the zone and nothing else.
//!
//! Credentials are sent as request headers, which the client never records.

use std::collections::BTreeSet;
use std::time::Duration;

use ring::hmac;
use sha2::{Digest, Sha256};

use crate::discover::PROVIDER_MAX_NAMES;
use crate::observe::is_ancestor_or_equal;
use crate::resolver::{Client, HttpOutcome, name_in_zone, normalise_zone};

/// The DNS hosts zoneblick can read names from, as written in
/// `--discover` and in the config file.
pub const PROVIDERS: [&str; 5] = ["digitalocean", "cloudflare", "gandi", "hetzner", "route53"];

const BODY_LIMIT: usize = 4 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(20);
/// No account lists a zone over more pages than this.
const MAX_PAGES: usize = 20;

/// What a provider's API accepts as proof of who is asking.
#[derive(Clone, PartialEq, Eq)]
pub enum Credential {
    Token(String),
    Aws {
        key_id: String,
        secret: String,
        session_token: Option<String>,
    },
}

// Never print a credential, not even in a panic message.
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential(..)")
    }
}

/// The provider's name as people write it.
pub fn label(provider: &str) -> &'static str {
    match provider {
        "digitalocean" => "DigitalOcean",
        "cloudflare" => "Cloudflare",
        "gandi" => "Gandi",
        "hetzner" => "Hetzner",
        "route53" => "Amazon Route 53",
        _ => "the DNS host",
    }
}

/// The environment variables `zoneblick run` reads a provider's
/// credential from.
pub fn env_names(provider: &str) -> &'static [&'static str] {
    match provider {
        "digitalocean" => &["ZONEBLICK_DIGITALOCEAN_TOKEN"],
        "cloudflare" => &["ZONEBLICK_CLOUDFLARE_TOKEN"],
        "gandi" => &["ZONEBLICK_GANDI_TOKEN"],
        "hetzner" => &["ZONEBLICK_HETZNER_TOKEN"],
        "route53" => &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
        _ => &[],
    }
}

/// Read a provider's credential from the environment.
pub fn credential_from_env(provider: &str) -> Result<Credential, String> {
    let var = |name: &str| {
        std::env::var(name)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let missing = || match env_names(provider) {
        [one] => format!("set {one} to a read-only API token"),
        names => format!("set {} to a read-only access key", names.join(" and ")),
    };
    if provider == "route53" {
        return Ok(Credential::Aws {
            key_id: var("AWS_ACCESS_KEY_ID").ok_or_else(missing)?,
            secret: var("AWS_SECRET_ACCESS_KEY").ok_or_else(missing)?,
            session_token: var("AWS_SESSION_TOKEN"),
        });
    }
    let name = env_names(provider)
        .first()
        .ok_or_else(|| format!("{provider} is not a DNS host zoneblick knows"))?;
    var(name).map(Credential::Token).ok_or_else(missing)
}

/// Read an AWS credentials file: `aws_access_key_id = ...` and
/// `aws_secret_access_key = ...` lines, as in `~/.aws/credentials`. The
/// first of each is used; section headers are read past.
pub fn parse_aws_credentials(text: &str) -> Result<Credential, String> {
    let mut found: [Option<String>; 3] = [None, None, None];
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let slot = match key.trim().to_ascii_lowercase().as_str() {
            "aws_access_key_id" => 0,
            "aws_secret_access_key" => 1,
            "aws_session_token" => 2,
            _ => continue,
        };
        let value = value.trim();
        if found[slot].is_none() && !value.is_empty() {
            found[slot] = Some(value.to_string());
        }
    }
    let [key_id, secret, session_token] = found;
    Ok(Credential::Aws {
        key_id: key_id.ok_or("no aws_access_key_id line")?,
        secret: secret.ok_or("no aws_secret_access_key line")?,
        session_token,
    })
}

fn plain(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn wanted(rtype: &str) -> bool {
    matches!(rtype, "A" | "AAAA" | "CNAME" | "MX" | "TXT")
}

/// Add a record's name to `names` when it is a plain hostname inside the
/// zone, not the apex, and of a type a run collects. `name` may be
/// relative to the zone (`www`, `@`) or absolute.
fn keep(names: &mut BTreeSet<String>, zone: &str, name: &str, rtype: &str, relative: bool) {
    if !wanted(rtype) || !plain(name.trim_end_matches('.')) && name != "@" {
        return;
    }
    let full = if relative {
        name_in_zone(zone, name).ok()
    } else {
        normalise_zone(name).ok()
    };
    if let Some(full) = full
        && full != zone
        && is_ancestor_or_equal(zone, &full)
    {
        names.insert(full);
    }
}

async fn get(
    client: &Client,
    who: &str,
    url: &str,
    headers: &[(&str, String)],
) -> Result<String, String> {
    match client
        .http_get_headers(url, headers, BODY_LIMIT, TIMEOUT)
        .await
    {
        HttpOutcome::Error { message } => Err(format!("{who}: {message}")),
        HttpOutcome::Response { status: 200, body } => Ok(body),
        HttpOutcome::Response {
            status: 401 | 403, ..
        } => Err(format!("{who} refused the credential")),
        HttpOutcome::Response { status: 404, .. } => {
            Err(format!("{who} has no such zone on this account"))
        }
        HttpOutcome::Response { status, .. } => Err(format!("{who} answered HTTP {status}")),
    }
}

fn json(who: &str, body: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(body).map_err(|e| format!("{who}: unreadable answer: {e}"))
}

fn bearer(token: &str) -> Vec<(&'static str, String)> {
    vec![("authorization", format!("Bearer {token}"))]
}

// ---------------------------------------------------------------- Cloudflare

pub fn cloudflare_zone_url(zone: &str) -> String {
    format!(
        "https://api.cloudflare.com/client/v4/zones?name={}",
        zone.trim_end_matches('.')
    )
}

pub fn cloudflare_records_url(zone_id: &str, page: usize) -> String {
    format!(
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?per_page=100&page={page}"
    )
}

/// The ID Cloudflare gives the zone, from a zone search answer.
pub fn parse_cloudflare_zone(body: &str) -> Result<String, String> {
    let doc = json("Cloudflare", body)?;
    let id = doc["result"][0]["id"]
        .as_str()
        .ok_or("Cloudflare has no such zone on this account")?;
    // The ID goes into a URL; it is 32 hex digits.
    if id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("Cloudflare gave an unusable zone ID".to_string());
    }
    Ok(id.to_string())
}

/// The names on one page of Cloudflare's record list, and the number of
/// pages.
pub fn parse_cloudflare_records(zone: &str, body: &str) -> Result<(Vec<String>, usize), String> {
    let doc = json("Cloudflare", body)?;
    let records = doc["result"]
        .as_array()
        .ok_or("Cloudflare: the answer has no record list")?;
    let mut names = BTreeSet::new();
    for r in records {
        if let (Some(name), Some(rtype)) = (r["name"].as_str(), r["type"].as_str()) {
            keep(&mut names, zone, name, rtype, false);
        }
    }
    let pages = doc["result_info"]["total_pages"].as_u64().unwrap_or(1) as usize;
    Ok((names.into_iter().collect(), pages))
}

async fn cloudflare(client: &Client, zone: &str, token: &str) -> Result<Vec<String>, String> {
    let headers = bearer(token);
    let id = parse_cloudflare_zone(
        &get(client, "Cloudflare", &cloudflare_zone_url(zone), &headers).await?,
    )?;
    let mut names = BTreeSet::new();
    for page in 1..=MAX_PAGES {
        let body = get(
            client,
            "Cloudflare",
            &cloudflare_records_url(&id, page),
            &headers,
        )
        .await?;
        let (found, pages) = parse_cloudflare_records(zone, &body)?;
        names.extend(found);
        if page >= pages || names.len() >= PROVIDER_MAX_NAMES {
            break;
        }
    }
    Ok(names.into_iter().collect())
}

// --------------------------------------------------------------------- Gandi

pub fn gandi_url(zone: &str, page: usize) -> String {
    format!(
        "https://api.gandi.net/v5/livedns/domains/{}/records?per_page=500&page={page}",
        zone.trim_end_matches('.')
    )
}

/// The names in Gandi's record list: an array of record sets with names
/// relative to the zone.
pub fn parse_gandi(zone: &str, body: &str) -> Result<(Vec<String>, usize), String> {
    let doc = json("Gandi", body)?;
    let sets = doc
        .as_array()
        .ok_or("Gandi: the answer has no record list")?;
    let mut names = BTreeSet::new();
    for r in sets {
        if let (Some(name), Some(rtype)) = (r["rrset_name"].as_str(), r["rrset_type"].as_str()) {
            keep(&mut names, zone, name, rtype, true);
        }
    }
    Ok((names.into_iter().collect(), sets.len()))
}

async fn gandi(client: &Client, zone: &str, token: &str) -> Result<Vec<String>, String> {
    let headers = bearer(token);
    let mut names = BTreeSet::new();
    for page in 1..=MAX_PAGES {
        let body = get(client, "Gandi", &gandi_url(zone, page), &headers).await?;
        let (found, count) = parse_gandi(zone, &body)?;
        names.extend(found);
        if count < 500 || names.len() >= PROVIDER_MAX_NAMES {
            break;
        }
    }
    Ok(names.into_iter().collect())
}

// ------------------------------------------------------------------- Hetzner

pub fn hetzner_url(zone: &str, page: usize) -> String {
    format!(
        "https://api.hetzner.cloud/v1/zones/{}/rrsets?per_page=100&page={page}",
        zone.trim_end_matches('.')
    )
}

/// The names on one page of Hetzner's record-set list, and whether
/// another page follows. Names are relative to the zone.
pub fn parse_hetzner(zone: &str, body: &str) -> Result<(Vec<String>, bool), String> {
    let doc = json("Hetzner", body)?;
    let sets = doc["rrsets"]
        .as_array()
        .ok_or("Hetzner: the answer has no record list")?;
    let mut names = BTreeSet::new();
    for r in sets {
        if let (Some(name), Some(rtype)) = (r["name"].as_str(), r["type"].as_str()) {
            keep(&mut names, zone, name, rtype, true);
        }
    }
    let more = doc["meta"]["pagination"]["next_page"].is_u64();
    Ok((names.into_iter().collect(), more))
}

async fn hetzner(client: &Client, zone: &str, token: &str) -> Result<Vec<String>, String> {
    let headers = bearer(token);
    let mut names = BTreeSet::new();
    for page in 1..=MAX_PAGES {
        let body = get(client, "Hetzner", &hetzner_url(zone, page), &headers).await?;
        let (found, more) = parse_hetzner(zone, &body)?;
        names.extend(found);
        if !more || names.len() >= PROVIDER_MAX_NAMES {
            break;
        }
    }
    Ok(names.into_iter().collect())
}

// ------------------------------------------------------------------ Route 53

const ROUTE53_HOST: &str = "route53.amazonaws.com";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
        .as_ref()
        .to_vec()
}

/// The key a request of one day, region and service is signed with
/// (AWS Signature Version 4).
pub fn sigv4_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k = hmac_sha256(&k, region.as_bytes());
    let k = hmac_sha256(&k, service.as_bytes());
    hmac_sha256(&k, b"aws4_request")
}

/// What a request is signed as.
pub struct SigV4<'a> {
    pub method: &'a str,
    /// The path, already URI-encoded.
    pub path: &'a str,
    /// The query string, already encoded and sorted by parameter name.
    pub query: &'a str,
    /// The signed headers: lowercase names, sorted, `host` among them.
    pub headers: &'a [(&'a str, &'a str)],
    /// `YYYYMMDDTHHMMSSZ`.
    pub timestamp: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

/// The `Authorization` header value for a request with an empty body.
pub fn sigv4_authorization(request: &SigV4<'_>, key_id: &str, secret: &str) -> String {
    let date = &request.timestamp[..8];
    let canonical_headers: String = request
        .headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect();
    let signed_headers: Vec<&str> = request.headers.iter().map(|(name, _)| *name).collect();
    let signed_headers = signed_headers.join(";");
    let canonical = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{}",
        request.method,
        request.path,
        request.query,
        hex(&Sha256::digest(b""))
    );
    let scope = format!("{date}/{}/{}/aws4_request", request.region, request.service);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        request.timestamp,
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let key = sigv4_signing_key(secret, date, request.region, request.service);
    let signature = hex(&hmac_sha256(&key, to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time.
pub fn amz_timestamp(unix: u64) -> String {
    // `utc` gives "YYYY-MM-DD HH:MM UTC".
    let text = crate::output::utc(unix);
    format!(
        "{}{}{}T{}{}{:02}Z",
        &text[0..4],
        &text[5..7],
        &text[8..10],
        &text[11..13],
        &text[14..16],
        unix % 60
    )
}

/// Percent-encode a query value the way Signature Version 4 wants it.
fn uri_encode(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The text between `<tag>` and `</tag>`, for each occurrence in order.
fn xml_values<'a>(body: &'a str, tag: &str) -> Vec<&'a str> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find(&open) {
        rest = &rest[start + open.len()..];
        let Some(end) = rest.find(&close) else {
            break;
        };
        out.push(&rest[..end]);
        rest = &rest[end + close.len()..];
    }
    out
}

/// The ID of the public hosted zone with exactly this name, from a
/// `ListHostedZonesByName` answer.
pub fn parse_route53_zone(zone: &str, body: &str) -> Result<String, String> {
    for block in xml_values(body, "HostedZone") {
        let name = xml_values(block, "Name").first().copied().unwrap_or("");
        let private = xml_values(block, "PrivateZone").first().copied() == Some("true");
        if private || normalise_zone(name).ok().as_deref() != Some(zone) {
            continue;
        }
        let id = xml_values(block, "Id").first().copied().unwrap_or("");
        let id = id.trim_start_matches("/hostedzone/");
        if !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Ok(id.to_string());
        }
    }
    Err("Amazon Route 53 has no public hosted zone of this name on this account".to_string())
}

/// The names on one page of a `ListResourceRecordSets` answer, and where
/// the next page starts (record name and type) when there is one.
pub fn parse_route53_records(zone: &str, body: &str) -> (Vec<String>, Option<(String, String)>) {
    let mut names = BTreeSet::new();
    for block in xml_values(body, "ResourceRecordSet") {
        let name = xml_values(block, "Name").first().copied().unwrap_or("");
        let rtype = xml_values(block, "Type").first().copied().unwrap_or("");
        // `\052` is how Route 53 writes `*`; such names are not plain.
        keep(&mut names, zone, name, rtype, false);
    }
    let next = (xml_values(body, "IsTruncated").first().copied() == Some("true"))
        .then(|| {
            Some((
                xml_values(body, "NextRecordName").first()?.to_string(),
                xml_values(body, "NextRecordType").first()?.to_string(),
            ))
        })
        .flatten();
    (names.into_iter().collect(), next)
}

async fn route53_get(
    client: &Client,
    path: &str,
    query: &str,
    credential: (&str, &str, Option<&str>),
) -> Result<String, String> {
    let (key_id, secret, session_token) = credential;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let timestamp = amz_timestamp(now);
    let mut signed: Vec<(&str, &str)> = vec![("host", ROUTE53_HOST), ("x-amz-date", &timestamp)];
    if let Some(token) = session_token {
        signed.push(("x-amz-security-token", token));
    }
    let authorization = sigv4_authorization(
        &SigV4 {
            method: "GET",
            path,
            query,
            headers: &signed,
            timestamp: &timestamp,
            // Route 53 is a global service, signed for us-east-1.
            region: "us-east-1",
            service: "route53",
        },
        key_id,
        secret,
    );
    let mut headers: Vec<(&str, String)> = vec![
        ("x-amz-date", timestamp.clone()),
        ("authorization", authorization),
    ];
    if let Some(token) = session_token {
        headers.push(("x-amz-security-token", token.to_string()));
    }
    let url = format!("https://{ROUTE53_HOST}{path}?{query}");
    get(client, "Amazon Route 53", &url, &headers).await
}

async fn route53(
    client: &Client,
    zone: &str,
    credential: (&str, &str, Option<&str>),
) -> Result<Vec<String>, String> {
    let body = route53_get(
        client,
        "/2013-04-01/hostedzonesbyname",
        &format!("dnsname={}&maxitems=5", uri_encode(zone)),
        credential,
    )
    .await?;
    let id = parse_route53_zone(zone, &body)?;
    let path = format!("/2013-04-01/hostedzone/{id}/rrset");
    let mut names = BTreeSet::new();
    let mut query = "maxitems=300".to_string();
    for _ in 0..MAX_PAGES {
        let body = route53_get(client, &path, &query, credential).await?;
        let (found, next) = parse_route53_records(zone, &body);
        names.extend(found);
        match next {
            Some((name, rtype)) if names.len() < PROVIDER_MAX_NAMES => {
                query = format!(
                    "maxitems=300&name={}&type={}",
                    uri_encode(&name),
                    uri_encode(&rtype)
                );
            }
            _ => break,
        }
    }
    Ok(names.into_iter().collect())
}

/// Ask the DNS host for the names in a zone.
pub async fn names(
    client: &Client,
    provider: &str,
    zone: &str,
    credential: &Credential,
) -> Result<Vec<String>, String> {
    let found = match (provider, credential) {
        ("digitalocean", Credential::Token(t)) => {
            crate::discover::digitalocean_names(client, zone, t).await
        }
        ("cloudflare", Credential::Token(t)) => cloudflare(client, zone, t).await,
        ("gandi", Credential::Token(t)) => gandi(client, zone, t).await,
        ("hetzner", Credential::Token(t)) => hetzner(client, zone, t).await,
        (
            "route53",
            Credential::Aws {
                key_id,
                secret,
                session_token,
            },
        ) => route53(client, zone, (key_id, secret, session_token.as_deref())).await,
        _ => Err(format!("{provider} cannot be asked with this credential")),
    }?;
    Ok(found.into_iter().take(PROVIDER_MAX_NAMES).collect())
}

/// A stand-in credential for a replayed run, which sends nothing.
pub fn replay_credential(provider: &str) -> Credential {
    if provider == "route53" {
        Credential::Aws {
            key_id: "REPLAY".to_string(),
            secret: "replay".to_string(),
            session_token: None,
        }
    } else {
        Credential::Token(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE: &str = "example.org.";

    #[test]
    fn the_signing_key_and_signature_match_the_published_example() {
        // The worked example in the AWS Signature Version 4 documentation.
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        assert_eq!(
            hex(&sigv4_signing_key(secret, "20150830", "us-east-1", "iam")),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
        let request = SigV4 {
            method: "GET",
            path: "/",
            query: "Action=ListUsers&Version=2010-05-08",
            headers: &[
                (
                    "content-type",
                    "application/x-www-form-urlencoded; charset=utf-8",
                ),
                ("host", "iam.amazonaws.com"),
                ("x-amz-date", "20150830T123600Z"),
            ],
            timestamp: "20150830T123600Z",
            region: "us-east-1",
            service: "iam",
        };
        assert_eq!(
            sigv4_authorization(&request, "AKIDEXAMPLE", secret),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn timestamps_and_encoding() {
        assert_eq!(amz_timestamp(1_440_938_160), "20150830T123600Z");
        assert_eq!(amz_timestamp(1_700_000_005), "20231114T221325Z");
        assert_eq!(uri_encode("a.b-c_d~e /*"), "a.b-c_d~e%20%2F%2A");
    }

    #[test]
    fn cloudflare_answers_are_read() {
        let zone = r#"{"success":true,"result":[{"id":"023e105f4ecef8ad9ca31a8372d0c353","name":"example.org"}]}"#;
        assert_eq!(
            parse_cloudflare_zone(zone).unwrap(),
            "023e105f4ecef8ad9ca31a8372d0c353"
        );
        assert!(parse_cloudflare_zone(r#"{"success":true,"result":[]}"#).is_err());
        assert!(parse_cloudflare_zone(r#"{"result":[{"id":"../../x"}]}"#).is_err());
        let records = r#"{"result":[
            {"name":"example.org","type":"A"},
            {"name":"WWW.example.org","type":"A"},
            {"name":"*.example.org","type":"A"},
            {"name":"_sip._tcp.example.org","type":"SRV"},
            {"name":"shop.example.org","type":"CNAME"},
            {"name":"www.other.net","type":"A"}],
            "result_info":{"page":1,"total_pages":3}}"#;
        let (names, pages) = parse_cloudflare_records(ZONE, records).unwrap();
        assert_eq!(names, ["shop.example.org.", "www.example.org."]);
        assert_eq!(pages, 3);
        assert_eq!(
            cloudflare_zone_url(ZONE),
            "https://api.cloudflare.com/client/v4/zones?name=example.org"
        );
    }

    #[test]
    fn gandi_and_hetzner_answers_are_read() {
        let gandi = r#"[{"rrset_name":"@","rrset_type":"A"},{"rrset_name":"www","rrset_type":"CNAME"},
            {"rrset_name":"mail","rrset_type":"MX"},{"rrset_name":"*","rrset_type":"A"}]"#;
        let (names, count) = parse_gandi(ZONE, gandi).unwrap();
        assert_eq!(names, ["mail.example.org.", "www.example.org."]);
        assert_eq!(count, 4);
        assert!(parse_gandi(ZONE, r#"{"code":401}"#).is_err());

        let hetzner = r#"{"rrsets":[{"name":"@","type":"NS"},{"name":"api","type":"AAAA"},
            {"name":"_dmarc","type":"TXT"}],"meta":{"pagination":{"page":1,"next_page":2}}}"#;
        let (names, more) = parse_hetzner(ZONE, hetzner).unwrap();
        assert_eq!(names, ["_dmarc.example.org.", "api.example.org."]);
        assert!(more);
        let last = r#"{"rrsets":[],"meta":{"pagination":{"page":2,"next_page":null}}}"#;
        assert!(!parse_hetzner(ZONE, last).unwrap().1);
    }

    #[test]
    fn route53_answers_are_read() {
        let zones = r#"<ListHostedZonesByNameResponse><HostedZones>
            <HostedZone><Id>/hostedzone/ZPRIVATE</Id><Name>example.org.</Name>
              <Config><PrivateZone>true</PrivateZone></Config></HostedZone>
            <HostedZone><Id>/hostedzone/Z1D633PJN98FT9</Id><Name>example.org.</Name>
              <Config><PrivateZone>false</PrivateZone></Config></HostedZone>
            <HostedZone><Id>/hostedzone/ZOTHER</Id><Name>example.org.uk.</Name></HostedZone>
            </HostedZones></ListHostedZonesByNameResponse>"#;
        assert_eq!(parse_route53_zone(ZONE, zones).unwrap(), "Z1D633PJN98FT9");
        assert!(parse_route53_zone("other.org.", zones).is_err());

        let records = r#"<ListResourceRecordSetsResponse><ResourceRecordSets>
            <ResourceRecordSet><Name>example.org.</Name><Type>NS</Type></ResourceRecordSet>
            <ResourceRecordSet><Name>\052.example.org.</Name><Type>A</Type></ResourceRecordSet>
            <ResourceRecordSet><Name>www.example.org.</Name><Type>A</Type></ResourceRecordSet>
            <ResourceRecordSet><Name>mail.example.org.</Name><Type>MX</Type></ResourceRecordSet>
            </ResourceRecordSets><IsTruncated>true</IsTruncated>
            <NextRecordName>zeta.example.org.</NextRecordName><NextRecordType>TXT</NextRecordType>
            </ListResourceRecordSetsResponse>"#;
        let (names, next) = parse_route53_records(ZONE, records);
        assert_eq!(names, ["mail.example.org.", "www.example.org."]);
        assert_eq!(
            next,
            Some(("zeta.example.org.".to_string(), "TXT".to_string()))
        );
        assert_eq!(parse_route53_records(ZONE, "<x/>"), (vec![], None));
    }

    #[test]
    fn credentials_are_read_and_never_printed() {
        let c = parse_aws_credentials(
            "[default]\naws_access_key_id = AKIDEXAMPLE\naws_secret_access_key=abc/def+ghi\n",
        )
        .unwrap();
        assert!(
            matches!(&c, Credential::Aws { key_id, secret, session_token: None }
            if key_id == "AKIDEXAMPLE" && secret == "abc/def+ghi")
        );
        assert_eq!(format!("{c:?}"), "Credential(..)");
        assert!(parse_aws_credentials("aws_access_key_id = x\n").is_err());
        for provider in PROVIDERS {
            assert!(!env_names(provider).is_empty());
            assert_ne!(label(provider), "the DNS host");
        }
    }
}
