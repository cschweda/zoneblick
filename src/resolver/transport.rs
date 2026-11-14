//! Sends one DNS query to one server and returns the raw outcome.
//!
//! The [`Client`] has two backends. The live backend talks to the network,
//! with timeouts, retries and the [`Limiter`]. The replay backend answers from
//! a [`Fixture`]. Either can record its exchanges, so a real run can be saved
//! to a fixture and replayed deterministically.
//!
//! Responses stay as wire bytes here. Parsing happens above this layer, so a
//! replayed run exercises the same parsing code as a live one.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, Query};
use hickory_proto::rr::{Name, RecordType};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::limiter::Limiter;
use crate::observe::{Probe, QType, Transport};

/// Network behaviour of the live backend. Defaults follow `DESIGN.md` where
/// it gives a value (`max_qps_per_server = 5`); the rest are in `DECISIONS.md`.
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// Queries in flight at once, across all servers.
    pub concurrency: usize,
    /// Queries per second to any one server address.
    pub qps_per_server: u32,
    pub udp_timeout: Duration,
    pub tcp_timeout: Duration,
    /// Extra attempts after a timeout.
    pub retries: u32,
    /// Wait before the first retry; doubles for each retry after that.
    pub backoff: Duration,
    /// The UDP payload size advertised in EDNS queries.
    pub edns_payload: u16,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            concurrency: 16,
            qps_per_server: 5,
            udp_timeout: Duration::from_secs(3),
            tcp_timeout: Duration::from_secs(5),
            retries: 2,
            backoff: Duration::from_millis(500),
            edns_payload: 1232,
        }
    }
}

/// One query: which server, how, and what was asked.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QuerySpec {
    pub server: IpAddr,
    pub transport: Transport,
    /// Lowercase, fully qualified.
    pub qname: String,
    pub qtype: QType,
    pub edns: bool,
    /// Set the DO bit, asking for DNSSEC records. Needs `edns`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dnssec: bool,
    /// An unusual way of asking; plain for everything but the deep probes.
    #[serde(default, skip_serializing_if = "Probe::is_plain")]
    pub probe: Probe,
}

/// What came back, before parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RawOutcome {
    Response {
        #[serde(with = "hex_bytes")]
        wire: Vec<u8>,
    },
    Timeout,
    NetError {
        message: String,
    },
}

/// One recorded query and its outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exchange {
    #[serde(flatten)]
    pub query: QuerySpec,
    pub outcome: RawOutcome,
}

/// A recorded run: every exchange, plus the start time so replays are stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fixture {
    pub version: u32,
    pub zone: String,
    pub started_at_unix: u64,
    pub exchanges: Vec<Exchange>,
    /// HTTP fetches made during the run (the MTA-STS policy file).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http: Vec<HttpExchange>,
}

/// What an HTTP GET returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HttpOutcome {
    Response { status: u16, body: String },
    Error { message: String },
}

/// One recorded HTTP GET.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpExchange {
    pub url: String,
    pub outcome: HttpOutcome,
}

impl Fixture {
    pub const VERSION: u32 = 1;
}

enum Backend {
    Live(NetConfig),
    Replay(HashMap<QuerySpec, RawOutcome>),
}

pub struct Client {
    backend: Backend,
    limiter: Limiter,
    recording: Option<Mutex<Vec<Exchange>>>,
    sent: AtomicUsize,
    http_replay: HashMap<String, HttpOutcome>,
    http_recording: Mutex<Vec<HttpExchange>>,
}

/// The most of an HTTP body that is read.
const HTTP_BODY_LIMIT: usize = 64 * 1024;

impl Client {
    /// A client that talks to the network.
    pub fn live(config: NetConfig) -> Self {
        Self {
            limiter: Limiter::new(config.concurrency, config.qps_per_server),
            backend: Backend::Live(config),
            recording: None,
            sent: AtomicUsize::new(0),
            http_replay: HashMap::new(),
            http_recording: Mutex::new(Vec::new()),
        }
    }

    /// A client that answers only from recorded exchanges.
    pub fn replay(fixture: &Fixture) -> Self {
        let map = fixture
            .exchanges
            .iter()
            .map(|e| (e.query.clone(), e.outcome.clone()))
            .collect();
        Self {
            limiter: Limiter::new(1, 1),
            backend: Backend::Replay(map),
            recording: None,
            sent: AtomicUsize::new(0),
            http_replay: fixture
                .http
                .iter()
                .map(|e| (e.url.clone(), e.outcome.clone()))
                .collect(),
            http_recording: Mutex::new(Vec::new()),
        }
    }

    /// Keep a copy of every exchange, for [`Client::take_recording`].
    pub fn with_recording(mut self) -> Self {
        self.recording = Some(Mutex::new(Vec::new()));
        self
    }

    /// The exchanges seen so far, in the order they completed.
    pub fn take_recording(&self) -> Vec<Exchange> {
        match &self.recording {
            Some(rec) => std::mem::take(&mut *rec.lock().expect("recording lock")),
            None => Vec::new(),
        }
    }

    /// The HTTP fetches seen so far.
    pub fn take_http_recording(&self) -> Vec<HttpExchange> {
        std::mem::take(&mut *self.http_recording.lock().expect("recording lock"))
    }

    /// Fetch a URL over HTTPS. Redirects are not followed and at most 64 KB
    /// of the body is kept. A replaying client answers from its fixture.
    pub async fn http_get(&self, url: &str) -> HttpOutcome {
        self.http_get_with(url, HTTP_BODY_LIMIT, Duration::from_secs(10))
            .await
    }

    /// [`Client::http_get`], connecting to `address` whatever the system
    /// resolver would say the URL's host is. For hosts whose address is
    /// chosen by the zone being checked: the caller resolves the name
    /// itself and refuses addresses that are not public.
    pub async fn http_get_at(&self, url: &str, address: IpAddr) -> HttpOutcome {
        self.http_fetch(
            url,
            &[],
            Some(address),
            HTTP_BODY_LIMIT,
            Duration::from_secs(10),
        )
        .await
    }

    /// [`Client::http_get`] with its own body limit and timeout.
    pub async fn http_get_with(&self, url: &str, limit: usize, timeout: Duration) -> HttpOutcome {
        self.http_get_auth(url, None, limit, timeout).await
    }

    /// [`Client::http_get_with`], sending `bearer` as a bearer token when
    /// given. The token is never recorded: a fixture holds only the URL and
    /// the answer.
    pub async fn http_get_auth(
        &self,
        url: &str,
        bearer: Option<&str>,
        limit: usize,
        timeout: Duration,
    ) -> HttpOutcome {
        let headers: Vec<(&str, String)> = bearer
            .map(|token| ("authorization", format!("Bearer {token}")))
            .into_iter()
            .collect();
        self.http_get_headers(url, &headers, limit, timeout).await
    }

    /// [`Client::http_get_with`], sending these request headers as well.
    /// Headers carry credentials, so they are never recorded: a fixture
    /// holds only the URL and the answer.
    pub async fn http_get_headers(
        &self,
        url: &str,
        headers: &[(&str, String)],
        limit: usize,
        timeout: Duration,
    ) -> HttpOutcome {
        self.http_fetch(url, headers, None, limit, timeout).await
    }

    async fn http_fetch(
        &self,
        url: &str,
        headers: &[(&str, String)],
        pin: Option<IpAddr>,
        limit: usize,
        timeout: Duration,
    ) -> HttpOutcome {
        let outcome = match &self.backend {
            Backend::Replay(_) => {
                self.http_replay
                    .get(url)
                    .cloned()
                    .unwrap_or(HttpOutcome::Error {
                        message: "no recorded exchange for this URL".to_string(),
                    })
            }
            Backend::Live(_) => live_http_get(url, headers, pin, limit, timeout).await,
        };
        let mut rec = self.http_recording.lock().expect("recording lock");
        if !rec.iter().any(|e| e.url == url) {
            rec.push(HttpExchange {
                url: url.to_string(),
                outcome: outcome.clone(),
            });
        }
        outcome
    }

    /// True when this client talks to the network, not to a fixture.
    pub fn is_live(&self) -> bool {
        matches!(self.backend, Backend::Live(_))
    }

    /// How many queries were asked of this client.
    pub fn queries_sent(&self) -> usize {
        self.sent.load(Ordering::Relaxed)
    }

    /// Send one query and wait for its outcome.
    pub async fn exchange(&self, spec: &QuerySpec) -> RawOutcome {
        self.sent.fetch_add(1, Ordering::Relaxed);
        let outcome = match &self.backend {
            Backend::Live(config) => self.exchange_live(config, spec).await,
            Backend::Replay(map) => map.get(spec).cloned().unwrap_or(RawOutcome::NetError {
                message: "no recorded exchange for this query".to_string(),
            }),
        };
        if let Some(rec) = &self.recording {
            let mut rec = rec.lock().expect("recording lock");
            if !rec.iter().any(|e| &e.query == spec) {
                rec.push(Exchange {
                    query: spec.clone(),
                    outcome: outcome.clone(),
                });
            }
        }
        outcome
    }

    async fn exchange_live(&self, config: &NetConfig, spec: &QuerySpec) -> RawOutcome {
        // A zone can name any address as its nameserver. No real one is
        // on this machine's loopback or link-local range, so those are
        // never queried: a hostile zone must not get zoneblick to probe
        // services of the machine it runs on.
        if let Some(why) = never_contacted(spec.server) {
            return RawOutcome::NetError {
                message: format!("not queried: {} is a {why} address", spec.server),
            };
        }
        let (id, wire) = match build_query(spec, config.edns_payload) {
            Ok(q) => q,
            Err(message) => return RawOutcome::NetError { message },
        };
        let timeout = match spec.transport {
            Transport::Udp => config.udp_timeout,
            Transport::Tcp => config.tcp_timeout,
        };
        let mut backoff = config.backoff;
        for attempt in 0..=config.retries {
            if attempt > 0 {
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
            let _permit = self.limiter.acquire(spec.server).await;
            let target = SocketAddr::new(spec.server, 53);
            let sent = async {
                match spec.transport {
                    Transport::Udp => send_udp(target, id, &wire).await,
                    Transport::Tcp => send_tcp(target, &wire).await,
                }
            };
            match tokio::time::timeout(timeout, sent).await {
                Ok(Ok(wire)) => return RawOutcome::Response { wire },
                Ok(Err(e)) => {
                    return RawOutcome::NetError {
                        message: e.to_string(),
                    };
                }
                Err(_) => continue,
            }
        }
        RawOutcome::Timeout
    }
}

async fn live_http_get(
    url: &str,
    headers: &[(&str, String)],
    pin: Option<IpAddr>,
    limit: usize,
    timeout: Duration,
) -> HttpOutcome {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let error = |e: reqwest::Error| HttpOutcome::Error {
        message: e.to_string(),
    };
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("zoneblick/", env!("CARGO_PKG_VERSION")));
    if let Some(address) = pin {
        // The pin only binds a host *name*. A URL whose host is an IP
        // address, or that carries a user name, would connect elsewhere
        // than the address that was checked, so it is refused.
        let parsed = reqwest::Url::parse(url).ok();
        let host = parsed
            .as_ref()
            .filter(|u| u.username().is_empty())
            .and_then(|u| u.host_str())
            .filter(|h| !h.starts_with('[') && h.parse::<IpAddr>().is_err())
            .map(str::to_string);
        let port = parsed.as_ref().and_then(|u| u.port_or_known_default());
        let (Some(host), Some(port)) = (host, port) else {
            return HttpOutcome::Error {
                message: "not fetched: the address does not name a plain host".to_string(),
            };
        };
        builder = builder.resolve(&host, SocketAddr::new(address, port));
    }
    let client = match builder.build() {
        Ok(client) => client,
        Err(e) => return error(e),
    };
    let mut request = client.get(url);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let mut response = match request.send().await {
        Ok(response) => response,
        Err(e) => return error(e),
    };
    let status = response.status().as_u16();
    let mut body: Vec<u8> = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let room = limit.saturating_sub(body.len());
                body.extend_from_slice(&chunk[..chunk.len().min(room)]);
                if body.len() >= limit {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => return error(e),
        }
    }
    HttpOutcome::Response {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// Why zoneblick never opens a connection to an address, if it does not:
/// loopback, link-local (which includes cloud metadata services),
/// unspecified, multicast and broadcast addresses, also when written as
/// IPv4-mapped IPv6. Private ranges are allowed, because internal zones
/// with internal nameservers are a normal thing to watch.
pub fn never_contacted(address: IpAddr) -> Option<&'static str> {
    let address = match address {
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(a),
        },
        v4 => v4,
    };
    match address {
        IpAddr::V4(a) if a.is_loopback() => Some("loopback"),
        IpAddr::V4(a) if a.is_link_local() => Some("link-local"),
        IpAddr::V4(a) if a.is_unspecified() || a.is_broadcast() => Some("reserved"),
        IpAddr::V4(a) if a.is_multicast() => Some("multicast"),
        IpAddr::V6(a) if a.is_loopback() => Some("loopback"),
        IpAddr::V6(a) if a.is_unspecified() => Some("reserved"),
        IpAddr::V6(a) if a.is_multicast() => Some("multicast"),
        IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80 => Some("link-local"),
        _ => None,
    }
}

/// Build the wire form of a query. Returns the message ID with it.
fn build_query(spec: &QuerySpec, edns_payload: u16) -> Result<(u16, Vec<u8>), String> {
    let qname = match spec.probe {
        Probe::MixedCase => mixed_case(&spec.qname),
        _ => spec.qname.clone(),
    };
    let name = Name::from_ascii(&qname).map_err(|e| e.to_string())?;
    // `Message::query` picks a random ID. Recursion is asked for only by
    // the probe that tests for it.
    let mut msg = Message::query();
    msg.metadata.recursion_desired = spec.probe == Probe::Recursion;
    msg.add_query(Query::query(name, record_type(spec.qtype)));
    if spec.edns {
        let mut edns = Edns::new();
        let version = u8::from(spec.probe == Probe::EdnsVersion1);
        edns.set_version(version).set_max_payload(edns_payload);
        edns.set_dnssec_ok(spec.dnssec);
        msg.set_edns(edns);
    }
    let mut wire = msg.to_vec().map_err(|e| e.to_string())?;
    if spec.edns && spec.probe == Probe::EdnsUnknownOption {
        // The OPT record is the last thing in the message and carries no
        // options, so it ends with a zero data length. Replace that with
        // one option from the range reserved for local use.
        let end = wire.len();
        if end < 2 || wire[end - 2..] != [0, 0] {
            return Err("cannot add an EDNS option to this query".to_string());
        }
        wire.truncate(end - 2);
        wire.extend_from_slice(&[0, 8, 0xFD, 0xE9, 0, 4, b'z', b'b', b'l', b'k']);
    }
    Ok((msg.metadata.id, wire))
}

/// The name with every second letter in upper case.
pub(crate) fn mixed_case(name: &str) -> String {
    let mut upper = false;
    name.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                upper = !upper;
                if upper {
                    return c.to_ascii_uppercase();
                }
            }
            c
        })
        .collect()
}

pub(crate) fn record_type(qtype: QType) -> RecordType {
    match qtype {
        QType::Soa => RecordType::SOA,
        QType::Ns => RecordType::NS,
        QType::A => RecordType::A,
        QType::Aaaa => RecordType::AAAA,
        QType::Cname => RecordType::CNAME,
        QType::Mx => RecordType::MX,
        QType::Txt => RecordType::TXT,
        QType::Caa => RecordType::CAA,
        QType::Ds => RecordType::DS,
        QType::Dnskey => RecordType::DNSKEY,
        QType::Nsec3param => RecordType::NSEC3PARAM,
        QType::Cds => RecordType::CDS,
        QType::Cdnskey => RecordType::CDNSKEY,
        QType::Tlsa => RecordType::TLSA,
    }
}

async fn send_udp(target: SocketAddr, id: u16, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let local: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid address")
    } else {
        "[::]:0".parse().expect("valid address")
    };
    let socket = UdpSocket::bind(local).await?;
    // A connected socket only accepts datagrams from the server we asked.
    socket.connect(target).await?;
    socket.send(query).await?;
    let mut buf = vec![0u8; 65535];
    loop {
        let n = socket.recv(&mut buf).await?;
        // Ignore anything that does not carry our message ID.
        if n >= 2 && buf[..2] == id.to_be_bytes() {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

async fn send_tcp(target: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(target).await?;
    let len = u16::try_from(query.len())
        .map_err(|_| std::io::Error::other("query too large for TCP framing"))?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).await?;
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let mut buf = vec![0u8; u16::from_be_bytes(len_buf) as usize];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Wire bytes as a lowercase hex string in JSON.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        if text.len() % 2 != 0 || !text.is_ascii() {
            return Err(D::Error::custom("hex string has odd length or non-ASCII"));
        }
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(D::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> QuerySpec {
        QuerySpec {
            server: "192.0.2.53".parse().unwrap(),
            transport: Transport::Udp,
            qname: "example.com.".to_string(),
            qtype: QType::Soa,
            edns: true,
            dnssec: false,
            probe: Default::default(),
        }
    }

    #[test]
    fn query_has_edns_and_no_recursion() {
        let (id, wire) = build_query(&spec(), 1232).unwrap();
        let msg = Message::from_vec(&wire).unwrap();
        assert_eq!(msg.metadata.id, id);
        assert!(!msg.metadata.recursion_desired);
        assert_eq!(msg.queries[0].query_type(), RecordType::SOA);
        assert_eq!(msg.edns.as_ref().unwrap().max_payload(), 1232);

        let mut plain = spec();
        plain.edns = false;
        let (_, wire) = build_query(&plain, 1232).unwrap();
        assert!(Message::from_vec(&wire).unwrap().edns.is_none());

        let signed = QuerySpec {
            dnssec: true,
            probe: Default::default(),
            ..spec()
        };
        let (_, wire) = build_query(&signed, 1232).unwrap();
        let msg = Message::from_vec(&wire).unwrap();
        assert!(msg.edns.as_ref().unwrap().flags().dnssec_ok);
        // The flag is left out of fixtures unless set, so old fixtures still load.
        assert!(!serde_json::to_string(&spec()).unwrap().contains("dnssec"));
        assert!(
            serde_json::to_string(&signed)
                .unwrap()
                .contains(r#""dnssec":true"#)
        );
    }

    #[test]
    fn fixture_round_trips_through_json() {
        let fixture = Fixture {
            version: Fixture::VERSION,
            zone: "example.com.".to_string(),
            started_at_unix: 1,
            http: vec![],
            exchanges: vec![
                Exchange {
                    query: spec(),
                    outcome: RawOutcome::Response {
                        wire: vec![0x00, 0xab, 0xff],
                    },
                },
                Exchange {
                    query: QuerySpec {
                        transport: Transport::Tcp,
                        ..spec()
                    },
                    outcome: RawOutcome::Timeout,
                },
            ],
        };
        let json = serde_json::to_string(&fixture).unwrap();
        assert!(json.contains(r#""wire":"00abff""#));
        assert_eq!(serde_json::from_str::<Fixture>(&json).unwrap(), fixture);
    }

    #[tokio::test]
    async fn replay_answers_from_the_fixture_and_records() {
        let fixture = Fixture {
            version: Fixture::VERSION,
            zone: "example.com.".to_string(),
            started_at_unix: 1,
            http: vec![],
            exchanges: vec![Exchange {
                query: spec(),
                outcome: RawOutcome::Timeout,
            }],
        };
        let client = Client::replay(&fixture).with_recording();
        assert_eq!(client.exchange(&spec()).await, RawOutcome::Timeout);
        let missing = QuerySpec {
            qtype: QType::Ns,
            ..spec()
        };
        assert!(matches!(
            client.exchange(&missing).await,
            RawOutcome::NetError { .. }
        ));
        assert_eq!(client.queries_sent(), 2);
        assert_eq!(client.take_recording().len(), 2);
    }

    #[test]
    fn probe_queries_are_built_as_asked() {
        let with = |probe: Probe| {
            let spec = QuerySpec {
                qname: "www.example.org.".to_string(),
                probe,
                ..spec()
            };
            build_query(&spec, 1232).unwrap().1
        };
        let plain = Message::from_vec(&with(Probe::Plain)).unwrap();
        assert!(!plain.metadata.recursion_desired);
        assert_eq!(plain.edns.as_ref().unwrap().version(), 0);

        let v1 = Message::from_vec(&with(Probe::EdnsVersion1)).unwrap();
        assert_eq!(v1.edns.as_ref().unwrap().version(), 1);

        assert!(
            Message::from_vec(&with(Probe::Recursion))
                .unwrap()
                .metadata
                .recursion_desired
        );

        // The unknown option is appended and the message still parses.
        let wire = with(Probe::EdnsUnknownOption);
        assert_eq!(wire.len(), with(Probe::Plain).len() + 8);
        assert!(wire.ends_with(&[0xFD, 0xE9, 0, 4, b'z', b'b', b'l', b'k']));
        assert!(Message::from_vec(&wire).unwrap().edns.is_some());

        // Mixed case goes out on the wire as written.
        assert_eq!(mixed_case("www.example.org."), "WwW.eXaMpLe.OrG.");
        let wire = with(Probe::MixedCase);
        assert!(wire.windows(3).any(|w| w == b"WwW"), "{wire:?}");
        // A plain query needs no probe field in a fixture.
        let json = serde_json::to_string(&spec()).unwrap();
        assert!(!json.contains("probe"), "{json}");
    }
}
