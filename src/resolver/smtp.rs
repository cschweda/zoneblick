//! Reads the certificate a mail server presents after STARTTLS, so it can
//! be compared with the server's TLSA records (DANE, RFC 7672).
//!
//! The certificate is not validated against any authority here: DANE
//! replaces that, and the TLSA comparison is the check. The connection
//! says EHLO, STARTTLS and QUIT and nothing else; no mail is sent.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256, Sha512};

const TIMEOUT: Duration = Duration::from_secs(10);
/// The whole exchange must end within this, however slowly the server
/// feeds it: a server that sends one byte every few seconds would
/// otherwise keep the connection, and a thread, for many minutes.
const DEADLINE: Duration = Duration::from_secs(30);

/// Give the next read or write on `stream` the time that is left before
/// `deadline`, at most [`TIMEOUT`]. Fails once the deadline has passed.
fn arm(stream: &TcpStream, deadline: std::time::Instant) -> Result<(), String> {
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    if left.is_zero() {
        return Err("the server took too long".to_string());
    }
    let limit = Some(left.min(TIMEOUT));
    stream
        .set_read_timeout(limit)
        .and_then(|()| stream.set_write_timeout(limit))
        .map_err(|e| e.to_string())
}
/// A reply longer than this is not SMTP.
const MAX_REPLY_LINES: usize = 60;
const MAX_LINE: u64 = 2048;

/// Accepts any certificate, so that it can be read and compared with the
/// TLSA records. Handshake signatures are still verified, so the server
/// must hold the key of the certificate it shows.
#[derive(Debug)]
pub(crate) struct AnyCertificate(pub(crate) Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A connection on which every single read and write is held to the
/// overall deadline. Buffered readers and the TLS handshake make many
/// small reads; each one gets only the time that is left.
struct Timed {
    stream: TcpStream,
    deadline: std::time::Instant,
}

impl Timed {
    fn arm(&self) -> std::io::Result<()> {
        arm(&self.stream, self.deadline)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::TimedOut, e))
    }
}

impl Read for Timed {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.stream.read(buf)
    }
}

impl Write for Timed {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

/// Read one SMTP reply: its code and its lines, without the code.
fn reply(reader: &mut BufReader<Timed>) -> Result<(u16, Vec<String>), String> {
    let mut lines = Vec::new();
    for _ in 0..MAX_REPLY_LINES {
        let mut line = String::new();
        let n = reader
            .by_ref()
            .take(MAX_LINE)
            .read_line(&mut line)
            .map_err(|e| format!("no reply: {e}"))?;
        if n == 0 {
            return Err("the server closed the connection".to_string());
        }
        let line = line.trim_end();
        let (Some(code), Some(rest)) = (line.get(..3), line.get(3..)) else {
            return Err("the reply is not SMTP".to_string());
        };
        let code: u16 = code
            .parse()
            .map_err(|_| "the reply is not SMTP".to_string())?;
        lines.push(rest.trim_start_matches(['-', ' ']).to_string());
        // "250-..." continues; "250 ..." (or a bare code) is the last line.
        if !rest.starts_with('-') {
            return Ok((code, lines));
        }
    }
    Err("the reply does not end".to_string())
}

/// Connect to a mail server, start TLS, and return the certificates it
/// presents, its own first, as DER. Blocking; call from a blocking task.
pub fn starttls_certificates(addr: SocketAddr, host: &str) -> Result<Vec<Vec<u8>>, String> {
    let io = |e: std::io::Error| e.to_string();
    let deadline = std::time::Instant::now() + DEADLINE;
    let stream = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(io)?;
    arm(&stream, deadline)?;
    let mut reader = BufReader::new(Timed {
        stream: stream.try_clone().map_err(io)?,
        deadline,
    });
    let mut writer = Timed { stream, deadline };

    let (code, _) = reply(&mut reader)?;
    if code != 220 {
        return Err(format!("the server greeted with {code}, not 220"));
    }
    writer
        .write_all(b"EHLO zoneblick.invalid\r\n")
        .map_err(io)?;
    let (code, extensions) = reply(&mut reader)?;
    if code != 250 {
        return Err(format!("EHLO was answered with {code}"));
    }
    if !extensions
        .iter()
        .any(|e| e.eq_ignore_ascii_case("STARTTLS"))
    {
        return Err(NO_STARTTLS.to_string());
    }
    writer.write_all(b"STARTTLS\r\n").map_err(io)?;
    let (code, _) = reply(&mut reader)?;
    if code != 220 {
        return Err(format!("STARTTLS was answered with {code}"));
    }
    // Anything the server sent ahead of the handshake would be a
    // plaintext injection; a clean server has sent nothing.
    if !reader.buffer().is_empty() {
        return Err("the server sent data before the TLS handshake".to_string());
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let name = ServerName::try_from(host.trim_end_matches('.').to_string())
        .map_err(|_| "the server's name cannot be used for TLS".to_string())?;
    let mut tls =
        rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    while tls.is_handshaking() {
        tls.complete_io(&mut writer)
            .map_err(|e| format!("the TLS handshake failed: {e}"))?;
    }
    let chain: Vec<Vec<u8>> = tls
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect();
    // Leave politely; the answer does not matter.
    let mut session = rustls::Stream::new(&mut tls, &mut writer);
    let _ = session.write_all(b"QUIT\r\n");
    if chain.is_empty() {
        return Err("the server presented no certificate".to_string());
    }
    Ok(chain)
}

/// Connect to a TLS port (443 for the web), finish the handshake under the
/// given name, and return the certificates the server presents, its own
/// first, as DER. Nothing is sent after the handshake. Blocking; call
/// from a blocking task.
pub fn tls_certificates(addr: SocketAddr, host: &str) -> Result<Vec<Vec<u8>>, String> {
    let io = |e: std::io::Error| e.to_string();
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(io)?;
    arm(&stream, deadline)?;
    let mut stream = Timed { stream, deadline };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let name = ServerName::try_from(host.trim_end_matches('.').to_string())
        .map_err(|_| "the name cannot be used for TLS".to_string())?;
    let mut tls =
        rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    while tls.is_handshaking() {
        tls.complete_io(&mut stream)
            .map_err(|e| format!("the TLS handshake failed: {e}"))?;
    }
    let chain: Vec<Vec<u8>> = tls
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect();
    tls.send_close_notify();
    let _ = tls.complete_io(&mut stream);
    if chain.is_empty() {
        return Err("the server presented no certificate".to_string());
    }
    Ok(chain)
}

/// When a certificate runs out, and the DNS names it is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    pub not_after_unix: u64,
    pub names: Vec<String>,
}

/// At most this many names are read from one certificate.
const MAX_CERTIFICATE_NAMES: usize = 100;

/// A time in a certificate: `YYMMDDHHMMSSZ` (tag 0x17) or
/// `YYYYMMDDHHMMSSZ` (tag 0x18).
fn certificate_time(tag: u8, content: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(content).ok()?;
    let digits = text.strip_suffix('Z')?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, rest) = match (tag, digits.len()) {
        (0x17, 12) => {
            let yy: u32 = digits[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &digits[2..])
        }
        (0x18, 14) => (digits[..4].parse().ok()?, &digits[4..]),
        _ => return None,
    };
    crate::registration::parse_rfc3339(&format!(
        "{year:04}-{}-{}T{}:{}:{}Z",
        &rest[..2],
        &rest[2..4],
        &rest[4..6],
        &rest[6..8],
        &rest[8..10]
    ))
}

/// Read the end of validity and the subject alternative names of a
/// certificate. The certificate comes from a server someone else runs, so
/// every length is checked and names are kept only when they look like
/// DNS names.
pub fn certificate_info(certificate: &[u8]) -> Option<CertificateInfo> {
    let (0x30, _, body, _) = der(certificate)? else {
        return None;
    };
    let (0x30, _, mut fields, _) = der(body)? else {
        return None;
    };
    let (tag, _, _, rest) = der(fields)?;
    if tag == 0xa0 {
        fields = rest;
    }
    // serial, signature algorithm, issuer
    for _ in 0..3 {
        fields = der(fields)?.3;
    }
    let (0x30, _, validity, mut fields) = der(fields)? else {
        return None;
    };
    let (_, _, _, after) = der(validity)?;
    let (tag, _, content, _) = der(after)?;
    let not_after_unix = certificate_time(tag, content)?;
    // subject, public key
    for _ in 0..2 {
        fields = der(fields)?.3;
    }
    let mut names = Vec::new();
    while let Some((tag, _, content, rest)) = der(fields) {
        fields = rest;
        // [3]: the extensions, a list inside a list.
        if tag != 0xa3 {
            continue;
        }
        let Some((0x30, _, mut extensions, _)) = der(content) else {
            break;
        };
        while let Some((0x30, _, extension, rest)) = der(extensions) {
            extensions = rest;
            let Some((0x06, _, oid, mut value)) = der(extension) else {
                continue;
            };
            // 2.5.29.17, subjectAltName
            if oid != [0x55, 0x1d, 0x11] {
                continue;
            }
            // An optional "critical" flag comes before the value.
            if let Some((0x01, _, _, rest)) = der(value) {
                value = rest;
            }
            let Some((0x04, _, inner, _)) = der(value) else {
                continue;
            };
            let Some((0x30, _, mut general, _)) = der(inner) else {
                continue;
            };
            while let Some((tag, _, name, rest)) = der(general) {
                general = rest;
                // [2]: a DNS name.
                if tag == 0x82
                    && names.len() < MAX_CERTIFICATE_NAMES
                    && !name.is_empty()
                    && name.len() <= 253
                    && name
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._*".contains(b))
                {
                    names.push(String::from_utf8_lossy(name).to_ascii_lowercase());
                }
            }
        }
    }
    names.sort();
    names.dedup();
    Some(CertificateInfo {
        not_after_unix,
        names,
    })
}

/// Whether a certificate with these names is good for `host`. A wildcard
/// stands for exactly one label, the leftmost.
pub fn certificate_covers(names: &[String], host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    names.iter().any(|name| {
        let name = name.trim_end_matches('.');
        match name.strip_prefix("*.") {
            Some(parent) => host
                .split_once('.')
                .is_some_and(|(label, rest)| !label.is_empty() && rest == parent),
            None => name == host,
        }
    })
}

/// The error text for a server that does not offer STARTTLS at all.
pub const NO_STARTTLS: &str = "the server does not offer STARTTLS";

/// One DER element: its tag, the whole element, its content, and what
/// follows it.
type Element<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

fn der(data: &[u8]) -> Option<Element<'_>> {
    let tag = *data.first()?;
    let first = *data.get(1)?;
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let bytes = data.get(2..2 + count)?;
        (
            bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize),
            2 + count,
        )
    };
    let end = header.checked_add(len)?;
    let whole = data.get(..end)?;
    Some((tag, whole, &whole[header..], &data[end..]))
}

/// The SubjectPublicKeyInfo of a certificate, as DER: the seventh field
/// of the certificate body, after the optional version, the serial, the
/// signature algorithm, the issuer, the validity and the subject.
pub fn public_key_info(certificate: &[u8]) -> Option<&[u8]> {
    let (0x30, _, body, _) = der(certificate)? else {
        return None;
    };
    let (0x30, _, mut fields, _) = der(body)? else {
        return None;
    };
    let (tag, _, _, rest) = der(fields)?;
    if tag == 0xa0 {
        fields = rest;
    }
    // serial, signature algorithm, issuer, validity, subject
    for _ in 0..5 {
        fields = der(fields)?.3;
    }
    let (0x30, whole, _, _) = der(fields)? else {
        return None;
    };
    Some(whole)
}

/// Whether one TLSA record (`usage selector matching data`, as text)
/// matches a certificate chain. `None` when the record cannot be used
/// here: bad parameters, or a usage that needs a public authority.
pub fn tlsa_matches(record: &str, chain: &[Vec<u8>]) -> Option<bool> {
    let fields: Vec<&str> = record.split_whitespace().collect();
    let [usage, selector, matching, data] = fields.as_slice() else {
        return None;
    };
    let data = crate::dnssec::unhex(&data.to_ascii_lowercase())?;
    let candidates: &[Vec<u8>] = match *usage {
        // DANE-EE: the server's own certificate.
        "3" => chain.get(..1)?,
        // DANE-TA: any certificate in the chain it sent.
        "2" => chain,
        _ => return None,
    };
    let matches = |cert: &Vec<u8>| -> Option<bool> {
        let selected: &[u8] = match *selector {
            "0" => cert,
            "1" => public_key_info(cert)?,
            _ => return None,
        };
        Some(match *matching {
            "0" => selected == data.as_slice(),
            "1" => Sha256::digest(selected).as_slice() == data.as_slice(),
            "2" => Sha512::digest(selected).as_slice() == data.as_slice(),
            _ => return None,
        })
    };
    let mut any_usable = false;
    for cert in candidates {
        match matches(cert) {
            Some(true) => return Some(true),
            Some(false) => any_usable = true,
            None => {}
        }
    }
    any_usable.then_some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate made with openssl: names
    /// mail.test.example, *.test.example and Other.Example (marked
    /// critical), valid until 2027-11-14 16:27:04 UTC.
    const TEST_CERTIFICATE: &[&str] = &[
        "3082019130820137a003020102021415fe9709cd7e44faf4bf187da1d5297ea372403b300a06082a",
        "8648ce3d04030230173115301306035504030c0c746573742e6578616d706c65301e170d32363131",
        "31343136323730345a170d3237313131343136323730345a30173115301306035504030c0c746573",
        "742e6578616d706c653059301306072a8648ce3d020106082a8648ce3d030107034200047e110660",
        "22b2dee84118d48ccf5aeba01b8826f6f78f40d55de7fa02ab4e1fb67b49cc301e992544ae6497e8",
        "88cba079fbbeb74f4854424970067239476cda33a361305f303e0603551d110101ff043430328211",
        "6d61696c2e746573742e6578616d706c65820e2a2e746573742e6578616d706c65820d4f74686572",
        "2e4578616d706c65301d0603551d0e04160414a0d09364f1feee94166fdee827c7e8d13879440c30",
        "0a06082a8648ce3d0403020348003045022100c8da02cb1afbf45823a9392cb29a519b70b5bfb14e",
        "98c5ab8cb9bc35d27af01a0220387ca256bb5170b1313251644754819907bad3d938591cb03f38f8",
        "e1ec65e1aa",
    ];

    fn test_certificate() -> Vec<u8> {
        let hex = TEST_CERTIFICATE.concat();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_end_date_and_names_of_a_certificate_are_read() {
        let der = test_certificate();
        let info = certificate_info(&der).unwrap();
        assert_eq!(info.not_after_unix, 1_826_209_624);
        assert_eq!(
            info.names,
            ["*.test.example", "mail.test.example", "other.example"]
        );
        // Cut short anywhere, or filled with noise, it is refused or read
        // without a panic.
        for end in 0..der.len() {
            let _ = certificate_info(&der[..end]);
        }
        let mut noise = der.clone();
        for i in (0..noise.len()).step_by(7) {
            noise[i] ^= 0x5a;
            let _ = certificate_info(&noise);
        }
        assert_eq!(certificate_info(&[]), None);
    }

    #[test]
    fn a_wildcard_covers_one_label() {
        let names = vec!["*.test.example".to_string(), "other.example".to_string()];
        assert!(certificate_covers(&names, "mail.test.example."));
        assert!(certificate_covers(&names, "OTHER.example"));
        assert!(!certificate_covers(&names, "test.example."));
        assert!(!certificate_covers(&names, "a.b.test.example."));
        assert!(!certificate_covers(&names, "another.example."));
        assert!(!certificate_covers(&[], "test.example."));
    }

    #[test]
    fn certificate_times() {
        assert_eq!(certificate_time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(
            certificate_time(0x17, b"231114221320Z"),
            Some(1_700_000_000)
        );
        assert_eq!(
            certificate_time(0x18, b"20231114221320Z"),
            Some(1_700_000_000)
        );
        assert_eq!(certificate_time(0x17, b"2311142213Z"), None);
        assert_eq!(certificate_time(0x17, b"23111422132aZ"), None);
        assert_eq!(certificate_time(0x18, b"20231114221320"), None);
    }

    use std::net::TcpListener;

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

    /// Something with the shape of a certificate around the given key.
    fn certificate(key: &[u8], with_version: bool) -> (Vec<u8>, Vec<u8>) {
        let spki = tlv(0x30, &[tlv(0x30, &[6, 1, 42]), tlv(0x03, key)].concat());
        let mut body = Vec::new();
        if with_version {
            body.extend(tlv(0xa0, &tlv(0x02, &[2])));
        }
        body.extend(tlv(0x02, &[7])); // serial
        body.extend(tlv(0x30, &[6, 1, 42])); // signature algorithm
        body.extend(tlv(0x30, b"issuer"));
        body.extend(tlv(0x30, b"validity"));
        body.extend(tlv(0x30, b"subject"));
        body.extend(&spki);
        body.extend(tlv(0xa3, b"extensions"));
        let cert = tlv(
            0x30,
            &[
                tlv(0x30, &body),
                tlv(0x30, &[6, 1, 42]),
                tlv(0x03, &[0; 300]),
            ]
            .concat(),
        );
        (cert, spki)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_public_key_is_found_in_a_certificate() {
        for with_version in [true, false] {
            let (cert, spki) = certificate(&[1, 2, 3, 4], with_version);
            assert_eq!(public_key_info(&cert), Some(spki.as_slice()));
        }
        assert_eq!(public_key_info(b"not a certificate"), None);
        assert_eq!(public_key_info(&[0x30, 0x82, 0xff, 0xff, 1]), None);
    }

    #[test]
    fn tlsa_records_are_matched_against_the_chain() {
        let (leaf, leaf_key) = certificate(&[1; 40], true);
        let (issuer, issuer_key) = certificate(&[2; 40], true);
        let chain = vec![leaf.clone(), issuer.clone()];
        let sha256 = |d: &[u8]| hex(&Sha256::digest(d));
        let sha512 = |d: &[u8]| hex(&Sha512::digest(d));

        assert_eq!(
            tlsa_matches(&format!("3 1 1 {}", sha256(&leaf_key)), &chain),
            Some(true)
        );
        assert_eq!(
            tlsa_matches(&format!("3 0 1 {}", sha256(&leaf)), &chain),
            Some(true)
        );
        assert_eq!(
            tlsa_matches(&format!("3 1 2 {}", sha512(&leaf_key)), &chain),
            Some(true)
        );
        assert_eq!(
            tlsa_matches(&format!("3 0 0 {}", hex(&leaf)), &chain),
            Some(true)
        );
        // DANE-EE looks at the server's own certificate only.
        assert_eq!(
            tlsa_matches(&format!("3 1 1 {}", sha256(&issuer_key)), &chain),
            Some(false)
        );
        // DANE-TA at any certificate the server sent.
        assert_eq!(
            tlsa_matches(&format!("2 1 1 {}", sha256(&issuer_key)), &chain),
            Some(true)
        );
        assert_eq!(
            tlsa_matches(&format!("2 1 1 {}", sha256(b"other")), &chain),
            Some(false)
        );
        // Usages that need a public authority, and nonsense, are not judged.
        assert_eq!(
            tlsa_matches(&format!("1 1 1 {}", sha256(&leaf_key)), &chain),
            None
        );
        assert_eq!(tlsa_matches("3 1 1 nothex", &chain), None);
        assert_eq!(tlsa_matches("3 9 1 abcd", &chain), None);
        assert_eq!(tlsa_matches("3 1", &chain), None);
    }

    /// A server that speaks the given lines, one reply per line read.
    fn fake_server(script: &'static [&'static str]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            for (i, reply) in script.iter().enumerate() {
                if i > 0 {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                }
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        addr
    }

    #[test]
    fn the_smtp_dialogue_stops_cleanly_when_tls_is_not_on_offer() {
        let addr = fake_server(&[
            "220 mail.example.test ESMTP\r\n",
            "250-mail.example.test\r\n250-SIZE 1000\r\n250 8BITMIME\r\n",
        ]);
        assert_eq!(
            starttls_certificates(addr, "mail.example.test.").unwrap_err(),
            NO_STARTTLS
        );
        let addr = fake_server(&["554 go away\r\n"]);
        assert!(
            starttls_certificates(addr, "x.test.")
                .unwrap_err()
                .contains("554")
        );
        let addr = fake_server(&[
            "220 hi\r\n",
            "250-x\r\n250 STARTTLS\r\n",
            "454 TLS not available\r\n",
        ]);
        assert!(
            starttls_certificates(addr, "x.test.")
                .unwrap_err()
                .contains("454")
        );
        let addr = fake_server(&["HTTP/1.1 200 OK\r\n"]);
        assert!(
            starttls_certificates(addr, "x.test.")
                .unwrap_err()
                .contains("not SMTP")
        );
        // A server that offers STARTTLS but then talks nonsense fails the
        // handshake; it must not hang or panic.
        let addr = fake_server(&[
            "220 hi\r\n",
            "250 STARTTLS\r\n",
            "220 go ahead\r\n",
            "this is not TLS\r\n",
        ]);
        assert!(starttls_certificates(addr, "x.test.").is_err());
    }
}
