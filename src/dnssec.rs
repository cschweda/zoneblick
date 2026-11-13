//! DNSSEC record parsing and the arithmetic the SEC checks need.
//!
//! Pure functions; no I/O and no signature validation. `hickory-proto` is
//! built without its DNSSEC feature, so DS, DNSKEY and RRSIG records arrive
//! as raw bytes and are parsed here (RFC 4034).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};

/// A DS record: the parent's pointer to a key in the child zone.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ds {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    /// The digest, in lowercase hex.
    pub digest: String,
}

/// A DNSKEY record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Dnskey {
    /// Computed from the record data (RFC 4034, appendix B).
    pub key_tag: u16,
    pub flags: u16,
    pub algorithm: u8,
    /// The whole record data in lowercase hex; DS digests are computed over it.
    pub rdata: String,
}

impl Dnskey {
    /// A key-signing key has the SEP bit set (flags 257).
    pub fn is_ksk(&self) -> bool {
        self.flags & 1 == 1
    }
}

/// The parts of an RRSIG record the checks use.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Rrsig {
    /// The record type the signature covers, for example `SOA`.
    pub type_covered: String,
    pub algorithm: u8,
    pub key_tag: u16,
    /// Signature expiry, seconds since the Unix epoch.
    pub expiration: u32,
    /// Signature start, seconds since the Unix epoch.
    pub inception: u32,
    pub signer: String,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

pub fn parse_ds(rdata: &[u8]) -> Option<Ds> {
    if rdata.len() < 5 {
        return None;
    }
    Some(Ds {
        key_tag: u16::from_be_bytes([rdata[0], rdata[1]]),
        algorithm: rdata[2],
        digest_type: rdata[3],
        digest: hex(&rdata[4..]),
    })
}

pub fn parse_dnskey(rdata: &[u8]) -> Option<Dnskey> {
    if rdata.len() < 5 {
        return None;
    }
    Some(Dnskey {
        key_tag: key_tag(rdata),
        flags: u16::from_be_bytes([rdata[0], rdata[1]]),
        algorithm: rdata[3],
        rdata: hex(rdata),
    })
}

pub fn parse_rrsig(rdata: &[u8]) -> Option<Rrsig> {
    if rdata.len() < 19 {
        return None;
    }
    let u32_at =
        |i: usize| u32::from_be_bytes([rdata[i], rdata[i + 1], rdata[i + 2], rdata[i + 3]]);
    // The signer name is never compressed (RFC 4034, section 3.1.7).
    let mut signer = String::new();
    let mut i = 18;
    loop {
        let len = *rdata.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        let label = rdata.get(i..i + len)?;
        for b in label {
            let c = b.to_ascii_lowercase() as char;
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                signer.push(c);
            } else {
                signer.push_str(&format!("\\{b:03}"));
            }
        }
        signer.push('.');
        i += len;
    }
    if signer.is_empty() {
        signer.push('.');
    }
    Some(Rrsig {
        type_covered: type_name(u16::from_be_bytes([rdata[0], rdata[1]])),
        algorithm: rdata[2],
        expiration: u32_at(8),
        inception: u32_at(12),
        key_tag: u16::from_be_bytes([rdata[16], rdata[17]]),
        signer,
    })
}

/// The key tag of a DNSKEY, from its record data (RFC 4034, appendix B).
pub fn key_tag(rdata: &[u8]) -> u16 {
    // Algorithm 1 (RSA/MD5) uses a different rule: part of the modulus.
    if rdata.get(3) == Some(&1) && rdata.len() >= 7 {
        let n = rdata.len();
        return u16::from_be_bytes([rdata[n - 3], rdata[n - 2]]);
    }
    let mut acc: u32 = 0;
    for (i, b) in rdata.iter().enumerate() {
        acc += if i % 2 == 0 {
            u32::from(*b) << 8
        } else {
            u32::from(*b)
        };
    }
    acc += (acc >> 16) & 0xffff;
    (acc & 0xffff) as u16
}

/// The wire form of a name in canonical (lowercase) form.
fn name_wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend(label.to_ascii_lowercase().bytes());
    }
    out.push(0);
    out
}

/// The digest a DS record for this key must carry, in lowercase hex.
/// `None` when the digest type cannot be computed here (SHA-1 and GOST).
pub fn ds_digest(owner: &str, dnskey_rdata: &[u8], digest_type: u8) -> Option<String> {
    let mut data = name_wire(owner);
    data.extend_from_slice(dnskey_rdata);
    match digest_type {
        2 => Some(hex(&Sha256::digest(&data))),
        4 => Some(hex(&Sha384::digest(&data))),
        _ => None,
    }
}

/// Does this DS record point at this key? Key tag and algorithm must agree,
/// and so must the digest when it can be computed.
pub fn ds_matches(owner: &str, ds: &Ds, key: &Dnskey) -> bool {
    if ds.key_tag != key.key_tag || ds.algorithm != key.algorithm {
        return false;
    }
    let Some(rdata) = unhex(&key.rdata) else {
        return false;
    };
    match ds_digest(owner, &rdata, ds.digest_type) {
        Some(digest) => digest == ds.digest,
        None => true,
    }
}

/// The name of a signing algorithm (IANA DNSSEC algorithm numbers).
pub fn algorithm_name(algorithm: u8) -> String {
    match algorithm {
        1 => "RSAMD5".to_string(),
        3 => "DSA".to_string(),
        5 => "RSASHA1".to_string(),
        6 => "DSA-NSEC3-SHA1".to_string(),
        7 => "RSASHA1-NSEC3-SHA1".to_string(),
        8 => "RSASHA256".to_string(),
        10 => "RSASHA512".to_string(),
        12 => "ECC-GOST".to_string(),
        13 => "ECDSAP256SHA256".to_string(),
        14 => "ECDSAP384SHA384".to_string(),
        15 => "ED25519".to_string(),
        16 => "ED448".to_string(),
        n => format!("algorithm {n}"),
    }
}

/// The name of a DS digest type.
pub fn digest_name(digest_type: u8) -> String {
    match digest_type {
        1 => "SHA-1".to_string(),
        2 => "SHA-256".to_string(),
        3 => "GOST".to_string(),
        4 => "SHA-384".to_string(),
        n => format!("digest type {n}"),
    }
}

/// Algorithms that must not be used for signing any more (RFC 8624).
pub fn is_weak_algorithm(algorithm: u8) -> bool {
    matches!(algorithm, 1 | 3 | 5 | 6 | 7 | 12)
}

/// Digest types that must not be used for DS records any more (RFC 8624).
pub fn is_weak_digest(digest_type: u8) -> bool {
    matches!(digest_type, 1 | 3)
}

fn type_name(code: u16) -> String {
    match code {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        43 => "DS".to_string(),
        47 => "NSEC".to_string(),
        50 => "NSEC3".to_string(),
        48 => "DNSKEY".to_string(),
        257 => "CAA".to_string(),
        n => format!("TYPE{n}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DNSKEY record data: flags 257, protocol 3, algorithm 13, 64 key bytes.
    pub(crate) fn sample_key(seed: u8) -> Vec<u8> {
        let mut rdata = vec![0x01, 0x01, 3, 13];
        rdata.extend((0..64u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)));
        rdata
    }

    #[test]
    fn key_tag_matches_the_rfc_algorithm() {
        // RFC 4034 appendix B, written out the slow way.
        let rdata = sample_key(1);
        let mut acc: u32 = 0;
        for (i, b) in rdata.iter().enumerate() {
            acc += if i & 1 == 1 {
                *b as u32
            } else {
                (*b as u32) << 8
            };
        }
        acc += (acc >> 16) & 0xffff;
        assert_eq!(key_tag(&rdata), (acc & 0xffff) as u16);
        assert_ne!(key_tag(&sample_key(1)), key_tag(&sample_key(2)));
    }

    #[test]
    fn parses_ds_and_dnskey() {
        let ds = parse_ds(&[0x4f, 0x66, 13, 2, 0xab, 0xcd]).unwrap();
        assert_eq!((ds.key_tag, ds.algorithm, ds.digest_type), (20326, 13, 2));
        assert_eq!(ds.digest, "abcd");
        assert!(parse_ds(&[1, 2]).is_none());

        let key = parse_dnskey(&sample_key(1)).unwrap();
        assert_eq!((key.flags, key.algorithm), (257, 13));
        assert!(key.is_ksk());
        assert_eq!(key.key_tag, key_tag(&sample_key(1)));
    }

    #[test]
    fn parses_rrsig() {
        let mut rdata = vec![0, 6, 13, 2];
        rdata.extend(3600u32.to_be_bytes());
        rdata.extend(1_700_600_000u32.to_be_bytes());
        rdata.extend(1_700_000_000u32.to_be_bytes());
        rdata.extend(4242u16.to_be_bytes());
        rdata.extend(b"\x07Example\x03COM\x00");
        rdata.extend([9u8; 64]);
        let sig = parse_rrsig(&rdata).unwrap();
        assert_eq!(sig.type_covered, "SOA");
        assert_eq!((sig.algorithm, sig.key_tag), (13, 4242));
        assert_eq!(
            (sig.expiration, sig.inception),
            (1_700_600_000, 1_700_000_000)
        );
        assert_eq!(sig.signer, "example.com.");
        assert!(parse_rrsig(&rdata[..10]).is_none());
    }

    #[test]
    fn ds_digest_covers_owner_and_key() {
        let rdata = sample_key(1);
        let digest = ds_digest("Example.COM.", &rdata, 2).unwrap();
        assert_eq!(digest.len(), 64);
        // The owner name is part of the digest, case-insensitively.
        assert_eq!(digest, ds_digest("example.com.", &rdata, 2).unwrap());
        assert_ne!(digest, ds_digest("example.org.", &rdata, 2).unwrap());
        assert_eq!(ds_digest("example.com.", &rdata, 4).unwrap().len(), 96);
        assert!(ds_digest("example.com.", &rdata, 1).is_none());

        let key = parse_dnskey(&rdata).unwrap();
        let ds = Ds {
            key_tag: key.key_tag,
            algorithm: 13,
            digest_type: 2,
            digest,
        };
        assert!(ds_matches("example.com.", &ds, &key));
        assert!(!ds_matches("example.org.", &ds, &key));
        let other = parse_dnskey(&sample_key(2)).unwrap();
        assert!(!ds_matches("example.com.", &ds, &other));
        // A SHA-1 DS can only be matched on key tag and algorithm.
        let sha1 = Ds {
            digest_type: 1,
            digest: "00".to_string(),
            ..ds
        };
        assert!(ds_matches("example.com.", &sha1, &key));
    }

    #[test]
    fn weak_choices() {
        assert!(is_weak_algorithm(5) && is_weak_algorithm(7) && is_weak_algorithm(1));
        assert!(!is_weak_algorithm(8) && !is_weak_algorithm(13) && !is_weak_algorithm(15));
        assert!(is_weak_digest(1) && !is_weak_digest(2) && !is_weak_digest(4));
    }
}
