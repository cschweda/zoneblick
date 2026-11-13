//! DNSSEC signature verification (RFC 4034, section 3.1.8.1): does an RRSIG
//! record really sign the record set it claims to, with a key the zone
//! publishes?
//!
//! Only the arithmetic is done here. Whether the signature's dates are
//! current is a separate check (`SEC-02`).

use ring::signature;

use crate::dnssec::{Dnskey, key_tag};

/// The outcome of trying the signatures over one record set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// At least one signature verifies with a published key.
    Valid,
    /// Signatures could be tried, and none verifies.
    Invalid,
    /// No signature could be tried: its key is not published, or its
    /// algorithm is not one this program knows.
    Untried,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Valid => "valid",
            Verdict::Invalid => "invalid",
            Verdict::Untried => "untried",
        }
    }
}

/// A name in uncompressed wire form, lower case. `name` is in text form
/// without escapes, as zone names are here.
pub fn name_wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        out.push(label.len() as u8);
        out.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0);
    out
}

/// The length of the uncompressed name at the start of `bytes`.
fn wire_name_len(bytes: &[u8]) -> Option<usize> {
    let mut at = 0;
    loop {
        let len = *bytes.get(at)? as usize;
        at += 1;
        if len == 0 {
            return Some(at);
        }
        if len > 63 {
            return None;
        }
        at += len;
    }
}

/// The parts of an RSA public key in DNSKEY form (RFC 3110): exponent, modulus.
fn rsa_parts(key: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = match *key.first()? {
        0 => (
            u16::from_be_bytes([*key.get(1)?, *key.get(2)?]) as usize,
            key.get(3..)?,
        ),
        n => (n as usize, key.get(1..)?),
    };
    (rest.len() > len).then(|| rest.split_at(len))
}

/// Verify one signature. `None` when the algorithm is not supported.
fn verify_one(algorithm: u8, public_key: &[u8], message: &[u8], sig: &[u8]) -> Option<bool> {
    let rsa = |params: &'static signature::RsaParameters| {
        let Some((e, n)) = rsa_parts(public_key) else {
            return false;
        };
        signature::RsaPublicKeyComponents { n, e }
            .verify(params, message, sig)
            .is_ok()
    };
    let fixed = |alg: &'static dyn signature::VerificationAlgorithm, key: &[u8]| {
        signature::UnparsedPublicKey::new(alg, key)
            .verify(message, sig)
            .is_ok()
    };
    // An ECDSA key in DNSKEY form is the two coordinates; ring wants the
    // "uncompressed point" marker in front.
    let point = || [&[4u8][..], public_key].concat();
    Some(match algorithm {
        5 | 7 => rsa(&signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY),
        8 => rsa(&signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY),
        10 => rsa(&signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY),
        13 => fixed(&signature::ECDSA_P256_SHA256_FIXED, &point()),
        14 => fixed(&signature::ECDSA_P384_SHA384_FIXED, &point()),
        15 => fixed(&signature::ED25519, public_key),
        _ => return None,
    })
}

/// The bytes an RRSIG signs: its own record data up to the signature, then
/// every record of the set in canonical form and order.
pub fn signed_data(
    rrsig: &[u8],
    signer_len: usize,
    owner: &[u8],
    rtype: u16,
    rdatas: &[Vec<u8>],
) -> Vec<u8> {
    let mut data = rrsig[..18].to_vec();
    data.extend(
        rrsig[18..18 + signer_len]
            .iter()
            .map(u8::to_ascii_lowercase),
    );
    let original_ttl = &rrsig[4..8];
    let mut sorted: Vec<&Vec<u8>> = rdatas.iter().collect();
    sorted.sort();
    sorted.dedup();
    for rdata in sorted {
        data.extend_from_slice(owner);
        data.extend_from_slice(&rtype.to_be_bytes());
        data.extend_from_slice(&[0, 1]); // class IN
        data.extend_from_slice(original_ttl);
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(rdata);
    }
    data
}

/// Try every signature over a record set owned by `owner`.
///
/// `rdatas` is the record data of each record in canonical form (names in
/// it uncompressed and lower case). `rrsigs` is the raw record data of the
/// RRSIG records that came with the set; those covering another type are
/// skipped. `keys` is the zone's DNSKEY set.
pub fn verify_rrset(
    owner: &str,
    rtype: u16,
    rdatas: &[Vec<u8>],
    rrsigs: &[&[u8]],
    keys: &[Dnskey],
) -> Verdict {
    let owner_wire = name_wire(owner);
    let mut tried = false;
    for rrsig in rrsigs {
        if rrsig.len() < 19 || u16::from_be_bytes([rrsig[0], rrsig[1]]) != rtype {
            continue;
        }
        let Some(signer_len) = wire_name_len(&rrsig[18..]) else {
            continue;
        };
        let (algorithm, tag) = (rrsig[2], u16::from_be_bytes([rrsig[16], rrsig[17]]));
        let sig = &rrsig[18 + signer_len..];
        let message = signed_data(rrsig, signer_len, &owner_wire, rtype, rdatas);
        for key in keys
            .iter()
            .filter(|k| k.algorithm == algorithm && k.key_tag == tag)
        {
            let Some(raw) = crate::dnssec::unhex(&key.rdata).filter(|r| r.len() > 4) else {
                continue;
            };
            debug_assert_eq!(key_tag(&raw), key.key_tag);
            match verify_one(algorithm, &raw[4..], &message, sig) {
                Some(true) => return Verdict::Valid,
                Some(false) => tried = true,
                None => {}
            }
        }
    }
    if tried {
        Verdict::Invalid
    } else {
        Verdict::Untried
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::{hex, parse_dnskey};
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};

    const ZONE: &str = "Example.Test.";
    const DNSKEY: u16 = 48;

    /// A DNSKEY record's data for a raw public key.
    fn dnskey_rdata(algorithm: u8, public_key: &[u8]) -> Vec<u8> {
        [&[1, 1, 3, algorithm][..], public_key].concat()
    }

    /// An RRSIG record's data, with the signature made by `sign`.
    fn rrsig(
        rtype: u16,
        algorithm: u8,
        key: &Dnskey,
        rdatas: &[Vec<u8>],
        sign: impl Fn(&[u8]) -> Vec<u8>,
    ) -> Vec<u8> {
        let mut head = Vec::new();
        head.extend_from_slice(&rtype.to_be_bytes());
        head.extend_from_slice(&[algorithm, 2]);
        head.extend_from_slice(&3600u32.to_be_bytes());
        head.extend_from_slice(&2_000_000_000u32.to_be_bytes());
        head.extend_from_slice(&1_000_000_000u32.to_be_bytes());
        head.extend_from_slice(&key.key_tag.to_be_bytes());
        let signer = name_wire(ZONE);
        head.extend_from_slice(&signer);
        let message = signed_data(&head, signer.len(), &name_wire(ZONE), rtype, rdatas);
        [head, sign(&message)].concat()
    }

    #[test]
    fn ed25519_and_ecdsa_signatures_verify() {
        let rng = SystemRandom::new();
        let ed = Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref())
            .unwrap();
        let ec_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let ec = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, ec_doc.as_ref(), &rng)
            .unwrap();

        let ed_rdata = dnskey_rdata(15, ed.public_key().as_ref());
        // Drop the "uncompressed point" marker: DNSKEY holds the coordinates only.
        let ec_rdata = dnskey_rdata(13, &ec.public_key().as_ref()[1..]);
        let keys = vec![
            parse_dnskey(&ed_rdata).unwrap(),
            parse_dnskey(&ec_rdata).unwrap(),
        ];
        let set = vec![ed_rdata.clone(), ec_rdata.clone()];

        let by_ed = rrsig(DNSKEY, 15, &keys[0], &set, |m| ed.sign(m).as_ref().to_vec());
        let by_ec = rrsig(DNSKEY, 13, &keys[1], &set, |m| {
            ec.sign(&rng, m).unwrap().as_ref().to_vec()
        });
        for sig in [&by_ed, &by_ec] {
            assert_eq!(
                verify_rrset(ZONE, DNSKEY, &set, &[sig], &keys),
                Verdict::Valid
            );
        }
        // The set is signed in canonical order, whatever order it arrives in.
        let reversed: Vec<Vec<u8>> = set.iter().rev().cloned().collect();
        assert_eq!(
            verify_rrset(ZONE, DNSKEY, &reversed, &[&by_ed], &keys),
            Verdict::Valid
        );

        // One flipped bit in the signature, or one in the data: invalid.
        let mut broken = by_ed.clone();
        *broken.last_mut().unwrap() ^= 1;
        assert_eq!(
            verify_rrset(ZONE, DNSKEY, &set, &[&broken], &keys),
            Verdict::Invalid
        );
        let mut other = set.clone();
        other[0][0] ^= 0x80;
        assert_eq!(
            verify_rrset(ZONE, DNSKEY, &other, &[&by_ec], &keys),
            Verdict::Invalid
        );
        // A good signature next to a bad one is enough.
        assert_eq!(
            verify_rrset(ZONE, DNSKEY, &set, &[&broken, &by_ec], &keys),
            Verdict::Valid
        );

        // Nothing to try: no signature for this type, or no such key.
        assert_eq!(
            verify_rrset(ZONE, 6, &set, &[&by_ed], &keys),
            Verdict::Untried
        );
        assert_eq!(
            verify_rrset(ZONE, DNSKEY, &set, &[&by_ed], &keys[1..]),
            Verdict::Untried
        );
        assert_eq!(
            verify_rrset(ZONE, DNSKEY, &set, &[], &keys),
            Verdict::Untried
        );
        assert_eq!(
            hex(&name_wire("Www.Example.")),
            "03777777076578616d706c6500"
        );
    }

    #[test]
    fn rsa_keys_are_split_into_exponent_and_modulus() {
        assert_eq!(rsa_parts(&[1, 3, 9, 9]), Some((&[3u8][..], &[9u8, 9][..])));
        assert_eq!(
            rsa_parts(&[0, 0, 2, 1, 0, 7]),
            Some((&[1u8, 0][..], &[7u8][..]))
        );
        assert_eq!(rsa_parts(&[3, 1, 0, 1]), None);
        assert_eq!(rsa_parts(&[]), None);
    }

    #[test]
    fn ecdsa_p384_signatures_verify() {
        use ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING;
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
        let ec =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, doc.as_ref(), &rng).unwrap();
        let rdata = dnskey_rdata(14, &ec.public_key().as_ref()[1..]);
        let keys = vec![parse_dnskey(&rdata).unwrap()];
        let set = vec![rdata];
        let sig = rrsig(DNSKEY, 14, &keys[0], &set, |m| {
            ec.sign(&rng, m).unwrap().as_ref().to_vec()
        });
        assert_eq!(
            verify_rrset(ZONE, DNSKEY, &set, &[&sig], &keys),
            Verdict::Valid
        );
        let mut broken = sig.clone();
        *broken.last_mut().unwrap() ^= 1;
        assert_eq!(
            verify_rrset(ZONE, DNSKEY, &set, &[&broken], &keys),
            Verdict::Invalid
        );
        // An algorithm this program does not know is left untried.
        let mut unknown = keys.clone();
        unknown[0].algorithm = 16;
        let mut sig16 = sig.clone();
        sig16[2] = 16;
        assert_eq!(
            verify_rrset(ZONE, DNSKEY, &set, &[&sig16], &unknown),
            Verdict::Untried
        );
    }
}
