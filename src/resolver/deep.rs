//! The deep probes: a few unusual queries per nameserver, one zone-transfer
//! attempt, and lookups for the names in the SOA record. Nothing is judged
//! here; the deep checks read the result.

use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use tokio::task::JoinSet;

use super::iterate::{Resolver, norm, printable, rcode_name};
use super::probe::responding_servers;
use super::signed::{ask_signed, is_authoritative_answer, raw_rdata};
use super::transport::{Client, QuerySpec, RawOutcome, mixed_case};
use crate::dnssec::{hex, parse_dnskey, parse_ds};
use crate::observe::{
    AddressOrigin, DeepObservation, Denial, Nsec3Param, Probe, ProbeAnswer, QType, ServerDeep,
    Transport, ZoneObservation,
};

/// Send one probe query for the zone's SOA and return the raw answer.
async fn probe(
    client: &Client,
    server: IpAddr,
    zone: &str,
    probe: Probe,
) -> Result<Vec<u8>, String> {
    let spec = QuerySpec {
        server,
        transport: Transport::Udp,
        qname: zone.to_string(),
        qtype: QType::Soa,
        edns: true,
        dnssec: false,
        probe,
    };
    match client.exchange(&spec).await {
        RawOutcome::Response { wire } => Ok(wire),
        RawOutcome::Timeout => Err("timeout".to_string()),
        RawOutcome::NetError { message } => Err(message),
    }
}

fn answer(raw: Result<Vec<u8>, String>) -> ProbeAnswer {
    match raw.and_then(|wire| Message::from_vec(&wire).map_err(|e| printable(&e.to_string()))) {
        Ok(msg) => ProbeAnswer {
            rcode: Some(rcode_name(msg.metadata.response_code)),
            opt_present: msg.edns.is_some(),
            error: None,
        },
        Err(error) => ProbeAnswer {
            rcode: None,
            opt_present: false,
            error: Some(error),
        },
    }
}

/// The name in the question section of a message, exactly as written.
pub(crate) fn question_name(wire: &[u8]) -> Option<String> {
    let mut at = 12;
    let mut out = String::new();
    loop {
        let len = *wire.get(at)? as usize;
        if len == 0 {
            break;
        }
        // A compression pointer has no place in a question.
        if len > 63 {
            return None;
        }
        let label = wire.get(at + 1..at + 1 + len)?;
        out.push_str(&String::from_utf8_lossy(label));
        out.push('.');
        at += 1 + len;
    }
    if out.is_empty() {
        out.push('.');
    }
    Some(out)
}

fn parse_nsec3param(rdata: &[u8]) -> Option<Nsec3Param> {
    let salt_len = *rdata.get(4)? as usize;
    Some(Nsec3Param {
        algorithm: rdata[0],
        iterations: u16::from_be_bytes([rdata[2], rdata[3]]),
        salt: hex(rdata.get(5..5 + salt_len)?),
    })
}

/// The records of one type at the apex, when the server answers with
/// authority. An empty list means it has none.
async fn apex_records<T: Ord>(
    client: &Client,
    server: IpAddr,
    zone: &str,
    qtype: QType,
    rtype: RecordType,
    parse: impl Fn(&[u8]) -> Option<T>,
) -> Option<Vec<T>> {
    let msg = ask_signed(client, server, zone, qtype).await.ok()?;
    if !is_authoritative_answer(&msg) {
        return None;
    }
    let mut out: Vec<T> = raw_rdata(&msg, zone, rtype)
        .into_iter()
        .filter_map(parse)
        .collect();
    out.sort();
    Some(out)
}

async fn probe_server(
    client: Arc<Client>,
    zone: String,
    ns_name: String,
    address: IpAddr,
) -> ServerDeep {
    let edns_version = answer(probe(&client, address, &zone, Probe::EdnsVersion1).await);
    let edns_option = answer(probe(&client, address, &zone, Probe::EdnsUnknownOption).await);
    let recursion_available = probe(&client, address, &zone, Probe::Recursion)
        .await
        .ok()
        .and_then(|wire| Message::from_vec(&wire).ok())
        .map(|msg| msg.metadata.recursion_available);
    let sent = mixed_case(&zone);
    let case_preserved = if sent == zone {
        // No letters to change the case of.
        None
    } else {
        probe(&client, address, &zone, Probe::MixedCase)
            .await
            .ok()
            .and_then(|wire| question_name(&wire))
            .map(|name| name == sent)
    };
    // One transfer attempt; only whether it was allowed is kept.
    let axfr_allowed = if client.is_live() {
        Some(crate::discover::axfr_allowed(&zone, address).await)
    } else {
        None
    };
    let nsec3param = apex_records(
        &client,
        address,
        &zone,
        QType::Nsec3param,
        RecordType::NSEC3PARAM,
        parse_nsec3param,
    )
    .await;
    let cds = apex_records(
        &client,
        address,
        &zone,
        QType::Cds,
        RecordType::CDS,
        parse_ds,
    )
    .await;
    let cdnskey = apex_records(
        &client,
        address,
        &zone,
        QType::Cdnskey,
        RecordType::CDNSKEY,
        parse_dnskey,
    )
    .await;
    let denial = probe_denial(&client, address, &zone).await;
    ServerDeep {
        ns_name,
        address,
        edns_version,
        edns_option,
        recursion_available,
        case_preserved,
        axfr_allowed,
        nsec3param,
        cds,
        cdnskey,
        denial,
    }
}

/// An NSEC3 record: the hash it is at, the next hash, and how names are
/// hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Nsec3 {
    pub hash: Vec<u8>,
    pub next: Vec<u8>,
    pub algorithm: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
}

/// Decode base32 with the "extended hex" alphabet (RFC 4648), unpadded.
fn base32hex(text: &str) -> Option<Vec<u8>> {
    let (mut bits, mut have, mut out) = (0u32, 0, Vec::new());
    for c in text.bytes() {
        let v = match c.to_ascii_lowercase() {
            d @ b'0'..=b'9' => d - b'0',
            l @ b'a'..=b'v' => l - b'a' + 10,
            _ => return None,
        };
        bits = (bits << 5) | u32::from(v);
        have += 5;
        if have >= 8 {
            have -= 8;
            out.push((bits >> have) as u8);
            bits &= (1 << have) - 1;
        }
    }
    Some(out)
}

fn parse_nsec3(owner: &str, rdata: &[u8]) -> Option<Nsec3> {
    let salt_len = *rdata.get(4)? as usize;
    let salt = rdata.get(5..5 + salt_len)?.to_vec();
    let hash_len = *rdata.get(5 + salt_len)? as usize;
    let next = rdata.get(6 + salt_len..6 + salt_len + hash_len)?.to_vec();
    Some(Nsec3 {
        hash: base32hex(owner.split('.').next()?)?,
        next,
        algorithm: rdata[0],
        iterations: u16::from_be_bytes([rdata[2], rdata[3]]),
        salt,
    })
}

/// The NSEC3 hash of a name (RFC 5155, section 5): SHA-1 over the name in
/// wire form and the salt, repeated.
pub(crate) fn nsec3_hash(name: &str, salt: &[u8], iterations: u16) -> Vec<u8> {
    let sha1 = |data: &[u8]| {
        ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data)
            .as_ref()
            .to_vec()
    };
    let mut hash = sha1(&[&crate::verify::name_wire(name)[..], salt].concat());
    for _ in 0..iterations {
        hash = sha1(&[&hash[..], salt].concat());
    }
    hash
}

/// Whether NSEC3 records prove that `qname`, one label below the apex of
/// `zone`, does not exist: one record is at the apex (the closest name that
/// does exist), one covers the name, and one covers the wildcard that could
/// have answered instead. A record at the name itself also counts: some
/// servers answer "the name exists, but has no such record".
pub(crate) fn nsec3_proves_absence(records: &[Nsec3], zone: &str, qname: &str) -> Option<bool> {
    let first = records.first()?;
    // Only SHA-1 is defined. Refuse absurd iteration counts.
    if first.algorithm != 1 || first.iterations > 2500 {
        return None;
    }
    let hash = |name: &str| nsec3_hash(name, &first.salt, first.iterations);
    let matches = |h: &[u8]| records.iter().any(|r| r.hash == h);
    let covers = |h: &[u8]| {
        records.iter().any(|r| {
            if r.hash < r.next {
                r.hash.as_slice() < h && h < r.next.as_slice()
            } else {
                h > r.hash.as_slice() || h < r.next.as_slice()
            }
        })
    };
    let name_hash = hash(qname);
    if matches(&name_hash) {
        return Some(true);
    }
    let wildcard = hash(&format!("*.{zone}"));
    Some(matches(&hash(zone)) && covers(&name_hash) && (covers(&wildcard) || matches(&wildcard)))
}

/// A label nobody would create, for asking about a name that is not there.
pub const ABSENT_LABEL: &str = "zz--zoneblick-absent";

/// A name in uncompressed wire form, as text. Returns it with the number of
/// bytes read.
fn wire_name(bytes: &[u8]) -> Option<(String, usize)> {
    let mut at = 0;
    let mut out = String::new();
    loop {
        let len = *bytes.get(at)? as usize;
        at += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        let label = bytes.get(at..at + len)?;
        // Anything but plain hostname characters is written as \DDD, so
        // no control character reaches a terminal or a report.
        for b in label {
            let c = b.to_ascii_lowercase() as char;
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                out.push(c);
            } else {
                out.push_str(&format!("\\{b:03}"));
            }
        }
        out.push('.');
        at += len;
    }
    if out.is_empty() {
        out.push('.');
    }
    Some((out, at))
}

/// Ask for a name that should not exist, with the DO bit, and note the
/// proof that comes back.
async fn probe_denial(client: &Client, server: IpAddr, zone: &str) -> Option<Denial> {
    if zone == "." {
        return None;
    }
    let qname = format!("{ABSENT_LABEL}.{zone}");
    let msg = ask_signed(client, server, &qname, QType::A).await.ok()?;
    if !msg.metadata.authoritative {
        return None;
    }
    let raw = |rtype: RecordType| {
        msg.authorities
            .iter()
            .filter(move |rec| rec.record_type() == rtype)
            .filter_map(|rec| match &rec.data {
                RData::Unknown { rdata, .. } => Some((norm(&rec.name), rdata.anything.as_slice())),
                _ => None,
            })
    };
    let mut nsec: Vec<(String, String)> = raw(RecordType::NSEC)
        .filter_map(|(owner, rdata)| Some((owner, wire_name(rdata)?.0)))
        .collect();
    nsec.sort();
    let signed = raw(RecordType::RRSIG)
        .filter_map(|(_, rdata)| crate::dnssec::parse_rrsig(rdata))
        .any(|sig| matches!(sig.type_covered.as_str(), "NSEC" | "NSEC3"));
    let nsec3: Vec<Nsec3> = raw(RecordType::NSEC3)
        .filter_map(|(owner, rdata)| parse_nsec3(&owner, rdata))
        .collect();
    let nsec3_proof = nsec3_proves_absence(&nsec3, zone, &qname);
    Some(Denial {
        nsec3_proof,
        qname,
        rcode: rcode_name(msg.metadata.response_code),
        answered: !msg.answers.is_empty(),
        nsec,
        nsec3: nsec3.len(),
        signed,
    })
}

/// Split an SOA contact into mailbox and mail domain: the first label is
/// the mailbox, and a dot inside it is written `\.`.
pub(crate) fn rname_domain(rname: &str) -> Option<String> {
    let bytes = rname.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'.' => {
                let domain = &rname[i + 1..];
                return (!domain.is_empty()).then(|| domain.to_string());
            }
            _ => i += 1,
        }
    }
    None
}

/// The name to ask Team Cymru's IP-to-ASN service about an address.
pub fn origin_query_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let nibbles: Vec<String> = a
                .octets()
                .iter()
                .rev()
                .flat_map(|b| [b & 0x0f, b >> 4])
                .map(|n| format!("{n:x}"))
                .collect();
            format!("{}.origin6.asn.cymru.com.", nibbles.join("."))
        }
    }
}

/// Read an answer such as `"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"`.
pub(crate) fn parse_origin(txt: &str) -> (Vec<u32>, Option<String>) {
    let mut fields = txt.split('|').map(str::trim);
    let asns = fields
        .next()
        .unwrap_or("")
        .split_whitespace()
        .filter_map(|n| n.parse().ok())
        .collect();
    let prefix = fields
        .next()
        .filter(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_hexdigit() || ".:/".contains(c))
        })
        .map(str::to_string);
    (asns, prefix)
}

/// Run the deep probes for an observed zone and attach the result.
pub async fn add_deep(client: Arc<Client>, obs: &mut ZoneObservation) {
    let mut tasks = JoinSet::new();
    for (ns_name, address) in responding_servers(&obs.probes) {
        tasks.spawn(probe_server(
            client.clone(),
            obs.zone.clone(),
            ns_name,
            address,
        ));
    }
    let mut servers = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        servers.push(joined.expect("deep probe task does not panic"));
    }
    servers.sort_by(|a, b| (&a.ns_name, a.address).cmp(&(&b.ns_name, b.address)));

    let soa = obs
        .probes
        .iter()
        .filter_map(|p| p.outcome.response())
        .filter(|r| r.is_authoritative_answer())
        .find_map(|r| r.soa.clone());
    let resolver = Resolver::new(client.clone(), obs.vantage);
    // Which network announces each nameserver address, from Team Cymru.
    let addresses: std::collections::BTreeSet<IpAddr> =
        obs.ns_hosts.iter().flat_map(|h| h.addresses()).collect();
    let mut origins = Vec::new();
    for address in addresses {
        let lookup = resolver
            .lookup(&origin_query_name(address), QType::Txt)
            .await;
        let (asns, prefix) = lookup
            .rdata
            .first()
            .map(|r| parse_origin(&super::policy::txt_value(r)))
            .unwrap_or_default();
        origins.push(AddressOrigin {
            address,
            asns,
            prefix,
        });
    }
    let mut deep = DeepObservation {
        servers,
        mname: None,
        rname_domain: None,
        rname_mx: None,
        rname_address: None,
        previous_dnskeys: None,
        origins,
        registration: None,
    };
    if let Some(soa) = soa {
        let mut lookup = resolver.lookup(&soa.mname, QType::A).await;
        if lookup.status == "nodata" {
            let v6 = resolver.lookup(&soa.mname, QType::Aaaa).await;
            if v6.status == "answer" {
                lookup = v6;
            }
        }
        deep.mname = Some(lookup);
        if let Some(domain) = rname_domain(&soa.rname) {
            let mx = resolver.lookup(&domain, QType::Mx).await;
            if mx.status == "nodata" {
                deep.rname_address = Some(resolver.lookup(&domain, QType::A).await);
            }
            deep.rname_mx = Some(mx);
            deep.rname_domain = Some(domain);
        }
    }
    deep.registration = crate::registration::collect(&client, obs).await;
    obs.deep = Some(deep);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_soa_contact_is_split_at_the_first_plain_dot() {
        assert_eq!(
            rname_domain("hostmaster.example.org.").as_deref(),
            Some("example.org.")
        );
        assert_eq!(
            rname_domain(r"john\.doe.example.org.").as_deref(),
            Some("example.org.")
        );
        assert_eq!(rname_domain("."), None);
        assert_eq!(rname_domain("nodots"), None);
    }

    #[test]
    fn nsec3param_is_read() {
        let p = parse_nsec3param(&[1, 0, 0, 10, 2, 0xab, 0xcd]).unwrap();
        assert_eq!(
            (p.algorithm, p.iterations, p.salt.as_str()),
            (1, 10, "abcd")
        );
        let p = parse_nsec3param(&[1, 0, 0, 0, 0]).unwrap();
        assert_eq!((p.iterations, p.salt.as_str()), (0, ""));
        assert!(parse_nsec3param(&[1, 0, 0]).is_none());
    }

    #[test]
    fn the_question_name_keeps_its_case() {
        let mut wire = vec![0u8; 12];
        wire.extend_from_slice(&[3, b'W', b'w', b'W', 2, b'o', b'R', 0, 0, 6, 0, 1]);
        assert_eq!(question_name(&wire).as_deref(), Some("WwW.oR."));
        assert_eq!(question_name(&[0u8; 13]).as_deref(), Some("."));
        assert_eq!(question_name(&[0u8; 5]), None);
    }

    #[test]
    fn names_in_record_data_are_read_and_escaped() {
        let bytes = [1, 0, 3, b'W', b'w', b'w', 2, b'o', b'r', 0, 9, 9];
        assert_eq!(wire_name(&bytes), Some((r"\000.www.or.".to_string(), 10)));
        assert_eq!(wire_name(&[0]), Some((".".to_string(), 1)));
        assert_eq!(wire_name(&[5, b'a']), None);
    }

    #[test]
    fn network_origin_names_and_answers() {
        assert_eq!(
            origin_query_name("8.8.4.1".parse().unwrap()),
            "1.4.8.8.origin.asn.cymru.com."
        );
        assert_eq!(
            origin_query_name("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com."
        );
        assert_eq!(
            parse_origin("15169 | 8.8.8.0/24 | US | arin | 1992-12-01"),
            (vec![15169], Some("8.8.8.0/24".to_string()))
        );
        assert_eq!(
            parse_origin("64496 64497 | 2001:db8::/32 | ZZ"),
            (vec![64496, 64497], Some("2001:db8::/32".to_string()))
        );
        assert_eq!(parse_origin("nonsense"), (vec![], None));
        assert_eq!(parse_origin("1 | <script>"), (vec![1], None));
    }

    fn b32(hash: &[u8]) -> String {
        // The inverse of `base32hex`, for writing test records.
        let alphabet = b"0123456789abcdefghijklmnopqrstuv";
        let (mut bits, mut have, mut out) = (0u32, 0, String::new());
        for b in hash {
            bits = (bits << 8) | u32::from(*b);
            have += 8;
            while have >= 5 {
                have -= 5;
                out.push(alphabet[((bits >> have) & 31) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn nsec3_hashes_match_the_rfc() {
        // RFC 5155, appendix A: zone "example", salt aabbccdd, 12 iterations.
        let salt = [0xaa, 0xbb, 0xcc, 0xdd];
        for (name, expected) in [
            ("example.", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
            ("a.example.", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
            ("*.w.example.", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"),
        ] {
            let hash = nsec3_hash(name, &salt, 12);
            assert_eq!(b32(&hash), expected, "{name}");
            assert_eq!(base32hex(expected).unwrap(), hash);
        }
        assert_eq!(base32hex("not base32!"), None);
    }

    #[test]
    fn an_nsec3_proof_needs_the_apex_the_name_and_the_wildcard() {
        let (zone, qname) = ("example.test.", "zz--zoneblick-absent.example.test.");
        let hash = |name: &str| nsec3_hash(name, &[], 0);
        let record = |hash: Vec<u8>, next: Vec<u8>| Nsec3 {
            hash,
            next,
            algorithm: 1,
            iterations: 0,
            salt: vec![],
        };
        // A record just before a hash and ending just after it covers it.
        let around = |h: &[u8]| {
            let (mut before, mut after) = (h.to_vec(), h.to_vec());
            *before.last_mut().unwrap() = before.last().unwrap().wrapping_sub(1);
            *after.last_mut().unwrap() = after.last().unwrap().wrapping_add(1);
            record(before, after)
        };
        let apex = record(hash(zone), vec![0xff; 20]);
        let name = around(&hash(qname));
        let wildcard = around(&hash("*.example.test."));

        let full = [apex.clone(), name.clone(), wildcard.clone()];
        assert_eq!(nsec3_proves_absence(&full, zone, qname), Some(true));
        // Any one part missing, and it is no proof.
        assert_eq!(
            nsec3_proves_absence(&[name.clone(), wildcard.clone()], zone, qname),
            Some(false)
        );
        assert_eq!(
            nsec3_proves_absence(&[apex.clone(), wildcard], zone, qname),
            Some(false)
        );
        assert_eq!(
            nsec3_proves_absence(&[apex.clone(), name], zone, qname),
            Some(false)
        );
        // A record at the name itself is the "no such record" form.
        let at_name = record(hash(qname), vec![0; 20]);
        assert_eq!(nsec3_proves_absence(&[at_name], zone, qname), Some(true));
        // Nothing to judge, or a hash this program does not know.
        assert_eq!(nsec3_proves_absence(&[], zone, qname), None);
        let odd = Nsec3 {
            algorithm: 2,
            ..apex
        };
        assert_eq!(nsec3_proves_absence(&[odd], zone, qname), None);
    }

    #[test]
    fn nsec3_records_are_read() {
        // algorithm 1, flags 0, 5 iterations, salt ab, next hash of 2 bytes.
        let r = parse_nsec3("0p9mhave.example.", &[1, 0, 0, 5, 1, 0xab, 2, 9, 8]).unwrap();
        assert_eq!(
            (r.algorithm, r.iterations, r.salt, r.next),
            (1, 5, vec![0xab], vec![9, 8])
        );
        assert_eq!(r.hash, base32hex("0p9mhave").unwrap());
        assert!(parse_nsec3("0p9mhave.example.", &[1, 0, 0, 5, 9]).is_none());
    }
}
