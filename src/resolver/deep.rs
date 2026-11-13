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
    Some(Denial {
        qname,
        rcode: rcode_name(msg.metadata.response_code),
        answered: !msg.answers.is_empty(),
        nsec,
        nsec3: msg
            .authorities
            .iter()
            .filter(|rec| rec.record_type() == RecordType::NSEC3)
            .count(),
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
}
