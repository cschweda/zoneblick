//! Collects the zone's DNSSEC data: the DS set from the parent, and the
//! DNSKEY set and signatures from every nameserver that answered.
//!
//! Nothing is validated here; the SEC checks read the result.

use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use tokio::task::JoinSet;

use super::iterate::{norm, parse_response, rcode_name};
use super::transport::{Client, QuerySpec, RawOutcome};
use crate::dnssec::{Dnskey, Ds, Rrsig, parse_dnskey, parse_ds, parse_rrsig};
use crate::observe::{DnssecObservation, ParentDs, QType, ReferralStep, ServerDnssec, Transport};
use crate::verify::verify_rrset;

/// One query with the DO bit set: UDP, then TCP if the answer is truncated.
pub(crate) async fn ask_signed(
    client: &Client,
    server: IpAddr,
    qname: &str,
    qtype: QType,
) -> Result<Message, String> {
    let mut spec = QuerySpec {
        server,
        transport: Transport::Udp,
        qname: qname.to_string(),
        qtype,
        edns: true,
        dnssec: true,
        probe: Default::default(),
    };
    for _ in 0..2 {
        let msg = match client.exchange(&spec).await {
            RawOutcome::Response { wire } => parse_response(&spec, &wire)?,
            RawOutcome::Timeout => return Err("timeout".to_string()),
            RawOutcome::NetError { message } => return Err(message),
        };
        if msg.metadata.truncation && spec.transport == Transport::Udp {
            spec.transport = Transport::Tcp;
            continue;
        }
        return Ok(msg);
    }
    Err("truncated over TCP".to_string())
}

/// The raw record data of the answer records of one type owned by `owner`.
pub(crate) fn raw_rdata<'m>(msg: &'m Message, owner: &str, rtype: RecordType) -> Vec<&'m [u8]> {
    msg.answers
        .iter()
        .filter(|rec| rec.record_type() == rtype && norm(&rec.name) == owner)
        .filter_map(|rec| match &rec.data {
            RData::Unknown { rdata, .. } => Some(rdata.anything.as_slice()),
            _ => None,
        })
        .collect()
}

fn signatures(msg: &Message, owner: &str, covered: &str) -> Vec<Rrsig> {
    let mut sigs: Vec<Rrsig> = raw_rdata(msg, owner, RecordType::RRSIG)
        .into_iter()
        .filter_map(parse_rrsig)
        .filter(|sig| sig.type_covered == covered)
        .collect();
    sigs.sort();
    sigs
}

/// A name in uncompressed wire form, lower case, as signatures are made
/// over it.
fn canonical_name(name: &hickory_proto::rr::Name) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.iter() {
        out.push(label.len() as u8);
        out.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    out.push(0);
    out
}

/// The zone's SOA record data in canonical form, when the answer has it.
fn soa_rdata(msg: &Message, owner: &str) -> Option<Vec<u8>> {
    msg.answers.iter().find_map(|rec| match &rec.data {
        RData::SOA(s) if norm(&rec.name) == owner => {
            let mut out = canonical_name(&s.mname);
            out.extend(canonical_name(&s.rname));
            out.extend_from_slice(&s.serial.to_be_bytes());
            out.extend_from_slice(&s.refresh.to_be_bytes());
            out.extend_from_slice(&s.retry.to_be_bytes());
            out.extend_from_slice(&s.expire.to_be_bytes());
            out.extend_from_slice(&s.minimum.to_be_bytes());
            Some(out)
        }
        _ => None,
    })
}

pub(crate) fn is_authoritative_answer(msg: &Message) -> bool {
    msg.metadata.authoritative && rcode_name(msg.metadata.response_code) == "NOERROR"
}

/// Ask the parent server that gave the referral for the zone's DS set, and
/// every responding nameserver for the DNSKEY set and a signed SOA.
pub(crate) async fn collect_dnssec(
    client: &Arc<Client>,
    zone: &str,
    parent: Option<&ReferralStep>,
    servers: &[(String, IpAddr)],
) -> DnssecObservation {
    let parent_ds = match parent {
        None => None,
        Some(step) => {
            let (records, error) =
                match ask_signed(client, step.server_address, zone, QType::Ds).await {
                    Ok(msg) if rcode_name(msg.metadata.response_code) == "NOERROR" => {
                        let mut ds: Vec<Ds> = raw_rdata(&msg, zone, RecordType::DS)
                            .into_iter()
                            .filter_map(parse_ds)
                            .collect();
                        ds.sort();
                        (Some(ds), None)
                    }
                    Ok(msg) => (None, Some(rcode_name(msg.metadata.response_code))),
                    Err(message) => (None, Some(message)),
                };
            Some(ParentDs {
                parent_zone: step.from_zone.clone(),
                server_name: step.server_name.clone(),
                server_address: step.server_address,
                records,
                error,
            })
        }
    };

    let mut tasks = JoinSet::new();
    for (ns_name, address) in servers {
        let client = client.clone();
        let (zone, ns_name, address) = (zone.to_string(), ns_name.clone(), *address);
        tasks.spawn(async move {
            let mut dnskey_sig_status = None;
            let (dnskeys, dnskey_sigs) =
                match ask_signed(&client, address, &zone, QType::Dnskey).await {
                    Ok(msg) if is_authoritative_answer(&msg) => {
                        // More keys than any real zone has are not kept:
                        // each one costs time in every later check.
                        let mut raw = raw_rdata(&msg, &zone, RecordType::DNSKEY);
                        raw.truncate(crate::verify::MAX_KEYS);
                        let mut keys: Vec<Dnskey> =
                            raw.iter().copied().filter_map(parse_dnskey).collect();
                        keys.sort();
                        let rrsigs = raw_rdata(&msg, &zone, RecordType::RRSIG);
                        if !keys.is_empty() && !rrsigs.is_empty() {
                            let set: Vec<Vec<u8>> = raw.iter().map(|r| r.to_vec()).collect();
                            let verdict = verify_rrset(&zone, 48, &set, &rrsigs, &keys);
                            dnskey_sig_status = Some(verdict.as_str().to_string());
                        }
                        (Some(keys), signatures(&msg, &zone, "DNSKEY"))
                    }
                    _ => (None, Vec::new()),
                };
            let mut soa_sig_status = None;
            let soa_sigs = match ask_signed(&client, address, &zone, QType::Soa).await {
                Ok(msg) if is_authoritative_answer(&msg) => {
                    let rrsigs = raw_rdata(&msg, &zone, RecordType::RRSIG);
                    if let (Some(keys), Some(soa)) = (
                        dnskeys
                            .as_ref()
                            .filter(|k| !k.is_empty() && !rrsigs.is_empty()),
                        soa_rdata(&msg, &zone),
                    ) {
                        let verdict = verify_rrset(&zone, 6, &[soa], &rrsigs, keys);
                        soa_sig_status = Some(verdict.as_str().to_string());
                    }
                    Some(signatures(&msg, &zone, "SOA"))
                }
                _ => None,
            };
            ServerDnssec {
                ns_name,
                address,
                dnskeys,
                dnskey_sigs,
                soa_sigs,
                dnskey_sig_status,
                soa_sig_status,
            }
        });
    }
    let mut out = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        out.push(joined.expect("dnssec task does not panic"));
    }
    out.sort();
    DnssecObservation {
        parent_ds,
        servers: out,
    }
}
