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
            let (dnskeys, dnskey_sigs) =
                match ask_signed(&client, address, &zone, QType::Dnskey).await {
                    Ok(msg) if is_authoritative_answer(&msg) => {
                        let mut keys: Vec<Dnskey> = raw_rdata(&msg, &zone, RecordType::DNSKEY)
                            .into_iter()
                            .filter_map(parse_dnskey)
                            .collect();
                        keys.sort();
                        (Some(keys), signatures(&msg, &zone, "DNSKEY"))
                    }
                    _ => (None, Vec::new()),
                };
            let soa_sigs = match ask_signed(&client, address, &zone, QType::Soa).await {
                Ok(msg) if is_authoritative_answer(&msg) => Some(signatures(&msg, &zone, "SOA")),
                _ => None,
            };
            ServerDnssec {
                ns_name,
                address,
                dnskeys,
                dnskey_sigs,
                soa_sigs,
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
