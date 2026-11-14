//! The deeper DNSSEC collection of a deep run: the chain of trust from
//! the root's trust anchor down to the zone, and a signature check of
//! every record set the run collected.
//!
//! Verdicts are computed here, where the raw record data is at hand, and
//! stored in the observation for the checks to read.

use std::collections::BTreeSet;
use std::net::IpAddr;

use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

use super::iterate::{norm, rcode_name};
use super::signed::{ask_signed, is_authoritative_answer, raw_rdata};
use super::transport::{Client, record_type};
use crate::dnssec::{Dnskey, Ds, ds_matches, parse_dnskey, parse_ds, parse_rrsig};
use crate::observe::{ChainLink, QType, RecordSignature, ZoneObservation};
use crate::verify::{Verdict, verify_rrset};

/// The root zone's trust anchors, as IANA publishes them: the key-signing
/// keys of 2017 and 2024, by key tag, algorithm, digest type and digest.
pub const ROOT_ANCHORS: [(u16, u8, u8, &str); 2] = [
    (
        20326,
        8,
        2,
        "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
    ),
    (
        38696,
        8,
        2,
        "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16",
    ),
];

/// The built-in trust anchors as DS records.
pub fn root_anchors() -> Vec<Ds> {
    ROOT_ANCHORS
        .iter()
        .map(|(key_tag, algorithm, digest_type, digest)| Ds {
            key_tag: *key_tag,
            algorithm: *algorithm,
            digest_type: *digest_type,
            digest: digest.to_string(),
        })
        .collect()
}

/// At most this many signed queries are made to check record sets.
const MAX_RECORD_QUERIES: usize = 300;

/// Record data in the form signatures are made over: names inside it
/// uncompressed and lower case.
fn canonical_rdata(data: &RData) -> Option<Vec<u8>> {
    if let RData::Unknown { rdata, .. } = data {
        return Some(rdata.anything.clone());
    }
    let mut buffer = Vec::new();
    let mut encoder = BinEncoder::new(&mut buffer);
    encoder.set_canonical_form(true);
    data.emit(&mut encoder).ok()?;
    Some(buffer)
}

/// The answer records of one type owned by `owner`, in canonical form.
fn answer_set(msg: &Message, owner: &str, rtype: RecordType) -> Vec<Vec<u8>> {
    msg.answers
        .iter()
        .filter(|rec| rec.record_type() == rtype && norm(&rec.name) == owner)
        .filter_map(|rec| canonical_rdata(&rec.data))
        .collect()
}

/// The signatures in an answer that cover `rtype` and are within their
/// validity period at `now`, and whether any covering signature was there
/// at all.
fn timely_signatures<'m>(
    msg: &'m Message,
    owner: &str,
    rtype: u16,
    now: u64,
) -> (Vec<&'m [u8]>, bool) {
    let covering: Vec<&[u8]> = raw_rdata(msg, owner, RecordType::RRSIG)
        .into_iter()
        .filter(|r| r.len() > 18 && u16::from_be_bytes([r[0], r[1]]) == rtype)
        .collect();
    let any = !covering.is_empty();
    let timely = covering
        .into_iter()
        .filter(|r| {
            parse_rrsig(r).is_some_and(|sig| {
                u64::from(sig.inception) <= now + 300 && now <= u64::from(sig.expiration)
            })
        })
        .collect();
    (timely, any)
}

/// True when at least one signature names a key that is in `keys`. A set
/// signed only by keys nobody publishes cannot be validated by anyone.
fn names_a_known_key(signatures: &[&[u8]], keys: &[Dnskey]) -> bool {
    signatures.iter().any(|r| {
        let (algorithm, tag) = (r[2], u16::from_be_bytes([r[16], r[17]]));
        keys.iter()
            .any(|k| k.algorithm == algorithm && k.key_tag == tag)
    })
}

/// Whether the signatures over one record set in an answer hold:
/// `valid`, `invalid`, `expired`, `unsigned`, or `untried` when no
/// signature could be tried (an algorithm zoneblick does not know).
fn judge(msg: &Message, owner: &str, rtype: RecordType, keys: &[Dnskey], now: u64) -> &'static str {
    let set = answer_set(msg, owner, rtype);
    let code = u16::from(rtype);
    let (signatures, any) = timely_signatures(msg, owner, code, now);
    if !any {
        return "unsigned";
    }
    if signatures.is_empty() {
        return "expired";
    }
    if !names_a_known_key(&signatures, keys) {
        return "invalid";
    }
    match verify_rrset(owner, code, &set, &signatures, keys) {
        Verdict::Valid => "valid",
        Verdict::Invalid => "invalid",
        Verdict::Untried => "untried",
    }
}

/// Ask for every record set the run found, with signatures, and check
/// each against the zone's keys. Empty for a zone without keys.
pub async fn record_signatures(client: &Client, obs: &ZoneObservation) -> Vec<RecordSignature> {
    let keys: BTreeSet<Dnskey> = obs
        .dnssec
        .iter()
        .flat_map(|d| &d.servers)
        .flat_map(|s| s.dnskeys.iter().flatten().cloned())
        .collect();
    if keys.is_empty() {
        return Vec::new();
    }
    let keys: Vec<Dnskey> = keys.into_iter().collect();
    let mut out = Vec::new();
    // Every query sent counts, whether or not it gives a verdict.
    let mut asked = 0;
    for rec in &obs.records {
        let has_data = rec
            .outcome
            .answer()
            .is_some_and(|a| a.authoritative && !a.rdata.is_empty());
        if !has_data || !QType::SWEEP.contains(&rec.qtype) {
            continue;
        }
        if asked >= MAX_RECORD_QUERIES {
            break;
        }
        asked += 1;
        let rtype = record_type(rec.qtype);
        let status = match ask_signed(client, rec.address, &rec.name, rec.qtype).await {
            Ok(msg) if is_authoritative_answer(&msg) => {
                if answer_set(&msg, &rec.name, rtype).is_empty() {
                    // The name is an alias; its own set is checked as CNAME.
                    continue;
                }
                judge(&msg, &rec.name, rtype, &keys, obs.started_at_unix)
            }
            _ => continue,
        };
        out.push(RecordSignature {
            name: rec.name.clone(),
            rtype: rec.qtype.as_str().to_string(),
            ns_name: rec.ns_name.clone(),
            address: rec.address,
            status: status.to_string(),
        });
    }
    out
}

fn link(zone: &str, status: &str, detail: Option<String>) -> ChainLink {
    ChainLink {
        zone: zone.to_string(),
        status: status.to_string(),
        detail,
    }
}

/// The DNSKEY set of `zone` from one of its servers, accepted only when
/// a key that one of `ds` points at signs the set. `Err` says why not,
/// with the status to report.
async fn trusted_keys(
    client: &Client,
    server: IpAddr,
    zone: &str,
    ds: &[Ds],
    now: u64,
) -> Result<Vec<Dnskey>, (&'static str, String)> {
    let msg = ask_signed(client, server, zone, QType::Dnskey)
        .await
        .map_err(|e| {
            (
                "unknown",
                format!("the keys of {zone} could not be read: {e}"),
            )
        })?;
    if !is_authoritative_answer(&msg) {
        return Err((
            "unknown",
            format!(
                "the keys of {zone} could not be read: {server} answered {}",
                rcode_name(msg.metadata.response_code)
            ),
        ));
    }
    let raw = raw_rdata(&msg, zone, RecordType::DNSKEY);
    let keys: Vec<Dnskey> = raw.iter().copied().filter_map(parse_dnskey).collect();
    if keys.is_empty() {
        return Err((
            "bogus",
            format!("the parent has a DS record for {zone}, but {zone} publishes no keys"),
        ));
    }
    let anchored: Vec<Dnskey> = keys
        .iter()
        .filter(|key| ds.iter().any(|d| ds_matches(zone, d, key)))
        .cloned()
        .collect();
    if anchored.is_empty() {
        return Err((
            "bogus",
            format!("no key of {zone} matches a DS record at its parent"),
        ));
    }
    let set: Vec<Vec<u8>> = raw.iter().map(|r| r.to_vec()).collect();
    let (signatures, any) = timely_signatures(&msg, zone, 48, now);
    if !any {
        return Err(("bogus", format!("the key set of {zone} is not signed")));
    }
    if signatures.is_empty() {
        return Err((
            "bogus",
            format!("every signature over the key set of {zone} is outside its validity period"),
        ));
    }
    if !names_a_known_key(&signatures, &anchored) {
        return Err((
            "bogus",
            format!(
                "the key set of {zone} is not signed by a key its parent's DS records point at"
            ),
        ));
    }
    match verify_rrset(zone, 48, &set, &signatures, &anchored) {
        Verdict::Valid => Ok(keys),
        Verdict::Invalid => Err((
            "bogus",
            format!("the signature over the key set of {zone} does not verify"),
        )),
        Verdict::Untried => Err((
            "unknown",
            format!("the key set of {zone} is signed with an algorithm zoneblick cannot check"),
        )),
    }
}

/// Follow the chain of trust from the trust anchors down the delegation
/// path. One link per zone on the path, starting with the root. After the
/// first link that is not `secure`, the zones below are not judged.
pub async fn chain_of_trust(
    client: &Client,
    obs: &ZoneObservation,
    anchors: &[Ds],
) -> Vec<ChainLink> {
    let now = obs.started_at_unix;
    let Some(first) = obs.delegation_path.first() else {
        return Vec::new();
    };
    let mut links = Vec::new();
    let mut keys = match trusted_keys(client, first.server_address, ".", anchors, now).await {
        Ok(keys) => {
            links.push(link(".", "secure", None));
            keys
        }
        Err((status, detail)) => {
            links.push(link(".", status, Some(detail)));
            return links;
        }
    };

    for (i, step) in obs.delegation_path.iter().enumerate() {
        let child = step.to_zone.as_str();
        // The DS set for the child, from the parent's server, signed by
        // the parent's keys.
        let msg = match ask_signed(client, step.server_address, child, QType::Ds).await {
            Ok(msg) if rcode_name(msg.metadata.response_code) == "NOERROR" => msg,
            Ok(msg) => {
                links.push(link(
                    child,
                    "unknown",
                    Some(format!(
                        "the DS query for {child} was answered {}",
                        rcode_name(msg.metadata.response_code)
                    )),
                ));
                break;
            }
            Err(e) => {
                links.push(link(
                    child,
                    "unknown",
                    Some(format!("the DS set of {child} could not be read: {e}")),
                ));
                break;
            }
        };
        let raw = raw_rdata(&msg, child, RecordType::DS);
        let ds: Vec<Ds> = raw.iter().copied().filter_map(parse_ds).collect();
        if ds.is_empty() {
            links.push(link(
                child,
                "insecure",
                Some(format!("{} has no DS record for {child}", step.from_zone)),
            ));
            break;
        }
        let set: Vec<Vec<u8>> = raw.iter().map(|r| r.to_vec()).collect();
        let (signatures, any) = timely_signatures(&msg, child, 43, now);
        let verdict = if !any {
            Err(format!(
                "the DS set for {child} at {} is not signed",
                step.from_zone
            ))
        } else if signatures.is_empty() {
            Err(format!(
                "every signature over the DS set for {child} is outside its validity period"
            ))
        } else if !names_a_known_key(&signatures, &keys) {
            Err(format!(
                "the DS set for {child} is signed by a key that {} does not publish",
                step.from_zone
            ))
        } else {
            match verify_rrset(child, 43, &set, &signatures, &keys) {
                Verdict::Valid => Ok(()),
                Verdict::Invalid => Err(format!(
                    "the signature over the DS set for {child} does not verify with the keys of {}",
                    step.from_zone
                )),
                Verdict::Untried => {
                    links.push(link(
                        child,
                        "unknown",
                        Some(format!(
                            "the DS set for {child} is signed with an algorithm zoneblick cannot check"
                        )),
                    ));
                    break;
                }
            }
        };
        if let Err(detail) = verdict {
            links.push(link(child, "bogus", Some(detail)));
            break;
        }

        // A server of the child: the one that gave the next referral, or
        // for the zone itself any nameserver that answered.
        let server = match obs.delegation_path.get(i + 1) {
            Some(next) => Some(next.server_address),
            None => obs
                .probes
                .iter()
                .find(|p| p.outcome.response().is_some())
                .map(|p| p.address),
        };
        let Some(server) = server else {
            links.push(link(
                child,
                "unknown",
                Some(format!("no server of {child} is known")),
            ));
            break;
        };
        match trusted_keys(client, server, child, &ds, now).await {
            Ok(child_keys) => {
                links.push(link(child, "secure", None));
                keys = child_keys;
            }
            Err((status, detail)) => {
                links.push(link(child, status, Some(detail)));
                break;
            }
        }
    }
    links
}
