//! DNSSEC checks, `SEC-01` to `SEC-05`.
//!
//! These checks read keys, DS records and signature dates. They do not
//! verify signatures cryptographically; that is a later step. They are
//! labelled beta in the documentation.

use std::collections::{BTreeMap, BTreeSet};

use super::{Evidence, Finding, ServerRef, Severity, Variant};
use crate::dnssec::{
    Dnskey, Ds, Rrsig, algorithm_name, digest_name, ds_matches, is_weak_algorithm, is_weak_digest,
};
use crate::observe::{ServerDnssec, ZoneObservation};

/// Signatures closer to expiry than this raise a warning (the design's
/// default of seven days).
const EXPIRY_WARNING_SECS: i64 = 7 * 86_400;

fn server_ref(s: &ServerDnssec) -> ServerRef {
    ServerRef {
        ns_name: s.ns_name.clone(),
        address: s.address,
    }
}

fn ds_label(ds: &Ds) -> String {
    format!(
        "key tag {}, {}, {}",
        ds.key_tag,
        algorithm_name(ds.algorithm),
        digest_name(ds.digest_type)
    )
}

fn key_label(key: &Dnskey) -> String {
    format!(
        "key tag {} ({}, {})",
        key.key_tag,
        if key.is_ksk() { "KSK" } else { "ZSK" },
        algorithm_name(key.algorithm)
    )
}

/// The parent's DS records, when the parent answered.
fn parent_ds(obs: &ZoneObservation) -> Option<&Vec<Ds>> {
    obs.dnssec.as_ref()?.parent_ds.as_ref()?.records.as_ref()
}

/// Servers that gave an authoritative DNSKEY answer, with their keys.
fn key_views(obs: &ZoneObservation) -> Vec<(&ServerDnssec, &Vec<Dnskey>)> {
    obs.dnssec
        .iter()
        .flat_map(|d| &d.servers)
        .filter_map(|s| s.dnskeys.as_ref().map(|k| (s, k)))
        .collect()
}

/// SEC-01: the parent has DS records but a server's DNSKEY set contains no
/// key that any of them points at. Validating resolvers treat the zone as
/// bogus and stop resolving it.
pub fn sec_01_ds_without_key(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(ds) = parent_ds(obs).filter(|ds| !ds.is_empty()) else {
        return Vec::new();
    };
    let broken: Vec<(&ServerDnssec, &Vec<Dnskey>)> = key_views(obs)
        .into_iter()
        .filter(|(_, keys)| {
            !keys
                .iter()
                .any(|key| ds.iter().any(|d| ds_matches(&obs.zone, d, key)))
        })
        .collect();
    if broken.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "SEC-01",
        Severity::Critical,
        &obs.zone,
        format!(
            "The parent has DS records for {} but {} of its nameservers serve no matching DNSKEY",
            obs.zone,
            broken.len()
        ),
        Evidence::DsWithoutKey {
            ds: ds.iter().map(ds_label).collect(),
            servers: broken
                .into_iter()
                .map(|(s, keys)| Variant {
                    value: keys.iter().map(key_label).collect(),
                    servers: vec![server_ref(s)],
                })
                .collect(),
        },
    )]
}

/// SEC-02: a signature has expired (critical) or is close to expiring
/// (warning). Time is measured from the start of the run.
///
/// "Close" is seven days, or a quarter of the signature's own lifetime when
/// that is shorter. Providers that sign on the fly issue signatures valid
/// for a day or two; a flat seven-day rule would warn about them forever.
pub fn sec_02_signature_expiry(obs: &ZoneObservation) -> Vec<Finding> {
    let now = obs.started_at_unix as i64;
    // Per covered type: the signature with the least time left, and where.
    let mut worst: BTreeMap<&str, (&Rrsig, Vec<ServerRef>)> = BTreeMap::new();
    for server in obs.dnssec.iter().flat_map(|d| &d.servers) {
        let sigs = server
            .dnskey_sigs
            .iter()
            .chain(server.soa_sigs.iter().flatten());
        for sig in sigs {
            match worst.get_mut(sig.type_covered.as_str()) {
                Some((current, servers)) if sig.expiration == current.expiration => {
                    servers.push(server_ref(server));
                }
                Some((current, _)) if sig.expiration > current.expiration => {}
                _ => {
                    worst.insert(&sig.type_covered, (sig, vec![server_ref(server)]));
                }
            }
        }
    }
    let mut findings = Vec::new();
    for (covered, (sig, mut servers)) in worst {
        let left = i64::from(sig.expiration) - now;
        let (severity, summary) = if left <= 0 {
            (
                Severity::Critical,
                format!(
                    "The signature over the {covered} record set of {} has expired",
                    obs.zone
                ),
            )
        } else if left < warning_window(sig) {
            (
                Severity::Warning,
                format!(
                    "The signature over the {covered} record set of {} expires in {}",
                    obs.zone,
                    duration(left)
                ),
            )
        } else {
            continue;
        };
        servers.sort();
        servers.dedup();
        findings.push(Finding::new(
            "SEC-02",
            severity,
            &obs.zone,
            summary,
            Evidence::SignatureExpiry {
                type_covered: covered.to_string(),
                key_tag: sig.key_tag,
                expiration_unix: sig.expiration,
                seconds_left: left,
                servers,
            },
        ));
    }
    findings
}

/// How long before expiry a signature starts to raise a warning.
fn warning_window(sig: &Rrsig) -> i64 {
    let lifetime = i64::from(sig.expiration) - i64::from(sig.inception);
    if lifetime <= 0 {
        return EXPIRY_WARNING_SECS;
    }
    EXPIRY_WARNING_SECS.min(lifetime / 4)
}

/// A length of time in days and hours, or hours and minutes.
fn duration(secs: i64) -> String {
    let (days, hours, minutes) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    if days > 0 {
        format!("{days} d {hours} h")
    } else {
        format!("{hours} h {minutes} min")
    }
}

/// SEC-03: the zone serves DNSKEY records but the parent has no DS, so the
/// zone is signed but nobody can validate it.
pub fn sec_03_signed_not_chained(obs: &ZoneObservation) -> Vec<Finding> {
    if !parent_ds(obs).is_some_and(|ds| ds.is_empty()) {
        return Vec::new();
    }
    let keys: BTreeSet<String> = key_views(obs)
        .into_iter()
        .flat_map(|(_, keys)| keys.iter().map(key_label))
        .collect();
    if keys.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "SEC-03",
        Severity::Notice,
        &obs.zone,
        format!(
            "{} is signed, but its parent has no DS record, so resolvers cannot validate it",
            obs.zone
        ),
        Evidence::SignedNotChained {
            dnskeys: keys.into_iter().collect(),
        },
    )]
}

/// SEC-04: a DS record or key uses an algorithm or digest that is no longer
/// considered safe (RFC 8624): RSA/MD5, DSA, RSA/SHA-1, GOST, SHA-1 digests.
pub fn sec_04_weak_algorithm(obs: &ZoneObservation) -> Vec<Finding> {
    let mut weak: BTreeSet<String> = BTreeSet::new();
    for ds in parent_ds(obs).into_iter().flatten() {
        if is_weak_digest(ds.digest_type) {
            weak.insert(format!(
                "DS for key tag {} uses a {} digest",
                ds.key_tag,
                digest_name(ds.digest_type)
            ));
        }
        if is_weak_algorithm(ds.algorithm) {
            weak.insert(format!(
                "DS for key tag {} names algorithm {}",
                ds.key_tag,
                algorithm_name(ds.algorithm)
            ));
        }
    }
    for (_, keys) in key_views(obs) {
        for key in keys.iter().filter(|k| is_weak_algorithm(k.algorithm)) {
            weak.insert(format!(
                "DNSKEY with key tag {} uses {}",
                key.key_tag,
                algorithm_name(key.algorithm)
            ));
        }
    }
    if weak.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "SEC-04",
        Severity::Warning,
        &obs.zone,
        format!(
            "{} uses a weak or deprecated DNSSEC algorithm or digest",
            obs.zone
        ),
        Evidence::WeakAlgorithm {
            items: weak.into_iter().collect(),
        },
    )]
}

/// SEC-05: nameservers disagree about the zone's keys or signatures: the
/// DNSKEY sets differ, or some servers sign the SOA and others do not.
pub fn sec_05_signatures_differ(obs: &ZoneObservation) -> Vec<Finding> {
    let mut groups: BTreeMap<Vec<String>, Vec<ServerRef>> = BTreeMap::new();
    for server in obs.dnssec.iter().flat_map(|d| &d.servers) {
        let (Some(keys), Some(soa_sigs)) = (&server.dnskeys, &server.soa_sigs) else {
            continue;
        };
        let tags: Vec<String> = keys.iter().map(|k| k.key_tag.to_string()).collect();
        let signers: BTreeSet<String> = soa_sigs.iter().map(|s| s.key_tag.to_string()).collect();
        let describe = |what: &str, items: Vec<String>| {
            if items.is_empty() {
                format!("{what}: none")
            } else {
                format!("{what}: {}", items.join(", "))
            }
        };
        groups
            .entry(vec![
                describe("DNSKEY key tags", tags),
                describe("SOA signed by key tag", signers.into_iter().collect()),
            ])
            .or_default()
            .push(server_ref(server));
    }
    if groups.len() < 2 {
        return Vec::new();
    }
    vec![Finding::new(
        "SEC-05",
        Severity::Warning,
        &obs.zone,
        format!(
            "Nameservers serve {} different sets of DNSSEC keys or signatures for {}",
            groups.len(),
            obs.zone
        ),
        Evidence::SignaturesDiffer {
            variants: groups
                .into_iter()
                .map(|(value, servers)| Variant { value, servers })
                .collect(),
        },
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::*;
    use crate::dnssec::{ds_digest, parse_dnskey};
    use crate::observe::{DnssecObservation, ParentDs};

    fn key(seed: u8, ksk: bool) -> (Dnskey, Vec<u8>) {
        let mut rdata = vec![0x01, if ksk { 0x01 } else { 0x00 }, 3, 13];
        rdata.extend((0..64u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)));
        (parse_dnskey(&rdata).unwrap(), rdata)
    }

    fn ds_for(key: &Dnskey, rdata: &[u8]) -> Ds {
        Ds {
            key_tag: key.key_tag,
            algorithm: key.algorithm,
            digest_type: 2,
            digest: ds_digest(ZONE, rdata, 2).unwrap(),
        }
    }

    /// A signature with a 60-day lifetime that ends `expires_in` from now.
    fn sig(covered: &str, key_tag: u16, expires_in: i64) -> Rrsig {
        let expiration = NOW as i64 + expires_in;
        Rrsig {
            type_covered: covered.to_string(),
            algorithm: 13,
            key_tag,
            expiration: expiration as u32,
            inception: (expiration - 2 * MONTH) as u32,
            signer: ZONE.to_string(),
        }
    }

    const NOW: u64 = 1_800_000_000;
    const MONTH: i64 = 30 * 86_400;

    /// A correctly signed zone: KSK with a matching DS, ZSK signing the SOA.
    fn signed() -> ZoneObservation {
        let mut obs = healthy();
        obs.started_at_unix = NOW;
        let (ksk, ksk_rdata) = key(1, true);
        let (zsk, _) = key(2, false);
        let servers = [("ns1.example.test.", V4_A), ("ns2.example.test.", V4_B)]
            .into_iter()
            .map(|(name, addr)| ServerDnssec {
                ns_name: name.to_string(),
                address: ip(addr),
                dnskeys: Some(vec![ksk.clone(), zsk.clone()]),
                dnskey_sigs: vec![sig("DNSKEY", ksk.key_tag, MONTH)],
                soa_sigs: Some(vec![sig("SOA", zsk.key_tag, MONTH)]),
            })
            .collect();
        obs.dnssec = Some(DnssecObservation {
            parent_ds: Some(ParentDs {
                parent_zone: "test.".to_string(),
                server_name: Some("ns.nic.test.".to_string()),
                server_address: ip("203.0.113.1"),
                records: Some(vec![ds_for(&ksk, &ksk_rdata)]),
                error: None,
            }),
            servers,
        });
        obs
    }

    fn dnssec(obs: &mut ZoneObservation) -> &mut DnssecObservation {
        obs.dnssec.as_mut().unwrap()
    }

    fn all(obs: &ZoneObservation) -> Vec<Finding> {
        [
            sec_01_ds_without_key(obs),
            sec_02_signature_expiry(obs),
            sec_03_signed_not_chained(obs),
            sec_04_weak_algorithm(obs),
            sec_05_signatures_differ(obs),
        ]
        .concat()
    }

    #[test]
    fn a_correctly_signed_zone_is_clean() {
        assert_eq!(all(&signed()), []);
    }

    #[test]
    fn an_unsigned_zone_is_clean() {
        let mut obs = signed();
        let d = dnssec(&mut obs);
        d.parent_ds.as_mut().unwrap().records = Some(vec![]);
        for s in &mut d.servers {
            s.dnskeys = Some(vec![]);
            s.dnskey_sigs.clear();
            s.soa_sigs = Some(vec![]);
        }
        assert_eq!(all(&obs), []);
        // And so is an observation with no DNSSEC data at all.
        obs.dnssec = None;
        assert_eq!(all(&obs), []);
    }

    #[test]
    fn sec_01_ds_points_at_a_missing_key() {
        let mut obs = signed();
        let (other, other_rdata) = key(9, true);
        dnssec(&mut obs).parent_ds.as_mut().unwrap().records =
            Some(vec![ds_for(&other, &other_rdata)]);
        let findings = sec_01_ds_without_key(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(matches!(
            &findings[0].evidence,
            Evidence::DsWithoutKey { servers, .. } if servers.len() == 2
        ));
    }

    #[test]
    fn sec_01_right_tag_wrong_digest() {
        let mut obs = signed();
        let ds = &mut dnssec(&mut obs)
            .parent_ds
            .as_mut()
            .unwrap()
            .records
            .as_mut()
            .unwrap()[0];
        ds.digest = "00".repeat(32);
        assert_eq!(sec_01_ds_without_key(&obs).len(), 1);
    }

    #[test]
    fn sec_01_one_server_lost_the_key() {
        let mut obs = signed();
        dnssec(&mut obs).servers[1].dnskeys = Some(vec![key(2, false).0]);
        let findings = sec_01_ds_without_key(&obs);
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            &findings[0].evidence,
            Evidence::DsWithoutKey { servers, .. }
                if servers.len() == 1 && servers[0].servers[0].address == ip(V4_B)
        ));
        // A server that did not answer is not judged.
        dnssec(&mut obs).servers[1].dnskeys = None;
        assert!(sec_01_ds_without_key(&obs).is_empty());
    }

    #[test]
    fn sec_02_expired_and_expiring() {
        let mut obs = signed();
        let zsk_tag = key(2, false).0.key_tag;
        dnssec(&mut obs).servers[0].soa_sigs = Some(vec![sig("SOA", zsk_tag, 3 * 86_400 + 7200)]);
        let findings = sec_02_signature_expiry(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(
            findings[0].summary.contains("SOA"),
            "{}",
            findings[0].summary
        );
        assert!(
            findings[0].summary.contains("3 d 2 h"),
            "{}",
            findings[0].summary
        );
        assert!(matches!(
            &findings[0].evidence,
            Evidence::SignatureExpiry { servers, .. } if servers.len() == 1
        ));

        for s in &mut dnssec(&mut obs).servers {
            s.dnskey_sigs = vec![sig("DNSKEY", 1, -60)];
        }
        let findings = sec_02_signature_expiry(&obs);
        assert_eq!(findings.len(), 2);
        let expired = findings
            .iter()
            .find(|f| f.severity == Severity::Critical)
            .unwrap();
        assert!(expired.summary.contains("DNSKEY") && expired.summary.contains("expired"));
        assert!(matches!(
            &expired.evidence,
            Evidence::SignatureExpiry { servers, seconds_left, .. } if servers.len() == 2 && *seconds_left == -60
        ));
        // The identity of the finding does not depend on the dates.
        let again = {
            let mut later = obs.clone();
            later.started_at_unix += 3600;
            sec_02_signature_expiry(&later)
        };
        assert_eq!(findings[0].fingerprint_key(), again[0].fingerprint_key());
    }

    #[test]
    fn sec_02_short_lived_signatures_are_judged_by_their_lifetime() {
        // Signed on the fly: valid from a day ago until a day from now.
        let mut obs = signed();
        let online = |left: i64| Rrsig {
            expiration: (NOW as i64 + left) as u32,
            inception: (NOW as i64 + left - 2 * 86_400) as u32,
            ..sig("SOA", 7, 0)
        };
        for s in &mut dnssec(&mut obs).servers {
            s.soa_sigs = Some(vec![online(86_400)]);
        }
        assert!(
            sec_02_signature_expiry(&obs).is_empty(),
            "a day left of two is fine"
        );
        // Under a quarter of the lifetime left: the signer has stopped.
        for s in &mut dnssec(&mut obs).servers {
            s.soa_sigs = Some(vec![online(3 * 3600)]);
        }
        let findings = sec_02_signature_expiry(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn sec_03_signed_without_ds() {
        let mut obs = signed();
        dnssec(&mut obs).parent_ds.as_mut().unwrap().records = Some(vec![]);
        let findings = sec_03_signed_not_chained(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Notice);
        assert!(sec_01_ds_without_key(&obs).is_empty());
        // If the parent did not answer, nothing is claimed.
        dnssec(&mut obs).parent_ds.as_mut().unwrap().records = None;
        assert!(sec_03_signed_not_chained(&obs).is_empty());
    }

    #[test]
    fn sec_04_weak_digest_and_algorithm() {
        let mut obs = signed();
        let d = dnssec(&mut obs);
        d.parent_ds.as_mut().unwrap().records.as_mut().unwrap()[0].digest_type = 1;
        let mut old = key(3, false).0;
        old.algorithm = 5;
        for s in &mut d.servers {
            s.dnskeys.as_mut().unwrap().push(old.clone());
        }
        let findings = sec_04_weak_algorithm(&obs);
        assert_eq!(findings.len(), 1);
        match &findings[0].evidence {
            Evidence::WeakAlgorithm { items } => {
                assert_eq!(items.len(), 2, "{items:?}");
                assert!(items.iter().any(|i| i.contains("SHA-1")));
                assert!(items.iter().any(|i| i.contains("RSASHA1")));
            }
            other => panic!("unexpected evidence: {other:?}"),
        }
    }

    #[test]
    fn sec_05_keys_or_signatures_differ() {
        let mut obs = signed();
        dnssec(&mut obs).servers[1].soa_sigs = Some(vec![]);
        let findings = sec_05_signatures_differ(&obs);
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            &findings[0].evidence,
            Evidence::SignaturesDiffer { variants } if variants.len() == 2
        ));

        let mut obs = signed();
        dnssec(&mut obs).servers[1]
            .dnskeys
            .as_mut()
            .unwrap()
            .push(key(5, false).0);
        assert_eq!(sec_05_signatures_differ(&obs).len(), 1);
    }
}
