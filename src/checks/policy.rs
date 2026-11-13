//! Mail and policy checks (`POL-01` to `POL-05`) and the takeover checks
//! that need only DNS (`TKO-01`, `TKO-03`, `TKO-04`).
//!
//! "Unregistered" here is decided from DNS alone: a name does not exist and
//! the server that said so belongs to a top-level domain, so the domain
//! itself is not delegated. Domains under two-level suffixes such as
//! `co.uk` are not recognised this way; those are reported as dangling
//! (`TKO-01`) rather than unregistered.

use super::{Evidence, Finding, Severity};
use crate::observe::{Lookup, PolicyObservation, TargetResolution, ZoneObservation};
use crate::resolver::policy::txt_value;

/// SPF evaluation must stop after ten DNS lookups (RFC 7208, section 4.6.4).
const SPF_LOOKUP_LIMIT: usize = 10;

fn policy(obs: &ZoneObservation) -> Option<&PolicyObservation> {
    obs.policy.as_ref()
}

/// POL-01: more than one SPF record, or an SPF record that needs more than
/// ten DNS lookups. Receivers treat both as a permanent error.
pub fn pol_01_spf(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(spf) = policy(obs).and_then(|p| p.spf.as_ref()) else {
        return Vec::new();
    };
    let mut problems = Vec::new();
    if spf.records.len() > 1 {
        problems.push(format!(
            "{} SPF records; there must be one",
            spf.records.len()
        ));
    }
    if spf.lookups.len() > SPF_LOOKUP_LIMIT {
        problems.push(format!(
            "{}{} DNS lookups; the limit is {SPF_LOOKUP_LIMIT}",
            spf.lookups.len(),
            if spf.truncated { " or more" } else { "" }
        ));
    }
    if problems.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "POL-01",
        Severity::Warning,
        &obs.zone,
        format!(
            "The SPF setup of {} is broken: {}",
            obs.zone,
            problems.join("; ")
        ),
        Evidence::SpfProblem {
            records: spf.records.clone(),
            lookups: spf.lookups.len(),
            chain: spf
                .lookups
                .iter()
                .map(|l| format!("{}{} {}", "  ".repeat(l.depth), l.mechanism, l.domain))
                .collect(),
        },
    )]
}

/// POL-02: no DMARC record, or a DMARC policy of `p=none`.
pub fn pol_02_dmarc(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(p) = policy(obs) else {
        return Vec::new();
    };
    if p.dmarc.status == "failed" {
        return Vec::new();
    }
    let record = p
        .dmarc
        .rdata
        .iter()
        .map(|r| txt_value(r))
        .find(|v| v.to_ascii_lowercase().starts_with("v=dmarc1"));
    let name = p.dmarc.name.clone();
    let (summary, tag) = match &record {
        None => (format!("{} has no DMARC record", obs.zone), None),
        Some(text) => {
            let tag = text
                .split(';')
                .filter_map(|part| part.trim().split_once('='))
                .find(|(k, _)| k.trim().eq_ignore_ascii_case("p"))
                .map(|(_, v)| v.trim().to_ascii_lowercase());
            if tag.as_deref() != Some("none") {
                return Vec::new();
            }
            (
                format!(
                    "The DMARC policy of {} is p=none: spoofed mail is reported but not stopped",
                    obs.zone
                ),
                tag,
            )
        }
    };
    vec![Finding::new(
        "POL-02",
        Severity::Notice,
        &name,
        summary,
        Evidence::DmarcProblem {
            record,
            policy: tag,
        },
    )]
}

/// POL-03: no CAA record, so any certificate authority may issue for the zone.
pub fn pol_03_caa(obs: &ZoneObservation) -> Vec<Finding> {
    match policy(obs) {
        Some(p) if p.caa.is_empty_answer() => vec![Finding::new(
            "POL-03",
            Severity::Notice,
            &obs.zone,
            format!(
                "{} has no CAA record, so any certificate authority may issue certificates for it",
                obs.zone
            ),
            Evidence::NoCaa {},
        )],
        _ => Vec::new(),
    }
}

/// Does an MTA-STS `mx:` pattern cover this mail host?
fn sts_pattern_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.');
    let pattern = pattern.trim_end_matches('.');
    match pattern.strip_prefix("*.") {
        // A wildcard covers exactly one extra label.
        Some(rest) => host
            .split_once('.')
            .is_some_and(|(_, parent)| parent.eq_ignore_ascii_case(rest)),
        None => host.eq_ignore_ascii_case(pattern),
    }
}

/// POL-04: an MTA-STS record exists, but the policy file cannot be fetched,
/// is not valid, or does not cover the zone's mail servers.
pub fn pol_04_mta_sts(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(p) = policy(obs) else {
        return Vec::new();
    };
    let Some(sts) = &p.mta_sts else {
        return Vec::new();
    };
    let mut problems = Vec::new();
    match (sts.http_status, &sts.error) {
        (_, Some(error)) => problems.push(format!("the policy file could not be fetched: {error}")),
        (Some(200), None) => {
            if sts.version.as_deref() != Some("STSv1") {
                problems.push("the policy has no 'version: STSv1' line".to_string());
            }
            let mode = sts.mode.as_deref();
            if !matches!(mode, Some("enforce" | "testing" | "none")) {
                problems.push("the policy has no valid 'mode' line".to_string());
            }
            if sts
                .max_age
                .as_deref()
                .is_none_or(|v| v.parse::<u64>().is_err())
            {
                problems.push("the policy has no valid 'max_age' line".to_string());
            }
            if mode != Some("none") {
                if sts.mx_patterns.is_empty() {
                    problems.push("the policy lists no 'mx' hosts".to_string());
                }
                for target in p.targets.iter().filter(|t| t.rtype == "MX") {
                    if !sts
                        .mx_patterns
                        .iter()
                        .any(|pat| sts_pattern_matches(pat, &target.target))
                    {
                        problems.push(format!(
                            "mail server {} is not covered by the policy's mx lines",
                            target.target
                        ));
                    }
                }
            }
        }
        (Some(status), None) => {
            problems.push(format!("the policy file request returned HTTP {status}"))
        }
        (None, None) => problems.push("the policy file could not be fetched".to_string()),
    }
    if problems.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        "POL-04",
        Severity::Warning,
        &obs.zone,
        format!(
            "{} publishes an MTA-STS record but its policy is unusable",
            obs.zone
        ),
        Evidence::MtaStsProblem {
            record: sts.record.clone(),
            policy_url: sts.policy_url.clone(),
            problems,
        },
    )]
}

fn resolves(t: &TargetResolution) -> bool {
    t.lookup.exists() || t.has_ipv6_only
}

/// POL-05: a mail exchanger is an alias, or has no address.
pub fn pol_05_mx_target(obs: &ZoneObservation) -> Vec<Finding> {
    let mut findings = Vec::new();
    for t in policy(obs).iter().flat_map(|p| &p.targets) {
        if t.rtype != "MX"
            || t.lookup.status == "failed"
            || t.lookup.unregistered_domain().is_some()
        {
            continue;
        }
        let problem = if t.lookup.cname.is_some() {
            "is a CNAME, which MX targets must not be"
        } else if !resolves(t) {
            "has no address"
        } else {
            continue;
        };
        findings.push(Finding::new(
            "POL-05",
            Severity::Warning,
            &t.target,
            format!("Mail server {} {problem}", t.target),
            Evidence::MailTargetProblem {
                target: t.target.clone(),
                problem: problem.to_string(),
                cname: t.lookup.cname.clone(),
            },
        ));
    }
    findings
}

fn dangling(
    check_id: &str,
    severity: Severity,
    summary: String,
    owner: &str,
    rtype: &str,
    target: &str,
    lookup: &Lookup,
) -> Finding {
    Finding::new(
        check_id,
        severity,
        owner,
        summary,
        Evidence::DanglingTarget {
            owner: owner.to_string(),
            rtype: rtype.to_string(),
            target: target.to_string(),
            said_by: lookup.enclosing.clone(),
            unregistered_domain: lookup.unregistered_domain(),
        },
    )
}

/// TKO-01: a CNAME points at a name that does not exist. If someone else
/// can create that name, they control what this hostname serves.
pub fn tko_01_dangling_cname(obs: &ZoneObservation) -> Vec<Finding> {
    policy(obs)
        .iter()
        .flat_map(|p| &p.targets)
        .filter(|t| t.rtype == "CNAME" && t.lookup.status == "nxdomain")
        .filter(|t| t.lookup.unregistered_domain().is_none())
        .map(|t| {
            dangling(
                "TKO-01",
                Severity::Warning,
                format!(
                    "{} is a CNAME to {}, which does not exist",
                    t.owner, t.target
                ),
                &t.owner,
                "CNAME",
                &t.target,
                &t.lookup,
            )
        })
        .collect()
}

/// TKO-03: a CNAME or MX points into a domain that is not registered.
/// Whoever registers it takes over the hostname, or the zone's mail.
pub fn tko_03_unregistered_target(obs: &ZoneObservation) -> Vec<Finding> {
    policy(obs)
        .iter()
        .flat_map(|p| &p.targets)
        .filter_map(|t| {
            let domain = t.lookup.unregistered_domain()?;
            Some(dangling(
                "TKO-03",
                Severity::Critical,
                format!(
                    "{} points at {}, but the domain {domain} is not registered",
                    t.owner, t.target
                ),
                &t.owner,
                &t.rtype,
                &t.target,
                &t.lookup,
            ))
        })
        .collect()
}

/// TKO-04: the SPF record includes or redirects to a domain that is not
/// registered. Whoever registers it can authorise mail for this zone.
pub fn tko_04_spf_unregistered(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(spf) = policy(obs).and_then(|p| p.spf.as_ref()) else {
        return Vec::new();
    };
    spf.lookups
        .iter()
        .filter_map(|l| {
            let lookup = l.target.as_ref()?;
            let domain = lookup.unregistered_domain()?;
            Some(dangling(
                "TKO-04",
                Severity::Critical,
                format!(
                    "The SPF record of {} uses {}, but the domain {domain} is not registered",
                    obs.zone, l.domain
                ),
                &obs.zone,
                &format!("SPF {}", l.mechanism),
                &l.domain,
                lookup,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::*;
    use crate::observe::{MtaSts, QType, SpfLookup, SpfObservation};

    fn lookup(name: &str, qtype: QType, status: &str, rdata: &[&str]) -> Lookup {
        Lookup {
            name: name.to_string(),
            qtype,
            status: status.to_string(),
            rdata: rdata.iter().map(|s| s.to_string()).collect(),
            cname: None,
            enclosing: None,
            error: None,
        }
    }

    fn nxdomain(name: &str, said_by: &str) -> Lookup {
        Lookup {
            enclosing: Some(said_by.to_string()),
            ..lookup(name, QType::A, "nxdomain", &[])
        }
    }

    fn target(owner: &str, rtype: &str, name: &str, lookup: Lookup) -> TargetResolution {
        TargetResolution {
            owner: owner.to_string(),
            rtype: rtype.to_string(),
            target: name.to_string(),
            lookup,
            has_ipv6_only: false,
        }
    }

    /// A zone with sound mail and policy records.
    fn sound() -> ZoneObservation {
        let mut obs = healthy();
        obs.policy = Some(PolicyObservation {
            apex_txt: lookup(ZONE, QType::Txt, "answer", &["\"v=spf1 mx -all\""]),
            dmarc: lookup(
                "_dmarc.example.test.",
                QType::Txt,
                "answer",
                &["\"v=DMARC1; p=reject; rua=mailto:d@example.test\""],
            ),
            caa: lookup(ZONE, QType::Caa, "answer", &["0 issue \"ca.example\""]),
            mx: lookup(ZONE, QType::Mx, "answer", &["10 mail.example.test."]),
            spf: Some(SpfObservation {
                records: vec!["v=spf1 mx -all".to_string()],
                lookups: vec![SpfLookup {
                    mechanism: "mx".to_string(),
                    domain: ZONE.to_string(),
                    depth: 0,
                    target: None,
                }],
                truncated: false,
            }),
            mta_sts: None,
            targets: vec![target(
                ZONE,
                "MX",
                "mail.example.test.",
                lookup("mail.example.test.", QType::A, "answer", &["192.0.2.25"]),
            )],
        });
        obs
    }

    fn pol(obs: &mut ZoneObservation) -> &mut PolicyObservation {
        obs.policy.as_mut().unwrap()
    }

    fn all(obs: &ZoneObservation) -> Vec<Finding> {
        [
            pol_01_spf(obs),
            pol_02_dmarc(obs),
            pol_03_caa(obs),
            pol_04_mta_sts(obs),
            pol_05_mx_target(obs),
            tko_01_dangling_cname(obs),
            tko_03_unregistered_target(obs),
            tko_04_spf_unregistered(obs),
        ]
        .concat()
    }

    #[test]
    fn a_sound_zone_is_clean() {
        assert_eq!(all(&sound()), []);
        // No policy data at all: nothing is claimed.
        assert_eq!(all(&healthy()), []);
    }

    #[test]
    fn unregistered_means_nxdomain_from_a_tld() {
        let gone = nxdomain("app.old-startup.example.", "example.");
        assert_eq!(
            gone.unregistered_domain().as_deref(),
            Some("old-startup.example.")
        );
        // The domain exists; only the name inside it is missing.
        let missing = nxdomain("app.host.example.", "host.example.");
        assert_eq!(missing.unregistered_domain(), None);
        // The root saying no is a missing TLD, not an unregistered domain.
        assert_eq!(nxdomain("x.nosuchtld.", ".").unregistered_domain(), None);
        assert_eq!(
            lookup("a.example.", QType::A, "nodata", &[]).unregistered_domain(),
            None
        );
    }

    #[test]
    fn pol_01_too_many_lookups_and_two_records() {
        let mut obs = sound();
        let spf = pol(&mut obs).spf.as_mut().unwrap();
        spf.lookups = (0..12)
            .map(|i| SpfLookup {
                mechanism: "include".to_string(),
                domain: format!("spf{i}.example."),
                depth: 0,
                target: None,
            })
            .collect();
        let findings = pol_01_spf(&obs);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].summary.contains("12 DNS lookups"),
            "{}",
            findings[0].summary
        );

        let mut obs = sound();
        pol(&mut obs)
            .spf
            .as_mut()
            .unwrap()
            .records
            .push("v=spf1 -all".to_string());
        let findings = pol_01_spf(&obs);
        assert!(findings[0].summary.contains("2 SPF records"));
        // Exactly ten lookups is allowed.
        let mut obs = sound();
        let spf = pol(&mut obs).spf.as_mut().unwrap();
        spf.lookups = vec![spf.lookups[0].clone(); 10];
        assert!(pol_01_spf(&obs).is_empty());
    }

    #[test]
    fn pol_02_missing_or_none() {
        let mut obs = sound();
        pol(&mut obs).dmarc = lookup("_dmarc.example.test.", QType::Txt, "nxdomain", &[]);
        let findings = pol_02_dmarc(&obs);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].summary.contains("no DMARC record"));
        assert_eq!(findings[0].severity, Severity::Notice);

        pol(&mut obs).dmarc = lookup(
            "_dmarc.example.test.",
            QType::Txt,
            "answer",
            &["\"v=DMARC1; p=none\""],
        );
        assert!(pol_02_dmarc(&obs)[0].summary.contains("p=none"));
        pol(&mut obs).dmarc = lookup(
            "_dmarc.example.test.",
            QType::Txt,
            "answer",
            &["\"v=DMARC1;p=quarantine\""],
        );
        assert!(pol_02_dmarc(&obs).is_empty());
        // A lookup that failed proves nothing.
        pol(&mut obs).dmarc = lookup("_dmarc.example.test.", QType::Txt, "failed", &[]);
        assert!(pol_02_dmarc(&obs).is_empty());
    }

    #[test]
    fn pol_03_no_caa() {
        let mut obs = sound();
        pol(&mut obs).caa = lookup(ZONE, QType::Caa, "nodata", &[]);
        assert_eq!(pol_03_caa(&obs).len(), 1);
        pol(&mut obs).caa = lookup(ZONE, QType::Caa, "failed", &[]);
        assert!(pol_03_caa(&obs).is_empty());
    }

    #[test]
    fn pol_04_policy_problems() {
        let sts = |status: Option<u16>, mode: &str, patterns: &[&str]| MtaSts {
            record: "v=STSv1; id=1".to_string(),
            policy_url: "https://mta-sts.example.test/.well-known/mta-sts.txt".to_string(),
            http_status: status,
            error: status.is_none().then(|| "connection refused".to_string()),
            version: Some("STSv1".to_string()),
            mode: Some(mode.to_string()),
            max_age: Some("86400".to_string()),
            mx_patterns: patterns.iter().map(|s| s.to_string()).collect(),
        };
        let mut obs = sound();
        pol(&mut obs).mta_sts = Some(sts(Some(200), "enforce", &["mail.example.test"]));
        assert!(pol_04_mta_sts(&obs).is_empty());
        pol(&mut obs).mta_sts = Some(sts(Some(200), "enforce", &["*.example.test"]));
        assert!(pol_04_mta_sts(&obs).is_empty());

        pol(&mut obs).mta_sts = Some(sts(Some(200), "enforce", &["mx.other.example"]));
        let findings = pol_04_mta_sts(&obs);
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            &findings[0].evidence,
            Evidence::MtaStsProblem { problems, .. } if problems[0].contains("mail.example.test. is not covered")
        ));
        pol(&mut obs).mta_sts = Some(sts(Some(404), "enforce", &[]));
        assert_eq!(pol_04_mta_sts(&obs).len(), 1);
        pol(&mut obs).mta_sts = Some(sts(None, "enforce", &[]));
        assert_eq!(pol_04_mta_sts(&obs).len(), 1);
        assert!(sts_pattern_matches("*.example.test", "a.example.test."));
        assert!(!sts_pattern_matches("*.example.test", "a.b.example.test."));
        assert!(!sts_pattern_matches("*.example.test", "example.test."));
    }

    #[test]
    fn pol_05_mx_alias_or_dead() {
        let mut obs = sound();
        pol(&mut obs).targets[0].lookup.cname = Some("real.example.net.".to_string());
        let findings = pol_05_mx_target(&obs);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].summary.contains("is a CNAME"));

        pol(&mut obs).targets[0].lookup = lookup("mail.example.test.", QType::A, "nodata", &[]);
        assert!(pol_05_mx_target(&obs)[0].summary.contains("has no address"));
        // An IPv6-only mail server is fine.
        pol(&mut obs).targets[0].has_ipv6_only = true;
        assert!(pol_05_mx_target(&obs).is_empty());
    }

    #[test]
    fn dangling_and_unregistered_targets() {
        let mut obs = sound();
        pol(&mut obs).targets = vec![
            target(
                "app.example.test.",
                "CNAME",
                "old.hosting.example.",
                nxdomain("old.hosting.example.", "hosting.example."),
            ),
            target(
                "shop.example.test.",
                "CNAME",
                "store.gone-startup.example.",
                nxdomain("store.gone-startup.example.", "example."),
            ),
            target(
                ZONE,
                "MX",
                "mx.gone-mail.example.",
                nxdomain("mx.gone-mail.example.", "example."),
            ),
        ];
        let findings = all(&obs);
        let ids: Vec<(&str, Severity, &str)> = findings
            .iter()
            .map(|f| (f.check_id.as_str(), f.severity, f.name.as_str()))
            .collect();
        assert_eq!(
            ids,
            [
                ("TKO-01", Severity::Warning, "app.example.test."),
                ("TKO-03", Severity::Critical, "shop.example.test."),
                ("TKO-03", Severity::Critical, ZONE),
            ]
        );
        assert!(
            findings[1]
                .summary
                .contains("gone-startup.example. is not registered")
        );
        // Each has its own identity across runs.
        let keys: std::collections::BTreeSet<String> =
            findings.iter().map(|f| f.fingerprint_key()).collect();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn tko_04_spf_include_of_an_unregistered_domain() {
        let mut obs = sound();
        pol(&mut obs).spf.as_mut().unwrap().lookups.push(SpfLookup {
            mechanism: "include".to_string(),
            domain: "_spf.old-esp.example.".to_string(),
            depth: 0,
            target: Some(nxdomain("_spf.old-esp.example.", "example.")),
        });
        let findings = tko_04_spf_unregistered(&obs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(
            findings[0]
                .summary
                .contains("old-esp.example. is not registered")
        );
    }
}
