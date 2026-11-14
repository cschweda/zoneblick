//! The registration checks (`REG`): expiry, registry holds, the transfer
//! lock, and whether the registry lists the nameservers the parent zone
//! delegates to. They read the RDAP answer a deep run collects.

use super::{Evidence, Finding, Severity};
use crate::observe::{Registration, ZoneObservation};
use crate::output::utc;

/// A registration that ends within this many days is reported.
const EXPIRY_WARNING_DAYS: i64 = 30;
/// ... and is critical within this many.
const EXPIRY_CRITICAL_DAYS: i64 = 7;

fn registration(obs: &ZoneObservation) -> Option<&Registration> {
    obs.deep
        .as_ref()?
        .registration
        .as_ref()
        .filter(|r| r.error.is_none())
}

fn details(r: &Registration) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(registrar) = &r.registrar {
        out.push(format!("registrar: {registrar}"));
    }
    if let Some(at) = r.expires_unix {
        out.push(format!("expires: {}", utc(at)));
    }
    if !r.status.is_empty() {
        out.push(format!("status: {}", r.status.join(", ")));
    }
    if let Some(url) = &r.url {
        out.push(format!("source: {url}"));
    }
    out
}

fn finding(check_id: &str, severity: Severity, r: &Registration, summary: String) -> Finding {
    Finding::new(
        check_id,
        severity,
        &r.domain,
        summary,
        Evidence::ZoneDetail {
            details: details(r),
        },
    )
}

/// REG-01: the registration has run out, or runs out soon.
pub fn reg_01_expiry(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(r) = registration(obs) else {
        return Vec::new();
    };
    let Some(expires) = r.expires_unix else {
        return Vec::new();
    };
    let seconds_left = expires as i64 - obs.started_at_unix as i64;
    let days = seconds_left.div_euclid(86_400);
    if days > EXPIRY_WARNING_DAYS {
        return Vec::new();
    }
    let (severity, summary) = if seconds_left <= 0 {
        (
            Severity::Critical,
            format!(
                "the registration of {} ran out on {}",
                r.domain,
                utc(expires)
            ),
        )
    } else {
        let severity = if days <= EXPIRY_CRITICAL_DAYS {
            Severity::Critical
        } else {
            Severity::Warning
        };
        let when = match days {
            0 => "in less than a day".to_string(),
            1 => "in 1 day".to_string(),
            n => format!("in {n} days"),
        };
        (
            severity,
            format!("the registration of {} runs out {when}", r.domain),
        )
    };
    vec![finding("REG-01", severity, r, summary)]
}

/// REG-02: nothing stops the domain from being transferred to another
/// registrar.
pub fn reg_02_transfer_lock(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(r) = registration(obs) else {
        return Vec::new();
    };
    // No status list at all says nothing either way.
    if r.status.is_empty() || r.status.iter().any(|s| s.contains("transfer prohibited")) {
        return Vec::new();
    }
    vec![finding(
        "REG-02",
        Severity::Notice,
        r,
        format!(
            "{} has no transfer lock: the registry would accept a transfer to another registrar",
            r.domain
        ),
    )]
}

/// REG-03: the registry has taken the domain out of the DNS, or is about
/// to delete it.
pub fn reg_03_hold(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(r) = registration(obs) else {
        return Vec::new();
    };
    let bad: Vec<&str> = r
        .status
        .iter()
        .map(String::as_str)
        .filter(|s| {
            s.ends_with(" hold")
                || matches!(*s, "redemption period" | "pending delete" | "inactive")
        })
        .collect();
    if bad.is_empty() {
        return Vec::new();
    }
    vec![finding(
        "REG-03",
        Severity::Critical,
        r,
        format!("the registry marks {} as: {}", r.domain, bad.join(", ")),
    )]
}

/// REG-04: the registry's record lists other nameservers than the parent
/// zone hands out. Only compared when the zone is the registered domain.
pub fn reg_04_nameservers(obs: &ZoneObservation) -> Vec<Finding> {
    let Some(r) = registration(obs) else {
        return Vec::new();
    };
    let Some(parent) = obs.parent().filter(|_| r.domain == obs.zone) else {
        return Vec::new();
    };
    if r.nameservers.is_empty() || parent.ns.is_empty() {
        return Vec::new();
    }
    let mut delegated = parent.ns.clone();
    delegated.sort();
    if delegated == r.nameservers {
        return Vec::new();
    }
    let mut details = vec![
        format!("registry record: {}", r.nameservers.join(", ")),
        format!("parent zone:     {}", delegated.join(", ")),
    ];
    details.extend(r.url.iter().map(|u| format!("source: {u}")));
    vec![Finding::new(
        "REG-04",
        Severity::Notice,
        &r.domain,
        format!(
            "the registry's record of {} lists other nameservers than the parent zone serves",
            r.domain
        ),
        Evidence::ZoneDetail { details },
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::*;
    use crate::observe::DeepObservation;

    const DAY: u64 = 86_400;

    fn with(r: Registration) -> ZoneObservation {
        let mut obs = healthy();
        obs.deep = Some(DeepObservation {
            servers: Vec::new(),
            mname: None,
            rname_domain: None,
            rname_mx: None,
            rname_address: None,
            previous_dnskeys: None,
            origins: Vec::new(),
            chain: Vec::new(),
            record_signatures: Vec::new(),
            mail_tls: Vec::new(),
            registration: Some(r),
        });
        obs
    }

    fn locked(obs: &ZoneObservation, expires_in: i64) -> Registration {
        let mut ns = obs.parent().unwrap().ns.clone();
        ns.sort();
        Registration {
            domain: obs.zone.clone(),
            url: Some("https://rdap.example/domain/example.test".to_string()),
            status: vec!["client transfer prohibited".to_string()],
            expires_unix: Some((obs.started_at_unix as i64 + expires_in) as u64),
            registrar: Some("Example Registrar".to_string()),
            nameservers: ns,
            error: None,
        }
    }

    fn ids(obs: &ZoneObservation) -> Vec<(String, Severity)> {
        [
            reg_01_expiry(obs),
            reg_02_transfer_lock(obs),
            reg_03_hold(obs),
            reg_04_nameservers(obs),
        ]
        .into_iter()
        .flatten()
        .map(|f| (f.check_id, f.severity))
        .collect()
    }

    #[test]
    fn a_healthy_registration_is_silent() {
        let base = healthy();
        assert!(ids(&with(locked(&base, 200 * DAY as i64))).is_empty());
        // No deep run, or a failed lookup: nothing to say.
        assert!(ids(&base).is_empty());
        let mut failed = locked(&base, -5);
        failed.error = Some("RDAP answered HTTP 500".to_string());
        assert!(ids(&with(failed)).is_empty());
    }

    #[test]
    fn expiry_is_graded() {
        let base = healthy();
        let at = |secs: i64| reg_01_expiry(&with(locked(&base, secs)));
        assert!(at(31 * DAY as i64).is_empty());
        let soon = at(20 * DAY as i64 + 5);
        assert_eq!(soon[0].severity, Severity::Warning);
        assert!(
            soon[0].summary.ends_with("runs out in 20 days"),
            "{}",
            soon[0].summary
        );
        assert_eq!(at(3 * DAY as i64)[0].severity, Severity::Critical);
        assert!(at(3600)[0].summary.ends_with("in less than a day"));
        let gone = at(-(DAY as i64));
        assert_eq!(gone[0].severity, Severity::Critical);
        assert!(
            gone[0].summary.contains("ran out on"),
            "{}",
            gone[0].summary
        );
    }

    #[test]
    fn locks_holds_and_nameservers() {
        let base = healthy();
        let mut r = locked(&base, 200 * DAY as i64);
        r.status = vec!["active".to_string()];
        assert_eq!(
            ids(&with(r.clone())),
            [("REG-02".to_string(), Severity::Notice)]
        );
        r.status = vec![
            "client hold".to_string(),
            "server transfer prohibited".to_string(),
        ];
        assert_eq!(
            ids(&with(r.clone())),
            [("REG-03".to_string(), Severity::Critical)]
        );
        r.status = vec!["client transfer prohibited".to_string()];
        r.nameservers = vec!["ns1.elsewhere.test.".to_string()];
        let found = with(r.clone());
        assert_eq!(ids(&found), [("REG-04".to_string(), Severity::Notice)]);
        // A zone below the registered domain is not compared.
        r.domain = "test.".to_string();
        assert!(ids(&with(r)).is_empty());
    }
}
