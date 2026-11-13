//! Alerts: what to say when a zone changes, and where to send it.
//!
//! An alert is composed only when something changed state: a finding opened
//! or resolved, records changed, or the delegation changed. A finding that
//! stays open does not alert again. Composing is a pure function; sending
//! is the only I/O here.

use serde::Serialize;

use crate::checks::Severity;
use crate::config::{AlertsConfig, EmailConfig};
use crate::diff::{ChangeKind, DiffReport, StoredFinding};
use crate::runner::RunOutcome;

/// One message about one run of one zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    pub zone: String,
    pub run: i64,
    /// The most severe thing in the alert.
    pub severity: Severity,
    pub title: String,
    /// Plain text, one item per line.
    pub text: String,
    pub findings_opened: Vec<StoredFinding>,
    pub findings_resolved: Vec<StoredFinding>,
    /// Record and delegation changes, one line each.
    pub changes: Vec<String>,
}

fn finding_line(verb: &str, f: &StoredFinding) -> String {
    format!(
        "{verb} {} ({}) {}",
        f.check_id,
        f.severity.as_str(),
        f.summary
    )
}

fn change_lines(diff: &DiffReport) -> Vec<String> {
    let mut lines = Vec::new();
    for c in &diff.changes {
        let mut line = format!(
            "{} {} {}",
            c.kind.as_str().to_uppercase(),
            c.name,
            c.rtype.as_str()
        );
        if c.kind == ChangeKind::Ttl {
            let join = |v: &[u32]| v.iter().map(u32::to_string).collect::<Vec<_>>().join(", ");
            line.push_str(&format!(
                ": ttl {} -> {}",
                join(&c.ttl_before),
                join(&c.ttl_after)
            ));
        } else {
            for v in &c.removed {
                line.push_str(&format!("  - {v}"));
            }
            for v in &c.added {
                line.push_str(&format!("  + {v}"));
            }
            if c.all_servers {
                line.push_str("  (every nameserver)");
            } else {
                let servers: Vec<String> = c
                    .servers
                    .iter()
                    .map(|s| format!("{} {}", s.ns_name, s.address))
                    .collect();
                line.push_str(&format!("  (only on {})", servers.join(", ")));
            }
        }
        lines.push(line);
    }
    if let Some(d) = &diff.delegation {
        for ns in &d.ns_removed {
            lines.push(format!("DELEGATION - NS {ns}"));
        }
        for ns in &d.ns_added {
            lines.push(format!("DELEGATION + NS {ns}"));
        }
        for g in &d.glue_removed {
            lines.push(format!("DELEGATION - glue {} {}", g.name, g.address));
        }
        for g in &d.glue_added {
            lines.push(format!("DELEGATION + glue {} {}", g.name, g.address));
        }
    }
    lines
}

/// Decide whether a run is worth an alert, and write it.
///
/// For the first run of a zone every finding counts as newly opened.
pub fn compose(outcome: &RunOutcome) -> Option<Alert> {
    let zone = outcome.report.zone.clone();
    let (opened, resolved, changes) = match &outcome.diff {
        Some(diff) => (
            diff.findings_opened.clone(),
            diff.findings_resolved.clone(),
            change_lines(diff),
        ),
        None => {
            let opened: Vec<StoredFinding> = outcome
                .report
                .findings
                .iter()
                .filter(|f| f.severity != Severity::Info)
                .map(|f| StoredFinding {
                    severity: f.severity,
                    check_id: f.check_id.clone(),
                    name: f.name.clone(),
                    summary: f.summary.clone(),
                    fingerprint: crate::store::fingerprint(f),
                })
                .collect();
            (opened, Vec::new(), Vec::new())
        }
    };
    if opened.is_empty() && resolved.is_empty() && changes.is_empty() {
        return None;
    }

    let severity = opened
        .iter()
        .map(|f| f.severity)
        .min()
        .unwrap_or(if changes.is_empty() {
            Severity::Info
        } else {
            Severity::Notice
        });
    let mut parts = Vec::new();
    let plural = |n: usize, one: &str, many: &str| {
        if n == 1 {
            format!("1 {one}")
        } else {
            format!("{n} {many}")
        }
    };
    if !opened.is_empty() {
        parts.push(plural(opened.len(), "new finding", "new findings"));
    }
    if !resolved.is_empty() {
        parts.push(format!("{} resolved", resolved.len()));
    }
    if !changes.is_empty() {
        parts.push(plural(changes.len(), "change", "changes"));
    }
    let title = format!("zoneblick: {zone} {}", parts.join(", "));

    let mut lines = vec![format!("{zone} run #{}", outcome.run_id)];
    lines.extend(opened.iter().map(|f| finding_line("OPENED", f)));
    lines.extend(resolved.iter().map(|f| finding_line("RESOLVED", f)));
    lines.extend(changes.iter().cloned());

    Some(Alert {
        zone,
        run: outcome.run_id,
        severity,
        title,
        text: lines.join("\n"),
        findings_opened: opened,
        findings_resolved: resolved,
        changes,
    })
}

/// Send an alert to every configured sink. Returns one result per sink; a
/// failing sink does not stop the others.
pub async fn send(
    alert: &Alert,
    config: &AlertsConfig,
    http: &reqwest::Client,
) -> Vec<(&'static str, Result<(), String>)> {
    let mut results = Vec::new();
    if let Some(webhook) = &config.webhook {
        let result = http
            .post(&webhook.url)
            .json(alert)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map(|_| ())
            .map_err(|e| e.to_string());
        results.push(("webhook", result));
    }
    if let Some(ntfy) = &config.ntfy {
        let priority = match alert.severity {
            Severity::Critical => "5",
            Severity::Warning => "4",
            _ => "3",
        };
        let mut request = http
            .post(&ntfy.url)
            .header("Title", &alert.title)
            .header("Priority", priority)
            .header("Tags", "dns")
            .body(alert.text.clone());
        if let Some(token) = &ntfy.token {
            request = request.bearer_auth(token);
        }
        let result = request
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map(|_| ())
            .map_err(|e| e.to_string());
        results.push(("ntfy", result));
    }
    if let Some(email) = &config.email {
        results.push(("email", send_email(alert, email).await));
    }
    results
}

async fn send_email(alert: &Alert, config: &EmailConfig) -> Result<(), String> {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    let message = Message::builder()
        .from(
            config
                .from
                .parse()
                .map_err(|e| format!("from address: {e}"))?,
        )
        .to(config.to.parse().map_err(|e| format!("to address: {e}"))?)
        .subject(alert.title.clone())
        .header(ContentType::TEXT_PLAIN)
        .body(alert.text.clone())
        .map_err(|e| e.to_string())?;

    let builder = match config.tls.as_str() {
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host),
        "none" => Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(
            &config.smtp_host,
        )),
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host),
    }
    .map_err(|e| e.to_string())?;
    let mut builder = builder.port(config.smtp_port);

    let password = match (&config.password, &config.password_file) {
        (Some(p), _) => Some(p.clone()),
        (None, Some(path)) => Some(
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?
                .trim()
                .to_string(),
        ),
        (None, None) => None,
    };
    if let (Some(user), Some(password)) = (&config.username, password) {
        builder = builder.credentials(Credentials::new(user.clone(), password));
    }
    builder
        .build()
        .send(message)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::run_all;
    use crate::checks::testkit::*;
    use crate::output::Report;
    use crate::runner::store_observation;
    use crate::store::Store;

    fn outcome_of(store: &mut Store, obs: crate::observe::ZoneObservation) -> RunOutcome {
        let at = obs.started_at_unix;
        store_observation(store, obs, vec![], 1, at, "test", &[]).unwrap()
    }

    #[test]
    fn a_clean_first_run_is_silent() {
        let mut store = Store::open_in_memory().unwrap();
        assert_eq!(compose(&outcome_of(&mut store, healthy())), None);
    }

    #[test]
    fn alerts_fire_on_state_changes_only() {
        let mut store = Store::open_in_memory().unwrap();
        let clean = |at: u64| {
            let mut o = healthy();
            o.started_at_unix = at;
            o
        };
        let broken = |at: u64| {
            let mut o = clean(at);
            set_serial(&mut o, V4_B, 43);
            o
        };
        assert_eq!(compose(&outcome_of(&mut store, clean(1))), None);

        let alert = compose(&outcome_of(&mut store, broken(2))).unwrap();
        assert_eq!(alert.severity, Severity::Warning);
        assert_eq!(alert.title, "zoneblick: example.test. 1 new finding");
        assert!(
            alert.text.contains("OPENED CON-01 (warning)"),
            "{}",
            alert.text
        );
        assert_eq!(alert.run, 2);

        // Still broken: nothing new to say.
        assert_eq!(compose(&outcome_of(&mut store, broken(3))), None);

        let alert = compose(&outcome_of(&mut store, clean(4))).unwrap();
        assert_eq!(alert.title, "zoneblick: example.test. 1 resolved");
        assert_eq!(alert.severity, Severity::Info);
        assert!(alert.text.contains("RESOLVED CON-01"));
    }

    #[test]
    fn a_first_run_with_findings_alerts() {
        let mut store = Store::open_in_memory().unwrap();
        let mut obs = healthy();
        set_serial(&mut obs, V4_B, 43);
        let findings = run_all(&obs);
        assert_eq!(Report::new(obs.clone(), findings).findings.len(), 1);
        let alert = compose(&outcome_of(&mut store, obs)).unwrap();
        assert_eq!(alert.findings_opened.len(), 1);
    }

    #[test]
    fn the_webhook_body_is_json_with_text() {
        let alert = Alert {
            zone: "example.test.".to_string(),
            run: 7,
            severity: Severity::Critical,
            title: "t".to_string(),
            text: "line one\nline two".to_string(),
            findings_opened: vec![],
            findings_resolved: vec![],
            changes: vec!["MODIFIED www.example.test. A".to_string()],
        };
        let v = serde_json::to_value(&alert).unwrap();
        assert_eq!(v["severity"], "critical");
        assert_eq!(v["text"], "line one\nline two");
        assert_eq!(v["changes"][0], "MODIFIED www.example.test. A");
    }
}
