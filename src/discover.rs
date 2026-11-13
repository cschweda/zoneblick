//! Discovery: finding names in a zone that nobody listed.
//!
//! One source so far: Certificate Transparency logs, read through the
//! public search at crt.sh. Every publicly trusted certificate is logged,
//! so the names on a zone's certificates are a good list of its hosts.
//! The query tells crt.sh which zone is being looked at, so discovery is
//! off unless asked for.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::observe::is_ancestor_or_equal;
use crate::resolver::{Client, HttpOutcome, normalise_zone};

/// At most this many discovered names are added per zone.
pub const CT_MAX_NAMES: usize = 200;
/// crt.sh answers can be large, and are often slow.
const CT_BODY_LIMIT: usize = 8 * 1024 * 1024;
const CT_TIMEOUT: Duration = Duration::from_secs(45);

/// The crt.sh search for every unexpired certificate under a zone.
pub fn ct_url(zone: &str) -> String {
    let host = zone.trim_end_matches('.');
    format!("https://crt.sh/?q=%25.{host}&output=json&exclude=expired&deduplicate=Y")
}

/// Read one JSON string starting after its opening quote.
fn json_string(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = text.chars();
    loop {
        match chars.next()? {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                'n' | 'r' | 't' => out.push('\n'),
                other => out.push(other),
            },
            c => out.push(c),
        }
    }
}

/// The names inside `zone` that a crt.sh JSON answer mentions, sorted.
/// Wildcards, the apex and anything that is not a plain hostname are left
/// out. The scan does not need the whole document, so a cut-off answer
/// still gives the names it holds.
pub fn parse_ct(zone: &str, body: &str) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for key in ["\"name_value\":\"", "\"common_name\":\""] {
        let mut rest = body;
        while let Some(at) = rest.find(key) {
            rest = &rest[at + key.len()..];
            let Some(value) = json_string(rest) else {
                break;
            };
            for line in value.lines() {
                let line = line.trim().to_ascii_lowercase();
                let plain = !line.is_empty()
                    && line.len() <= 253
                    && line
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
                if !plain {
                    continue;
                }
                if let Ok(name) = normalise_zone(&line)
                    && name != zone
                    && is_ancestor_or_equal(zone, &name)
                {
                    names.insert(name);
                }
            }
        }
    }
    names.into_iter().take(CT_MAX_NAMES).collect()
}

/// Ask crt.sh for the names on a zone's certificates.
pub async fn ct_names(client: &Client, zone: &str) -> Result<Vec<String>, String> {
    match client
        .http_get_with(&ct_url(zone), CT_BODY_LIMIT, CT_TIMEOUT)
        .await
    {
        HttpOutcome::Error { message } => Err(format!("crt.sh: {message}")),
        HttpOutcome::Response { status: 200, body } => Ok(parse_ct(zone, &body)),
        HttpOutcome::Response { status, .. } => Err(format!("crt.sh answered HTTP {status}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_read_from_a_crt_sh_answer() {
        let body = r#"[{"issuer_ca_id":1,"common_name":"www.example.org","name_value":"www.example.org\nexample.org\n*.example.org"},
            {"common_name":"Mail.Example.Org","name_value":"mail.example.org\nother.example.net\nbad name.example.org\nadmin@example.org"},
            {"common_name":"api.example.org","name_value":"api.exam"#;
        assert_eq!(
            parse_ct("example.org.", body),
            ["api.example.org.", "mail.example.org.", "www.example.org."]
        );
        assert!(parse_ct("example.org.", "not json at all").is_empty());
    }

    #[test]
    fn the_search_url_names_the_zone() {
        assert_eq!(
            ct_url("example.org."),
            "https://crt.sh/?q=%25.example.org&output=json&exclude=expired&deduplicate=Y"
        );
    }
}
