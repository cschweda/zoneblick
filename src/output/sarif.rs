//! SARIF 2.1.0 output, the format code-scanning tools read. Each finding
//! is one result; each check that fired is one rule.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::Report;
use crate::checks::{CATALOG, Evidence, Severity};

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "error",
        Severity::Warning => "warning",
        Severity::Notice | Severity::Info => "note",
    }
}

/// The report as a SARIF document. A result about a declared zone file
/// points at that file; the others name only the DNS name.
pub fn document(report: &Report) -> Value {
    let fired: BTreeSet<&str> = report
        .findings
        .iter()
        .map(|f| f.check_id.as_str())
        .collect();
    let rules: Vec<Value> = CATALOG
        .iter()
        .filter(|c| fired.contains(c.id))
        .map(|c| {
            json!({
                "id": c.id,
                "name": c.id,
                "shortDescription": { "text": c.title },
                "defaultConfiguration": { "level": level(c.severity) },
                "helpUri": "https://zoneblick.com/#checks",
            })
        })
        .collect();
    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let mut location = json!({
                "logicalLocations": [{ "fullyQualifiedName": f.name, "kind": "resource" }],
            });
            if let Evidence::Drift { source, .. } = &f.evidence {
                location["physicalLocation"] = json!({
                    "artifactLocation": { "uri": source.replace('\\', "/") },
                });
            }
            json!({
                "ruleId": f.check_id,
                "level": level(f.severity),
                "message": { "text": f.summary },
                "locations": [location],
                "partialFingerprints": { "zoneblick/v1": crate::store::fingerprint(f) },
                "properties": { "severity": f.severity.as_str(), "zone": report.zone },
            })
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "zoneblick",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://zoneblick.com",
                "rules": rules,
            }},
            "results": results,
        }],
    })
}

pub fn render(report: &Report) -> String {
    super::json::render(&document(report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::run_all;
    use crate::checks::testkit::*;

    #[test]
    fn findings_become_results_with_their_rules() {
        let mut obs = healthy();
        set_serial(&mut obs, V4_B, 43);
        let findings = run_all(&obs);
        let doc = document(&Report::new(obs, findings));
        assert_eq!(doc["version"], "2.1.0");
        let run = &doc["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "zoneblick");
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 1);
        assert_eq!(run["tool"]["driver"]["rules"][0]["id"], "CON-01");
        let result = &run["results"][0];
        assert_eq!(result["ruleId"], "CON-01");
        assert_eq!(result["level"], "warning");
        assert_eq!(
            result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"],
            "example.test."
        );
        assert_eq!(
            result["partialFingerprints"]["zoneblick/v1"]
                .as_str()
                .unwrap()
                .len(),
            32
        );

        let clean = document(&Report::new(healthy(), vec![]));
        assert_eq!(clean["runs"][0]["results"], json!([]));
    }
}
