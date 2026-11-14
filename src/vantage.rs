//! Vantage points: other zoneblick daemons, somewhere else on the
//! network, whose view of a zone is compared with this one's. A nameserver
//! that answers from one place and not from another, or an anycast node
//! that serves old data to one region, only shows up this way.
//!
//! A vantage point is asked over its ordinary API for a short report of
//! its latest stored run. Nothing new runs on it.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::observe::{RecordObservation, ServerProbe};

/// One record set as a vantage point saw it: the union over the
/// nameservers that answered it with authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VantageSet {
    pub name: String,
    pub rtype: String,
    pub rdata: Vec<String>,
}

/// Whether one nameserver address answered a vantage point.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VantageServer {
    pub ns_name: String,
    pub address: IpAddr,
    pub answered: bool,
}

/// What a daemon reports about its latest run of a zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VantageReport {
    pub zone: String,
    pub run_started_unix: u64,
    pub sets: Vec<VantageSet>,
    pub servers: Vec<VantageServer>,
}

/// A vantage point's report as fetched for one run, or why there is none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VantageView {
    /// The vantage point's name in the config file.
    pub name: String,
    pub report: Option<VantageReport>,
    pub error: Option<String>,
}

/// The record sets of a run, each as the union over the servers that
/// answered with authority. SOA is left out: its serial moves by itself.
pub fn sets_of(records: &[RecordObservation]) -> Vec<VantageSet> {
    let mut sets: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for rec in records {
        if rec.qtype == crate::observe::QType::Soa {
            continue;
        }
        if let Some(answer) = rec.outcome.answer().filter(|a| a.authoritative) {
            sets.entry((rec.name.clone(), rec.qtype.as_str().to_string()))
                .or_default()
                .extend(answer.rdata.iter().cloned());
        }
    }
    sets.into_iter()
        .map(|((name, rtype), rdata)| VantageSet {
            name,
            rtype,
            rdata: rdata.into_iter().collect(),
        })
        .collect()
}

/// Which nameserver addresses answered at least one probe of a run.
pub fn servers_of(probes: &[ServerProbe]) -> Vec<VantageServer> {
    let mut servers: BTreeMap<(String, IpAddr), bool> = BTreeMap::new();
    for p in probes {
        *servers.entry((p.ns_name.clone(), p.address)).or_default() |=
            p.outcome.response().is_some();
    }
    servers
        .into_iter()
        .map(|((ns_name, address), answered)| VantageServer {
            ns_name,
            address,
            answered,
        })
        .collect()
}

/// A report may be at most this large.
const REPORT_LIMIT: usize = 8 * 1024 * 1024;

/// Ask one vantage point for its report on a zone.
pub async fn fetch(
    http: &reqwest::Client,
    name: &str,
    url: &str,
    token: Option<&str>,
    zone: &str,
) -> VantageView {
    let failed = |error: String| VantageView {
        name: name.to_string(),
        report: None,
        error: Some(error),
    };
    let address = format!(
        "{}/api/v1/vantage?zone={}",
        url.trim_end_matches('/'),
        zone.trim_end_matches('.')
    );
    let mut request = http.get(&address);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let mut response = match request.send().await {
        Ok(r) => r,
        // The address may hold nothing secret, but keep it out anyway.
        Err(e) => return failed(e.without_url().to_string()),
    };
    let status = response.status().as_u16();
    if status != 200 {
        return failed(match status {
            401 => "the vantage point refused the token".to_string(),
            404 => "the vantage point has no run of this zone".to_string(),
            n => format!("the vantage point answered HTTP {n}"),
        });
    }
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > REPORT_LIMIT {
                    return failed("the report is too large".to_string());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => return failed(e.without_url().to_string()),
        }
    }
    match serde_json::from_slice::<VantageReport>(&body) {
        Ok(report) if report.zone == zone => VantageView {
            name: name.to_string(),
            report: Some(report),
            error: None,
        },
        Ok(_) => failed("the report is for another zone".to_string()),
        Err(e) => failed(format!("the report cannot be read: {e}")),
    }
}
