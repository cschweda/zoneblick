//! The run pipeline shared by `zoneblick run` and the daemon: check the
//! findings, store the snapshot, and compare with the previous run.

use crate::checks::run_all;
use crate::diff::{self, DiffReport};
use crate::observe::ZoneObservation;
use crate::output::Report;
use crate::store::{RunMeta, Store, StoreError};

/// A stored run and what changed since the one before it.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub run_id: i64,
    pub report: Report,
    /// `None` for the first stored run of the zone.
    pub diff: Option<DiffReport>,
    pub names: Vec<String>,
    pub queries: usize,
}

/// Run the checks over an observation, store it, and diff it against the
/// zone's previous stored run. `ignore` patterns apply to the diff only.
pub fn store_observation(
    store: &mut Store,
    obs: ZoneObservation,
    names: Vec<String>,
    queries: usize,
    finished_at_unix: u64,
    trigger: &str,
    ignore: &[String],
) -> Result<RunOutcome, StoreError> {
    let findings = run_all(&obs);
    let zone = obs.zone.clone();
    let meta = RunMeta {
        names: &names,
        finished_at_unix,
        queries,
        trigger,
    };
    let run_id = store.save_run(&obs, &findings, &meta)?;
    let diff = match store.pick_runs(&zone, None, Some(run_id)) {
        Ok((from, to)) => Some(diff::diff(
            &store.load_run(&zone, from)?,
            &store.load_run(&zone, to)?,
            ignore,
        )),
        Err(StoreError::NotEnoughRuns { .. }) => None,
        Err(e) => return Err(e),
    };
    Ok(RunOutcome {
        run_id,
        report: Report::new(obs, findings),
        diff,
        names,
        queries,
    })
}
