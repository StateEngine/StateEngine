//! An absent endpoint is only a hint. Exclude starts and writers, then prove
//! the prior host exited and no unresolved native custody remains in this home.
use super::super::{execute, files::Files, owner, process};
use se_core::{ops::*, scope, store_error::store_error};
use se_host::client::{ClientOptions, lease::Deadline};
use se_store::{ReadStore, StateFiles};
use se_types::{Read, Result};

pub(super) fn observe<R: ReadStore>(
    files: &Files,
    reader: &R,
    options: &ClientOptions,
) -> Result<AnyOutput> {
    let bound = Deadline::from_options(options)?;
    let lock = scope::require_present(
        files
            .readback(&files.0.root().join("runtime.lock"))
            .map_err(|error| store_error(&error))?,
        "already-down native exclusion",
        "Restore the protected runtime lock before retrying se down.",
    )?;
    lock.try_lock().map_err(|error| {
        scope::unreadable(
            "already-down native exclusion",
            &format!("The runtime or a direct writer still holds this home: {error}. Run se status for this home and retry se down after the current owner completes; the missing endpoint does not prove exit."),
        )
    })?;
    // The exclusive native lease prevents publication or a custody commit
    // between the fresh endpoint, complete inventory and process readbacks.
    match execute::endpoint(files)? {
        Read::Absent { .. } => (),
        _ => {
            return Err(scope::unreadable(
                "already-down endpoint readback",
                "The protected endpoint changed while acquiring exclusion. Run se status for this home and retry se down; its endpoint was preserved.",
            ));
        }
    }
    let mut budget = owner::budget()?;
    budget.deadline = budget.deadline.min(bound.remaining()?);
    let inventory = reader
        .owner_guard(files, budget)
        .map_err(|error| store_error(&error))?;
    if !inventory.processes.is_empty() {
        return Err(scope::unreadable(
            "already-down native custody",
            "Unresolved owned process or session cleanup remains in this home. Run se up to reconcile the retained custody, then se down; no process was declared stopped.",
        ));
    }
    match reader
        .runtime_owner()
        .map_err(|error| store_error(&error))?
    {
        Read::Present { value } => process::witness_exit(&value.epoch.owner, &bound)?,
        Read::Absent { .. } => (),
        other => {
            scope::require_present(
                other,
                "already-down prior host identity",
                "Restore access to this home's protected runtime owner before retrying se down.",
            )?;
        }
    }
    bound.remaining()?;
    Ok(RuntimeStop {
        complete: true,
        already_down: true,
        stops: Vec::new(),
        witness: Witness {
            state: WitnessState::Witnessed,
            method: "exclusive runtime lease, absent endpoint, complete empty unresolved custody and prior-host exit readback".into(),
            observed_at: receipt::timestamp(execute::now_us()?)?,
            detail: Some("Already down; no host was running. No process was stopped.".into()),
        },
    }
    .into())
}
