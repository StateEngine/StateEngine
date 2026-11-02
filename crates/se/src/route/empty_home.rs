//! Read-only exclusion for the two explicit post-remove operations. Holding
//! this file excludes a host and direct writers; callers hold the native
//! installation claim to exclude setup and uninstall before touching a key.
use super::files::Files;
use se_core::{scope, store_error::store_error};
use se_store::{Admission, ReadStore, Snapshot, StateFiles};
use se_types::{Result, SeError};
use std::{fs::File, num::NonZeroU32, time::Duration};

pub fn lock<R: ReadStore>(
    files: &Files,
    reader: &R,
    admission: &Admission,
    timeout: Duration,
) -> Result<File> {
    let mut options = super::execute::options();
    options.timeout = timeout;
    let bound = se_host::client::lease::Deadline::from_options(&options)?;
    let path = files.0.root().join("runtime.lock");
    let lock = scope::require_present(
        files.readback(&path).map_err(|e| store_error(&e))?,
        "runtime lock",
        "Restore the protected runtime lock before retrying explicit setup or removal.",
    )?;
    lock.try_lock().map_err(|error| {
        scope::unreadable(
            "empty-home exclusion",
            &format!("runtime or direct writer is active: {error}"),
        )
    })?;
    let mut admitted = admission.clone();
    admitted.scope = se_store::Scope::Registry;
    let mut snapshot = reader
        .snapshot(se_core::admission::read_scope(&admitted))
        .map_err(|e| store_error(&e))?;
    let projects = snapshot
        .projects(se_store::ReadBudget {
            page: se_types::PageRequest {
                after: None,
                limit: NonZeroU32::new(1)
                    .ok_or_else(|| SeError::invalid("project check", "positive bound"))?,
                max_bytes: NonZeroU32::new(64 * 1024)
                    .ok_or_else(|| SeError::invalid("project bytes", "positive bound"))?,
            },
            deadline: bound.remaining()?.min(Duration::from_secs(5)),
        })
        .map_err(|e| store_error(&e));
    let closed = snapshot.close().map_err(|e| store_error(&e));
    let projects = projects?;
    closed?;
    if !projects.items().is_empty() || !projects.window().complete() {
        return Err(scope::unreadable(
            "empty-home exclusion",
            "registered projects remain or their inventory is incomplete; the original credential must be restored rather than regenerated",
        ));
    }
    match reader.runtime_owner().map_err(|e| store_error(&e))? {
        se_types::Read::Present { value } => {
            super::process::witness_exit(&value.epoch.owner, &bound)?
        }
        se_types::Read::Absent { .. } => (),
        other => {
            scope::require_present(
                other,
                "empty-home prior runtime owner",
                "Restore the recorded runtime identity before declaring the home idle.",
            )?;
        }
    }
    Ok(lock)
}
