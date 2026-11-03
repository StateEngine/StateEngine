//! The stop reply precedes native close. Final release is witnessed by its caller.
use super::*;
use se_core::store_error::store_error;
use se_host::EndpointRecord;
use se_store::StateFiles;
use se_types::Read;
use std::{fs::TryLockError, time::Duration};

pub(super) fn report(
    files: &Files,
    endpoint: &EndpointRecord,
    key: &se_types::IdempotencyKey,
    bound: &Deadline,
) -> Result<Option<se_host::client::closure::RuntimeClosure>> {
    loop {
        bound.remaining()?;
        // Observe exit before reading: a publication followed by exit between
        // these samples must not turn a completed per-agent report into None.
        let already_exited =
            endpoint.kind == se_host::HostKind::Standalone && exited(endpoint, bound)?;
        if let Some(record) = se_host::client::closure::read(files, files.0.root())?
            && record.matches(endpoint, key)
        {
            return Ok(Some(record));
        }
        // Legacy standalone hosts have no close-receipt producer. Once the
        // exact owner exited it cannot publish later; final OS checks still apply.
        if already_exited {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(10).min(bound.remaining()?));
    }
}
pub(super) fn witness(
    files: &Files,
    endpoint: &EndpointRecord,
    key: &se_types::IdempotencyKey,
    bound: &Deadline,
) -> Result<()> {
    let fields = endpoint.epoch.owner.fields();
    let current = se_proc::current_runtime_identity(fields.machine.clone())
        .map_err(|e| scope::unreadable("shutdown native boot", &format!("{e:?}")))?;
    if current.boot_id != fields.boot {
        return Err(scope::unreadable(
            "shutdown native boot",
            "native boot changed since authenticated stop admission",
        ));
    }
    let lock = scope::require_present(
        files
            .readback(&files.0.root().join("runtime.lock"))
            .map_err(|e| store_error(&e))?,
        "shutdown runtime lease",
        "Preserve the runtime lock and reread this same data home's shutdown state.",
    )?;
    loop {
        bound.remaining()?;
        if endpoint.kind != se_host::HostKind::Standalone || exited(endpoint, bound)? {
            match lock.try_lock() {
                Ok(()) => {
                    // Hold the observed exclusive lock while checking publication:
                    // a racing successor cannot be mistaken for this old owner.
                    match execute::endpoint(files)? {
                        Read::Absent { .. } => (),
                        _ => Err(scope::unreadable(
                            "shutdown endpoint retirement",
                            "the authenticated runtime's protected endpoint is still present under the exclusive lease",
                        ))?,
                    }
                    match se_host::client::closure::read(files, files.0.root())? {
                        Some(record)
                            if record.matches(endpoint, key) && record.resources_closed =>
                        {
                            return Ok(());
                        }
                        value
                            if endpoint.kind == se_host::HostKind::Standalone
                                && value
                                    .as_ref()
                                    .is_none_or(|record| !record.matches(endpoint, key)) =>
                        {
                            return Ok(());
                        }
                        _ => {
                            return Err(scope::unreadable(
                                "runtime close receipt",
                                "the original stop key, epoch and generation have no successful protected post-transport receipt; the lease and endpoint observations alone do not prove embedded closure",
                            ));
                        }
                    }
                }
                Err(TryLockError::WouldBlock) => (),
                Err(TryLockError::Error(error)) => {
                    return Err(
                        scope::unreadable("shutdown runtime lease", &error.to_string())
                            .with_cause(error),
                    );
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10).min(bound.remaining()?));
    }
}

fn exited(endpoint: &EndpointRecord, bound: &Deadline) -> Result<bool> {
    bound.remaining()?;
    let fields = endpoint.epoch.owner.fields();
    let current = se_proc::current_runtime_identity(fields.machine.clone())
        .map_err(|e| scope::unreadable("shutdown native boot", &format!("{e:?}")))?;
    if current.boot_id != fields.boot {
        return Err(scope::unreadable(
            "shutdown native boot",
            "native boot changed since authenticated stop admission",
        ));
    }
    let observed =
        se_proc::read_process(fields.machine.clone(), se_proc::ProcessId(fields.pid.get()))
            .map_err(|e| scope::unreadable("shutdown exact native owner", &format!("{e:?}")))?;
    Ok(match observed {
        se_proc::ProcessRead::Absent { .. } | se_proc::ProcessRead::ExitedRecord { .. } => true,
        se_proc::ProcessRead::Present(value) => {
            let same_start = match (&value.identity.start, &fields.started) {
                (
                    se_proc::StartIdentity::Linux { start_ticks: a },
                    se_types::StartIdentity::Linux { start_ticks: b },
                ) => a == b,
                (
                    se_proc::StartIdentity::Windows {
                        creation_filetime: a,
                    },
                    se_types::StartIdentity::Windows {
                        creation_filetime: b,
                    },
                ) => *a == b.get(),
                _ => {
                    return Err(scope::unreadable(
                        "shutdown exact native owner",
                        "unsupported native start identity",
                    ));
                }
            };
            !same_start
                || matches!(
                    value.state,
                    se_proc::NativeState::Exited | se_proc::NativeState::ExitedAwaitingReap
                )
        }
    })
}
