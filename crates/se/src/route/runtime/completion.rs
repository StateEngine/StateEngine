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
    let mut last_issue = None;
    loop {
        report_remaining(bound, last_issue.as_deref())?;
        // Observe exit before reading: a publication followed by exit between
        // these samples must not turn a completed per-agent report into None.
        let already_exited =
            endpoint.kind == se_host::HostKind::Standalone && exited(endpoint, bound)?;
        match se_host::client::closure::read(files, files.0.root()) {
            Ok(Some(record)) if record.matches(endpoint, key) => return Ok(Some(record)),
            Err(error) if already_exited => return Err(error),
            Err(error) => last_issue = Some(error.to_string()),
            _ => (),
        }
        // Legacy standalone hosts have no close-receipt producer. Once the
        // exact owner exited it cannot publish later; final OS checks still apply.
        if already_exited {
            return Ok(None);
        }
        std::thread::sleep(
            Duration::from_millis(10).min(report_remaining(bound, last_issue.as_deref())?),
        );
    }
}
fn report_remaining(bound: &Deadline, issue: Option<&str>) -> Result<Duration> {
    bound.remaining().map_err(|error| match issue {
        Some(issue) => scope::unreadable("runtime close receipt", &format!("Receipt remained unreadable while waiting for the original shutdown: {issue}; {error}")),
        None => error,
    })
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
    let mut last_read_failure = None;
    let observed = loop {
        bound.remaining().map_err(|deadline| {
            scope::unreadable(
                "shutdown exact native owner",
                &format!(
                    "No conclusive native observation within the original shutdown bound: {}; {deadline}",
                    last_read_failure.as_deref().unwrap_or("no completed observation")
                ),
            )
        })?;
        match se_proc::read_process_until(
            fields.machine.clone(),
            se_proc::ProcessId(fields.pid.get()),
            bound.at(),
        ) {
            Ok(observed) => break observed,
            Err(error) => {
                // A process may exit between the native reader's birth and
                // executable samples. Reobserve; unreadable is never absent.
                last_read_failure = Some(format!("{error:?}"));
                std::thread::sleep(
                    Duration::from_millis(10).min(bound.remaining().unwrap_or(Duration::ZERO)),
                );
            }
        }
    };
    Ok(match observed {
        se_proc::ProcessRead::Absent { .. } | se_proc::ProcessRead::ExitedRecord { .. } => true,
        se_proc::ProcessRead::Present(value) => {
            let same_start = process::same_start(&value.identity.start, &fields.started)
                .ok_or_else(|| {
                    scope::unreadable(
                        "shutdown exact native owner",
                        "unsupported native start identity",
                    )
                })?;
            !same_start
                || matches!(
                    value.state,
                    se_proc::NativeState::Exited | se_proc::NativeState::ExitedAwaitingReap
                )
        }
    })
}
