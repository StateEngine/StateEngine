//! Finish --all outside the writer: authenticated down, exact exit readback,
//! then digest-checked credential retirement under the exclusive runtime lock.
use super::{execute, files::Files};
use se_core::{ops::*, scope, store_error::store_error};
use se_host::{EndpointRecord, client::lease::Deadline};
use se_store::{Admission, ReadStore, Snapshot, StateFiles};
use se_types::{Read, Result, SeError};
use sha2::{Digest, Sha256};
use std::{num::NonZeroU32, time::Duration};

pub fn complete<R: ReadStore>(
    files: &Files,
    reader: &R,
    admission: &Admission,
    target: &EndpointRecord,
    mut output: AnyOutput,
    bound: &Deadline,
) -> AnyOutput {
    let AnyOutput::ProjectRemove(envelope) = &mut output else {
        return output;
    };
    let value = &mut envelope.value;
    if value.scope != "all" || target.kind != se_host::HostKind::Standalone {
        return output;
    }
    // A new project or any unsettled project effect must keep its host and key.
    if value
        .projects
        .iter()
        .any(|p| !matches!(p.outcome.as_str(), "removed" | "absent") || !p.remaining.is_empty())
    {
        return output;
    }
    if let Err(error) = finish(files, reader, admission, target, value, bound) {
        value.outcome = "partial".into();
        let witness = if value.runtime.action == "stopped" {
            &mut value.machine_credential.witness
        } else {
            &mut value.runtime.witness
        };
        witness.state = "unknown".into();
        witness.detail = Some(format!(
            "Removal effects above remain committed; outside completion is incomplete: {error}. Retry the same remove --all request key after reading status; the credential was not replaced."
        ));
    }
    output
}
fn finish<R: ReadStore>(
    files: &Files,
    reader: &R,
    admission: &Admission,
    target: &EndpointRecord,
    value: &mut RemoveResult,
    bound: &Deadline,
) -> Result<()> {
    bound.remaining()?;
    // Setup and uninstall take this same native per-user claim before touching
    // the machine credential, including before their runtime-lock acquisition.
    let _installation = se_proc::NativeInstallationClaim::acquire().map_err(|error| {
        scope::unreadable("remove installation claim", &error.to_string()).with_cause(error)
    })?;
    let credential = super::credential::require(files)?;
    let digest = Sha256::digest(credential.expose()).into();
    let key_digest = Sha256::digest(value.idempotency_key.as_str().as_bytes());
    let key = format!(
        "remove-down-{}",
        key_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let mut options = execute::options();
    options.expected_generation = Some(target.generation);
    options.timeout = bound.remaining()?;
    let stopped = super::runtime_control::down_endpoint(
        files,
        target,
        RuntimeDown {
            idempotency_key: se_types::IdempotencyKey::new(key)?,
        },
        &options,
    )?;
    let AnyOutput::RuntimeDown(stopped) = stopped else {
        return Err(scope::unreadable(
            "remove runtime completion",
            "graceful down returned a different output family",
        ));
    };
    if !stopped.value.complete {
        return Err(scope::unreadable(
            "remove runtime completion",
            stopped
                .value
                .witness
                .detail
                .as_deref()
                .unwrap_or("graceful shutdown obligations remain"),
        ));
    }
    witness_exit(target, bound)?;
    value.runtime.action = "stopped".into();
    value.runtime.witness = witnessed(
        "authenticated graceful down and exact native process exit",
        None,
    )?;

    // An exclusive lock excludes both host startup and concurrent direct setup.
    // No removal is authorized by endpoint absence or a lock file's existence.
    let path = files.0.root().join("runtime.lock");
    let lock = scope::require_present(
        files.readback(&path).map_err(|e| store_error(&e))?,
        "runtime lock",
        "Restore the protected runtime lock before retrying remove --all.",
    )?;
    lock.try_lock().map_err(|error| {
        scope::unreadable(
            "remove credential exclusion",
            &format!("runtime or direct writer is active: {error}"),
        )
    })?;
    bound.remaining()?;
    if let Read::Present { value: current } = execute::endpoint(files)?
        && (current.epoch != target.epoch || current.generation != target.generation)
    {
        return Err(scope::unreadable(
            "remove credential exclusion",
            "a different host endpoint appeared; its credential was preserved",
        ));
    }
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
            "remove credential exclusion",
            "registered projects remain or their inventory is incomplete; credential preserved",
        ));
    }
    bound.remaining()?;
    let path = files.0.root().join("credential");
    files
        .remove_owned(&path, digest)
        .map_err(|e| store_error(&e))?;
    match super::credential::read(files)? {
        Read::Absent { checked } => {
            value.machine_credential.state = "removed".into();
            value.machine_credential.witness = witnessed(
                "digest-checked removal and independent protected-file absence",
                Some(checked),
            )?;
        }
        _ => {
            return Err(scope::unreadable(
                "removed machine credential",
                "absence was not witnessed; no replacement credential was generated",
            ));
        }
    }
    value.outcome = if value.projects.iter().any(|p| p.outcome == "removed") {
        "removed"
    } else {
        "absent"
    }
    .into();
    Ok(())
}
fn witnessed(method: &str, detail: Option<String>) -> Result<project_remove::RemovalWitness> {
    Ok(project_remove::RemovalWitness {
        state: "witnessed".into(),
        method: Some(method.into()),
        observed_at: Some(receipt::timestamp(execute::now_us()?)?),
        detail,
    })
}
#[cfg(any(target_os = "linux", windows))]
fn witness_exit(target: &EndpointRecord, bound: &Deadline) -> Result<()> {
    let expected = target.epoch.owner.fields();
    loop {
        bound.remaining()?;
        let native = se_proc::current_runtime_identity(expected.machine.clone())
            .map_err(|e| scope::unreadable("remove host exit", &format!("{e:?}")))?;
        if native.boot_id != expected.boot {
            return Ok(());
        }
        let observed = se_proc::read_process(
            expected.machine.clone(),
            se_proc::ProcessId(expected.pid.get()),
        )
        .map_err(|e| scope::unreadable("remove host exit", &format!("{e:?}")))?;
        match observed {
            se_proc::ProcessRead::Absent { .. } | se_proc::ProcessRead::ExitedRecord { .. } => {
                return Ok(());
            }
            se_proc::ProcessRead::Present(live) => {
                let same_start = match (&live.identity.start, &expected.started) {
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
                            "remove host exit",
                            "native start identity has an incompatible platform",
                        ));
                    }
                };
                if !same_start
                    || matches!(
                        live.state,
                        se_proc::NativeState::Exited | se_proc::NativeState::ExitedAwaitingReap
                    )
                {
                    return Ok(());
                }
                if live.identity.image != expected.executable.to_local()? {
                    return Err(scope::unreadable(
                        "remove host exit",
                        "the same process changed its executable; exit is not proven",
                    ));
                }
            }
        }
        std::thread::sleep(bound.remaining()?.min(Duration::from_millis(25)));
    }
}
#[cfg(not(any(target_os = "linux", windows)))]
fn witness_exit(_target: &EndpointRecord, _bound: &Deadline) -> Result<()> {
    Err(scope::unreadable(
        "remove host exit",
        "native host exit observation is unavailable on this platform",
    ))
}
