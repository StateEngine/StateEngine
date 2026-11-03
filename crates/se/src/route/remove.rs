//! Finish --all outside the writer: authenticated down, exact exit readback,
//! then digest-checked credential retirement under the exclusive runtime lock.
use super::{execute, files::Files};
use se_core::{ops::*, scope, store_error::store_error};
use se_host::{EndpointRecord, client::lease::Deadline};
use se_store::{Admission, ReadStore, Snapshot, StateFiles};
use se_types::{Read, Result};
use sha2::{Digest, Sha256};
use std::time::Duration;

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
    super::process::witness_exit(&target.epoch.owner, bound)?;
    value.runtime.action = "stopped".into();
    value.runtime.witness = witnessed(
        "authenticated graceful down and exact native process exit",
        None,
    )?;

    // An exclusive lock excludes both host startup and concurrent direct setup.
    // No removal is authorized by endpoint absence or a lock file's existence.
    let _lock = super::empty_home::lock(files, reader, admission, bound.remaining()?)?;
    if let Read::Present { value: current } = execute::endpoint(files)?
        && (current.epoch != target.epoch || current.generation != target.generation)
    {
        return Err(scope::unreadable(
            "remove credential exclusion",
            "a different host endpoint appeared; its credential was preserved",
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
/// After a successful --all retirement there is deliberately no credential
/// with which to start a host. A measured empty home can answer absence alone.
pub fn absent<R: ReadStore>(
    cx: &crate::bootstrap::Bootstrap,
    files: &Files,
    reader: &R,
    admission: &Admission,
    input: &ProjectRemove,
) -> Result<Option<AnyOutput>> {
    if !input.all {
        return absent_project(cx, files, reader, admission, input);
    }
    if !input.all || !matches!(super::credential::read(files)?, Read::Absent { .. }) {
        return Ok(None);
    }
    let _claim = se_proc::NativeInstallationClaim::acquire().map_err(|error| {
        scope::unreadable("remove installation claim", &error.to_string()).with_cause(error)
    })?;
    let _lock = super::empty_home::lock(files, reader, admission, Duration::from_secs(5))?;
    let Read::Absent { checked } = super::credential::read(files)? else {
        return Err(scope::unreadable(
            "empty-home credential",
            "a credential appeared during exclusion; retry without replacing it",
        ));
    };
    Ok(Some(
        RemoveResult {
            idempotency_key: input.idempotency_key.clone(),
            scope: "all".into(),
            outcome: "absent".into(),
            projects: vec![],
            runtime: project_remove::RemovedRuntime {
                action: "not-running".into(),
                process: None,
                witness: witnessed(
                    "exclusive native runtime lock",
                    Some(
                        "No active project and no host/direct writer held the runtime lock.".into(),
                    ),
                )?,
            },
            machine_credential: project_remove::RemovedMachineCredential {
                state: "removed".into(),
                witness: witnessed("independent protected-file absence", Some(checked))?,
            },
            next: project_remove::RemovalNext {
                text: "Initialize a repository to come back".into(),
                command: "se init".into(),
                argv: vec!["se".into(), "init".into()],
            },
        }
        .into(),
    ))
}
/// A project tombstone is permanent. A human retry can report its measured
/// absence without starting a host, replacing a retired key or writing again.
fn absent_project<R: ReadStore>(
    cx: &crate::bootstrap::Bootstrap,
    files: &Files,
    reader: &R,
    admission: &Admission,
    input: &ProjectRemove,
) -> Result<Option<AnyOutput>> {
    let mut snapshot = reader
        .snapshot(se_core::admission::read_scope(admission))
        .map_err(|e| store_error(&e))?;
    let plan = project_remove::plan(
        input.clone(),
        &mut se_core::commit::Cx {
            read: &mut snapshot,
            admission,
        },
    );
    let closed = snapshot.close().map_err(|e| store_error(&e));
    let plan = match plan {
        Ok(plan) => {
            closed?;
            plan
        }
        Err(error) => {
            return Err(match closed {
                Ok(()) => error,
                Err(close) => error.with_cause(close),
            });
        }
    };
    if !plan.projects.is_empty() {
        return Ok(None);
    }
    let AnyOutput::ProjectStatus(status) = super::status::observe(cx, reader, files, admission)?
    else {
        return Err(scope::unreadable(
            "removed project retry",
            "status returned a different output family",
        ));
    };
    let status = status.value;
    let removal = status.removal.ok_or_else(|| {
        scope::unreadable(
            "removed project retry",
            "the selected project's tombstone was not read back",
        )
    })?;
    let action = match status.runtime.state.as_str() {
        "running" => "left-running",
        "stopped" => "not-running",
        _ => {
            return Err(scope::unreadable(
                "removed project runtime",
                "status could not establish the runtime state; restore its protected endpoint and retry the same project ID",
            ));
        }
    };
    let credential = match super::credential::read(files)? {
        Read::Present { .. } => project_remove::RemovedMachineCredential {
            state: "kept".into(),
            witness: project_remove::RemovalWitness {
                state: "not-applicable".into(),
                method: None,
                observed_at: None,
                detail: Some("This already removed project changes no machine credential.".into()),
            },
        },
        Read::Absent { checked } => project_remove::RemovedMachineCredential {
            state: "removed".into(),
            witness: witnessed("independent protected-file absence", Some(checked))?,
        },
        other => {
            scope::require_present(
                other,
                "removed project credential",
                "Restore access to the original credential state before retrying; unreadable is not absent.",
            )?;
            unreachable!()
        }
    };
    Ok(Some(
        RemoveResult {
            idempotency_key: input.idempotency_key.clone(),
            scope: "project".into(),
            outcome: "absent".into(),
            projects: vec![project_remove::ProjectRemoval {
                project: project_remove::RemovedProject {
                    id: removal.project.id,
                    name: removal.project.name,
                    root: removal.root,
                },
                outcome: "absent".into(),
                removed_at: Some(removal.removed_at),
                event_id: Some(removal.event_id),
                agents_stopped: vec![],
                processes_stopped: vec![],
                processes_may_remain: vec![],
                credentials_revoked: vec![],
                integrations: vec![],
                removed: vec![],
                kept: vec![],
                remaining: vec![],
            }],
            runtime: project_remove::RemovedRuntime {
                action: action.into(),
                process: status.runtime.process,
                witness: witnessed(
                    "independent native status observation",
                    Some("No runtime or project effects were performed by this retry.".into()),
                )?,
            },
            machine_credential: credential,
            next: project_remove::RemovalNext {
                text: status.next.text,
                command: status.next.command,
                argv: status.next.argv,
            },
        }
        .into(),
    ))
}
fn witnessed(method: &str, detail: Option<String>) -> Result<project_remove::RemovalWitness> {
    Ok(project_remove::RemovalWitness {
        state: "witnessed".into(),
        method: Some(method.into()),
        observed_at: Some(receipt::timestamp(execute::now_us()?)?),
        detail,
    })
}
