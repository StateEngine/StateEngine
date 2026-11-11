//! Human-authorized cleanup for an initialized home without an installation
//! manifest. Ordinary down owns process/session closure; only named runtime
//! artifacts are retired. No executable, PATH or retained data is claimed.
use crate::{bootstrap::Bootstrap, route};
use se_core::{ops::*, scope, store_error::store_error};
use se_host::client::lease::Deadline;
use se_store::{ReadStore, StateFiles};
use se_types::{Read, Result, SeError};
use std::{io, path::Path};

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) fn execute(
    cx: &Bootstrap,
    input: &Uninstall,
    diagnostic: &mut dyn FnMut(&str) -> io::Result<()>,
) -> Result<Option<UninstallOutput>> {
    let route::setup::Setup::Present(reader) =
        route::setup::inspect(&cx.home, receipt::timestamp(route::execute::now_us()?)?)?
    else {
        return Ok(None);
    };
    let files = route::files::Files::open(&cx.home).map_err(|e| store_error(&e))?;
    let _claim = se_proc::NativeInstallationClaim::acquire().map_err(|e| {
        crate::installation_error::map(e, |e| {
            scope::unreadable(
                "initialized-home cleanup installation exclusion",
                &e.to_string(),
            )
        })
    })?;
    match files
        .readback(&cx.home.join("standalone-install.json"))
        .map_err(|e| store_error(&e))?
    {
        Read::Present { .. } => return Ok(None),
        Read::Absent { .. } => (),
        other => {
            scope::require_present(
                other,
                "installation record",
                "Restore access to the selected home's record; no cleanup was attempted.",
            )?;
        }
    }
    let inventory = route::owner::inventory(&reader, &files)?;
    let owner = route::owner::from_inventory(&inventory)?;
    owner.authorize(
        "installation.uninstall",
        owner.os_owner(),
        cx.session.is_some(),
        true,
    )?;
    drop(reader);
    drop(files);
    diagnostic("No standalone installation record: stop this initialized home and retire only its runtime artifacts; retain the executable, PATH, state, configuration and identity.\n")
        .map_err(|e| scope::unreadable("initialized-home cleanup diagnostic", &e.to_string()))?;
    let stopped = route::execute::stop_for_uninstall(
        cx,
        RuntimeDown {
            idempotency_key: input.idempotency_key.clone(),
        },
        diagnostic,
    );
    let mut issues = Vec::new();
    let runtime = match stopped {
        Ok(AnyOutput::RuntimeDown(value)) => Read::Present { value: value.value },
        Ok(_) => {
            return Err(SeError::invalid(
                "initialized-home shutdown",
                "ordinary down result",
            ));
        }
        Err(error) => {
            issues.push(error.body.clone());
            Read::Unreadable {
                source: "ordinary down".into(),
                reason: error.to_string(),
                error: Some(Box::new(error.body)),
            }
        }
    };
    let mut runtime_files = Vec::new();
    if matches!(&runtime, Read::Present { value } if value.complete && value.witness.state == WitnessState::Witnessed)
    {
        // Reacquire the same persistent inode after down, then re-observe all
        // custody. A concurrent start wins or cleanup wins; no unlinkable lock.
        match retire(cx, &mut runtime_files) {
            Ok(()) => (),
            Err(error) => issues.push(error.body),
        }
    }
    let complete = matches!(&runtime, Read::Present { value } if value.complete && value.witness.state == WitnessState::Witnessed)
        && issues.is_empty();
    let observed_at = receipt::timestamp(route::execute::now_us()?)?;
    let home = cx.home.display().to_string();
    let preserved = [
        "state.db",
        "config.toml",
        "credential",
        "machine.json",
        "runtime.lock",
    ]
    .into_iter()
    .map(|name| {
        format!(
            "{}{}",
            cx.home.join(name).display(),
            if name == "runtime.lock" {
                " (shared coordination lock for this home)"
            } else {
                ""
            }
        )
    })
    .chain(std::iter::once(format!(
        "{home} (all other contents, including history, backups, transcripts and unrelated files)"
    )))
    .chain(std::iter::once(
        "Executable, PATH, repositories and provider login are unchanged".into(),
    ))
    .collect();
    Ok(Some(UninstallOutput {
        idempotency_key: input.idempotency_key.clone(),
        complete,
        home_cleanup: Some(InitializedHomeCleanup {
            runtime,
            runtime_files,
            manual_data_removal: format!(
                "To also delete retained data, separately remove the entire directory {home} manually after closing every StateEngine process using it. This deletes its history, configuration and identity."
            ),
        }),
        install_files: Vec::new(),
        directories: Vec::new(),
        integrations: Vec::new(),
        stops: Vec::new(),
        revocations: Vec::new(),
        recovery: Vec::new(),
        issues,
        preserved,
        path: PathEffect {
            scope: "unmanaged installation assets; no PATH changes attempted".into(),
            before_entries: Vec::new(),
            after_entries: Vec::new(),
            witness: Witness {
                state: WitnessState::Witnessed,
                method: "protected installation-record absence under account-wide native exclusion"
                    .into(),
                observed_at,
                detail: None,
            },
        },
    }))
}
fn retire(cx: &Bootstrap, effects: &mut Vec<FileEffect>) -> Result<()> {
    let route::setup::Setup::Present(reader) =
        route::setup::inspect(&cx.home, receipt::timestamp(route::execute::now_us()?)?)?
    else {
        return Err(scope::unreadable(
            "initialized-home cleanup",
            "the retained store disappeared after shutdown",
        ));
    };
    let files = route::files::Files::open(&cx.home).map_err(|e| store_error(&e))?;
    let _lease = route::files::setup_lock(&files)
        .map_err(|e| store_error(&e))?
        .ok_or_else(|| {
            scope::unreadable(
                "initialized-home cleanup",
                "a runtime, setup or writer holds this home; retry uninstall after it completes",
            )
        })?;
    let options = route::execute::options();
    let bound = Deadline::from_options(&options)?;
    let inventory = route::owner::inventory(&reader, &files)?;
    let owner = route::owner::from_inventory(&inventory)?;
    owner.authorize(
        "installation.uninstall",
        owner.os_owner(),
        cx.session.is_some(),
        true,
    )?;
    if !inventory.processes.is_empty() {
        return Err(scope::unreadable(
            "initialized-home cleanup",
            "unresolved process/session custody appeared after shutdown; retry se down",
        ));
    }
    match reader.runtime_owner().map_err(|e| store_error(&e))? {
        Read::Present { value } => route::process::witness_exit(&value.epoch.owner, &bound)?,
        Read::Absent { .. } => (),
        other => {
            scope::require_present(
                other,
                "cleanup prior host identity",
                "Restore access to this home's protected runtime owner before retrying uninstall.",
            )?;
        }
    }
    match route::execute::endpoint(&files)? {
        Read::Absent { .. } => effects.push(effect(&cx.home.join("endpoint.json"), false)?),
        _ => {
            return Err(scope::unreadable(
                "initialized-home cleanup",
                "an endpoint appeared after shutdown; it was preserved",
            ));
        }
    }
    #[cfg(unix)]
    {
        let path = crate::config::unix_socket_paths()?
            .expected_path(&cx.home)
            .map_err(|e| scope::unreadable("cleanup runtime socket address", &e.to_string()))?;
        let bound = se_proc::native_ipc::IpcIoBound {
            deadline: bound.at(),
            cancelled: options.cancelled.clone(),
        };
        let absent = match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => {
                return Err(scope::unreadable(
                    "cleanup runtime socket",
                    &error.to_string(),
                ));
            }
            Ok(_) => false,
        };
        let removed = if absent {
            false
        } else {
            let socket = se_proc::native_ipc::NativeUnixSocketCleanup::observe(&path, &bound)
                .map_err(|e| scope::unreadable("cleanup runtime socket", &e.to_string()))?;
            if let Some(socket) = socket {
                socket
                    .compare_remove(&bound)
                    .map_err(|e| scope::unreadable("cleanup runtime socket", &e.to_string()))?;
                true
            } else {
                false
            }
        };
        effects.push(effect(&path, removed)?);
    }
    #[cfg(any(target_os = "linux", windows))]
    effects.push(effect(
        &cx.home.join("runtime-info.json"),
        crate::runtime::host::retire_detachment(&files, &bound)?,
    )?);
    Ok(())
}
fn effect(path: &Path, removed: bool) -> Result<FileEffect> {
    Ok(FileEffect { path: path.display().to_string(), outcome: if removed { FileOutcome::Removed } else { FileOutcome::AlreadyAbsent },
        witness: Witness { state: WitnessState::Witnessed, method: "exclusive home lease, complete custody inventory and protected native retirement/absence readback".into(), observed_at: receipt::timestamp(route::execute::now_us()?)?, detail: None } })
}
