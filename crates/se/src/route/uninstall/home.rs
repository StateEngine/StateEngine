//! Human-authorized cleanup for an initialized home without an installation
//! manifest. Ordinary down owns process/session closure; only named runtime
//! artifacts are retired. No executable, PATH or retained data is claimed.
use crate::{bootstrap::Bootstrap, route};
use se_core::{ops::*, scope, store_error::store_error};
use se_host::client::lease::Deadline;
use se_store::{ReadStore, StateFiles};
use se_types::{Detail, Read, Result, SeError, details};
use std::{
    io,
    path::{Path, PathBuf},
};

pub(super) fn execute(
    cx: &Bootstrap,
    input: &Uninstall,
    diagnostic: &mut dyn FnMut(&str) -> io::Result<()>,
) -> Result<Option<UninstallOutput>> {
    let Some((_claim, managed)) = admit(cx, input)? else {
        return Ok(None);
    };
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
        match retire(cx, &mut runtime_files, input.yes) {
            Ok(()) => (),
            Err(error) => issues.push(error.body),
        }
    }
    let home = cx.home.display().to_string();
    let preserved = preserved(&cx.home, &home, managed.is_some());
    // The account claim stays held, so the revocation is admitted and a
    // partially cleaned home still reports the achieved effects.
    let integrations = match route::adoption::uninstall(cx) {
        Ok(integrations) => integrations,
        Err((revoked, error)) => {
            issues.push(error.body.clone());
            if revoked
                .iter()
                .any(|entry| entry.witness.state == WitnessState::Failed)
            {
                revoked
            } else {
                failed_revocation(&error, revoked)?
            }
        }
    };
    let complete = matches!(&runtime, Read::Present { value } if value.complete && value.witness.state == WitnessState::Witnessed)
        && issues.is_empty();
    let observed_at = receipt::timestamp(route::execute::now_us()?)?;
    Ok(Some(UninstallOutput {
        idempotency_key: input.idempotency_key.clone(),
        complete,
        home_cleanup: Some(InitializedHomeCleanup {
            runtime,
            runtime_files,
            manual_data_removal: match &managed {
                Some(PackageOwner::Npm) => format!(
                    "Final step: run `npm uninstall -g @stateengine/cli` to remove the package-owned se binary and wrapper. Your StateEngine data stays in {home}; to delete it, separately remove the entire directory {home} manually after closing every StateEngine process using it. This deletes its history, configuration and identity."
                ),
                Some(PackageOwner::Brew) => format!(
                    "Final step: run `brew uninstall stateengine` to remove the stateengine formula's se binary and wrapper. Your StateEngine data stays in {home}; to delete it, separately remove the entire directory {home} manually after closing every StateEngine process using it. This deletes its history, configuration and identity."
                ),
                None => format!(
                    "To also delete retained data, separately remove the entire directory {home} manually after closing every StateEngine process using it. This deletes its history, configuration and identity."
                ),
            },
        }),
        install_files: Vec::new(),
        directories: Vec::new(),
        integrations,
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
/// A refused provider revocation still reports the effects achieved before
/// the refusal, marked failed, alongside the issue it added.
fn failed_revocation(
    error: &SeError,
    revoked: Vec<IntegrationEffect>,
) -> Result<Vec<IntegrationEffect>> {
    let mut integrations = revoked;
    integrations.push(IntegrationEffect {
        path: "provider integrations".into(),
        entry: "provider integration revocation".into(),
        action: FileOutcome::Unreadable,
        witness: Witness {
            state: WitnessState::Failed,
            method: "provider integration revocation".into(),
            observed_at: receipt::timestamp(route::execute::now_us()?)?,
            detail: Some(error.to_string()),
        },
    });
    Ok(integrations)
}
/// Admit cleanup only for a present home without an installation record,
/// holding the account-wide installation exclusion for the caller.
fn admit(
    cx: &Bootstrap,
    input: &Uninstall,
) -> Result<Option<(se_proc::NativeInstallationClaim, Option<PackageOwner>)>> {
    // A package-owned executable is refused before any cleanup effect: an
    // uninitialized package install must still learn its exact package-manager
    // removal. An initialized package-managed home cleans its runtime the same
    // way and names the package command as the final step.
    let managed = managed_package();
    let route::setup::Setup::Present(reader) =
        route::setup::inspect(&cx.home, receipt::timestamp(route::execute::now_us()?)?)?
    else {
        if let Some(managed) = managed {
            return Err(managed.refusal());
        }
        return Ok(None);
    };
    let files = route::files::Files::open(&cx.home).map_err(|e| store_error(&e))?;
    let claim = se_proc::NativeInstallationClaim::acquire().map_err(|e| {
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
        !input.yes,
    )?;
    drop(reader);
    drop(files);
    Ok(Some((claim, managed)))
}
/// The package manager that owns the running executable.
enum PackageOwner {
    Npm,
    Brew,
}
impl PackageOwner {
    /// An executable owned by the package manager cannot be retired by the
    /// standalone uninstaller; name the package command that owns it.
    fn refusal(&self) -> SeError {
        let (reason, next_step) = match self {
            PackageOwner::Npm => (
                "is installed by npm as the @stateengine/cli package, so the standalone uninstaller cannot remove it",
                "Run `npm uninstall -g @stateengine/cli`; your StateEngine data stays in place.",
            ),
            PackageOwner::Brew => (
                "is installed by Homebrew as the stateengine formula, so the standalone uninstaller cannot remove it",
                "Run `brew uninstall stateengine`; your StateEngine data stays in place.",
            ),
        };
        SeError::new(Detail::ListenerUnavailable(details::ListenerUnavailable {
            subject: "the se command".into(),
            reason: reason.into(),
            next_step: next_step.into(),
        }))
    }
}
/// Witness a package-owned executable. Unreadable self-identity falls back to
/// the ordinary initialized-home cleanup.
fn managed_package() -> Option<PackageOwner> {
    let executable = std::env::current_exe()
        .ok()
        .and_then(|path| se_proc::canonicalize_path(&path).ok())?;
    if npm_owned(&executable) {
        Some(PackageOwner::Npm)
    } else if brew_owned(&executable) {
        Some(PackageOwner::Brew)
    } else {
        None
    }
}
/// Witness the npm global layout: a manifest naming this exact package at or
/// above the executable. Other manifests and unreadable files never stop the
/// bounded walk.
fn npm_owned(executable: &Path) -> bool {
    if hoisted_npm_payload(executable) {
        return true;
    }
    let Some(mut ancestor) = executable.parent() else {
        return false;
    };
    for _ in 0..8 {
        let manifest = ancestor.join("package.json");
        let bounded = std::fs::metadata(&manifest)
            .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= 65536);
        if bounded {
            let parsed: serde_json::Value = std::fs::read(&manifest)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or(serde_json::Value::Null);
            if parsed.get("name").and_then(serde_json::Value::as_str) == Some("@stateengine/cli") {
                return true;
            }
        }
        let Some(next) = ancestor.parent() else {
            break;
        };
        ancestor = next;
    }
    false
}
/// Hoisted global layout: the platform payload package is a sibling of the
/// wrapper package under the scope directory, and the wrapper's manifest
/// names this exact package.
fn hoisted_npm_payload(executable: &Path) -> bool {
    let Some(payload) = executable.parent() else {
        return false;
    };
    if !payload.file_name().is_some_and(|name| name == "payload") {
        return false;
    }
    let Some(native_root) = payload.parent() else {
        return false;
    };
    if !native_root
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "cli-linux-x64" | "cli-win32-x64" | "cli-darwin-arm64" | "cli-darwin-x64"
            )
        })
    {
        return false;
    }
    let Some(scoped) = native_root.parent() else {
        return false;
    };
    if !scoped
        .file_name()
        .is_some_and(|name| name == "@stateengine")
    {
        return false;
    }
    let manifest = scoped.join("cli/package.json");
    std::fs::metadata(&manifest).is_ok_and(|metadata| metadata.is_file() && metadata.len() <= 65536)
        && std::fs::read(&manifest)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_some_and(|parsed| {
                parsed.get("name").and_then(serde_json::Value::as_str) == Some("@stateengine/cli")
            })
}
/// Witness the Homebrew layout: the formula's libexec under
/// Cellar/stateengine/<version>, whose version directory holds Homebrew's
/// installation receipt.
fn brew_owned(executable: &Path) -> bool {
    let components: Vec<std::path::Component<'_>> = executable.components().collect();
    let Some(index) = components
        .windows(2)
        .position(|pair| pair[0].as_os_str() == "Cellar" && pair[1].as_os_str() == "stateengine")
    else {
        return false;
    };
    let Some(version) = components.get(index + 2) else {
        return false;
    };
    if !matches!(version, std::path::Component::Normal(_)) {
        return false;
    }
    let libexec = std::path::Component::Normal(std::ffi::OsStr::new("libexec"));
    if components.get(index + 3) != Some(&libexec) {
        return false;
    }
    let receipt: PathBuf = components
        .iter()
        .take(index + 3)
        .map(|component| component.as_os_str())
        .collect();
    receipt.join("INSTALL_RECEIPT.json").is_file()
}
fn preserved(root: &Path, home: &str, managed: bool) -> Vec<String> {
    [
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
            root.join(name).display(),
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
    .chain(std::iter::once(if managed {
        "Executable is package-managed; PATH, repositories and provider login are unchanged".into()
    } else {
        "Executable, PATH, repositories and provider login are unchanged".into()
    }))
    .collect()
}
fn retire(cx: &Bootstrap, effects: &mut Vec<FileEffect>, confirmed: bool) -> Result<()> {
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
        !confirmed,
    )?;
    if !inventory.processes.is_empty() {
        return Err(scope::unreadable(
            "initialized-home cleanup",
            "unresolved process/session custody appeared after shutdown; retry se down",
        ));
    }
    match reader.runtime_owner().map_err(|e| store_error(&e))? {
        Read::Present { value } => {
            route::process::witness_exit(&files, &value.epoch.owner, &bound)?
        }
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
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
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
