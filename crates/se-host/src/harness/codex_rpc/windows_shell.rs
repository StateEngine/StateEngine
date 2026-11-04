//! Select only the standard unpackaged PowerShell locations. This changes the
//! child PATH; login, global PATH/configuration and sandbox choice stay intact.
use super::*;
use std::ffi::OsString;
pub(super) fn candidates(environment: &[(OsString, OsString)]) -> Result<Vec<PathBuf>> {
    let value = |wanted: &str| {
        environment
            .iter()
            .find(|(name, _)| name.to_string_lossy().eq_ignore_ascii_case(wanted))
            .map(|(_, value)| PathBuf::from(value))
    };
    let mut candidates = Vec::new();
    for root in [value("ProgramW6432"), value("ProgramFiles")]
        .into_iter()
        .flatten()
    {
        candidates.push(root.join("PowerShell/7/pwsh.exe"));
    }
    candidates.push(
        se_proc::windows_directory()
            .map_err(proc_error)?
            .join("System32/WindowsPowerShell/v1.0/powershell.exe"),
    );
    let mut available = Vec::new();
    for candidate in candidates {
        if !candidate.is_absolute() {
            continue;
        }
        let actual = match se_proc::canonicalize_path(&candidate) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(native_error(error)),
        };
        if packaged(&actual) {
            continue;
        }
        // Windows system executables legitimately have WinSxS hard links.
        // This is an executable lookup, not an owner-only state-file read pin.
        if std::fs::metadata(&actual).map_err(native_error)?.is_file()
            && !available.contains(&actual)
        {
            available.push(actual);
        }
    }
    Ok(available)
}
fn packaged(path: &Path) -> bool {
    path.components().any(|part| {
        let part = part.as_os_str().to_string_lossy();
        part.eq_ignore_ascii_case("WindowsApps") || part.eq_ignore_ascii_case("AppX")
    })
}
pub(super) fn apply(
    mut environment: Vec<(OsString, OsString)>,
    shell: &Path,
) -> Result<Vec<(OsString, OsString)>> {
    let parent = shell.parent().ok_or_else(|| {
        SeError::invalid("PowerShell selection", "an absolute unpackaged executable")
    })?;
    let previous = environment
        .iter()
        .find(|(name, _)| name.to_string_lossy().eq_ignore_ascii_case("path"))
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    let paths = std::iter::once(parent.to_owned())
        .chain(std::env::split_paths(&previous).filter(|path| !packaged(path)));
    let selected = std::env::join_paths(paths)
        .map_err(|e| se_core::scope::unreadable("PowerShell child PATH", &e.to_string()))?;
    environment.retain(|(name, _)| !name.to_string_lossy().eq_ignore_ascii_case("path"));
    environment.retain(|(name, _)| !name.to_string_lossy().eq_ignore_ascii_case("shell"));
    environment.push(("PATH".into(), selected));
    environment.push(("SHELL".into(), shell.as_os_str().to_owned()));
    Ok(environment)
}

/// Query the actual candidate's process identity before launching Codex. The
/// probe reads only its private stdin, and every path proves that exact child
/// exited. No user command, login or provider model turn is involved.
pub(super) async fn probe(shell: &Path, pool: &BlockingPool, cx: &CallContext) -> Result<bool> {
    use std::process::Stdio;
    let budget = cx.timeout.min(Duration::from_secs(5));
    if budget.is_zero() {
        return Err(incompatible(
            "shell probe deadline expired",
            "Retry with an unexpired launch deadline.",
        ));
    }
    let until = tokio::time::Instant::now() + budget;
    let query_until = until - (budget / 10).min(Duration::from_millis(500));
    let mut child = tokio::process::Command::new(shell)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::In.ReadLine() | Out-Null",
        ])
        .env_clear()
        .envs(input::provider_environment())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            incompatible(
                &format!("selected shell probe failed: {e}"),
                "Install the PowerShell MSI and retry.",
            )
        })?;
    let checked = async {
        let pid = child.id().ok_or_else(|| {
            incompatible(
                "shell probe has no retained process ID",
                "Retry the shell probe.",
            )
        })?;
        let remaining = query_until.saturating_duration_since(tokio::time::Instant::now());
        let deadline = crate::client::lease::Deadline::idle()?.stage(remaining)?;
        let packaged = pool
            .run_owned(&deadline, move || {
                se_proc::process_has_package_identity(se_proc::ProcessId(pid)).map_err(proc_error)
            })
            .await?;
        Ok(!packaged)
    }
    .await;
    // This is our retained direct child, never a name/pattern-selected process.
    let killed = child.start_kill();
    let exit = tokio::time::timeout_at(until, child.wait()).await;
    if !matches!(exit, Ok(Ok(_))) {
        return Err(incompatible(
            "selected shell probe exit is unproved",
            "Reconcile the exact probe child before retrying.",
        ));
    }
    if let Err(error) = killed {
        return Err(se_core::scope::unreadable(
            "selected shell probe stop",
            &error.to_string(),
        ));
    }
    checked
}
fn proc_error(error: se_proc::ProcError) -> SeError {
    se_core::scope::unreadable("Codex shell native observation", &format!("{error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standard_shell_has_no_package_identity() -> Result<()> {
        let _initialized = crate::initialize_host_process()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()
            .map_err(native_error)?;
        let pool = BlockingPool::new(runtime.handle().clone());
        let available = candidates(&input::provider_environment())?;
        let mut verified = false;
        for candidate in available {
            let cx = context(se_types::Generation::new(1)?, Duration::from_secs(5));
            if runtime.block_on(probe(&candidate, &pool, &cx))? {
                println!("native unpackaged shell: {}", candidate.display());
                verified = true;
                break;
            }
        }
        assert!(
            verified,
            "a standard unpackaged shell must qualify on this native Windows fixture"
        );
        Ok(())
    }
    #[test]
    fn child_environment_excludes_store_paths_and_selects_the_verified_shell() -> Result<()> {
        let shell = Path::new(r"C:\Program Files\PowerShell\7\pwsh.exe");
        let changed = apply(
            vec![
                (
                    "Path".into(),
                    r"C:\WindowsApps\PowerShell;C:\Windows\System32".into(),
                ),
                ("SHELL".into(), r"C:\WindowsApps\PowerShell\pwsh.exe".into()),
            ],
            shell,
        )?;
        let shell_value = changed
            .iter()
            .find(|(key, _)| key == "SHELL")
            .map(|(_, value)| value);
        assert_eq!(
            shell_value.map(|value| value.as_os_str()),
            Some(shell.as_os_str())
        );
        let paths = changed
            .iter()
            .find(|(key, _)| key == "PATH")
            .map(|(_, value)| value)
            .ok_or_else(|| SeError::invalid("shell test", "the selected child PATH"))?;
        let paths = std::env::split_paths(paths).collect::<Vec<_>>();
        assert_eq!(paths.first().map(PathBuf::as_path), shell.parent());
        assert!(!paths.iter().any(|path| packaged(path)));
        Ok(())
    }
}
