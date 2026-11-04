//! Select only the standard unpackaged PowerShell locations. This changes the
//! child PATH; login, global PATH/configuration and sandbox choice stay intact.
use super::*;
use std::ffi::OsString;
pub(super) fn select(environment: &[(OsString, OsString)]) -> Result<PathBuf> {
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
    if let Some(root) = value("SystemRoot").or_else(|| value("windir")) {
        candidates.push(root.join("System32/WindowsPowerShell/v1.0/powershell.exe"));
    }
    for candidate in candidates {
        if !candidate.is_absolute() {
            continue;
        }
        let actual = match se_proc::canonicalize_path(&candidate) {
            Ok(path) => path,
            Err(_) => continue,
        };
        if packaged(&actual) {
            continue;
        }
        match se_proc::NativeSourcePin::open(&actual).map_err(native_error)? {
            Some(_) => return Ok(actual),
            None => continue,
        }
    }
    Err(incompatible(
        "no standard unpackaged PowerShell executable is available",
        "Install the PowerShell MSI and retry; the sandbox will not be widened.",
    ))
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
    environment.push(("PATH".into(), selected));
    Ok(environment)
}
