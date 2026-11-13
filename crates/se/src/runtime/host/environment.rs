//! The detached host retains the provider's allowlisted user paths/login
//! configuration, plus native protected temporary storage. Fleet and session
//! authority never crosses this environment boundary.
use super::*;

pub(super) fn prepare(
    files: &se_proc::NativeStateFiles,
    configuration: &std::path::Path,
) -> Result<se_proc::Environment> {
    let temporary = files.root().join("tmp");
    files.prepare_directory(&temporary).map_err(|error| {
        se_core::scope::unreadable("protected host temporary directory", &error.to_string())
            .with_cause(error)
    })?;
    let mut entries = se_host::provider_environment();
    if super::startup_log::StartupLog::success_enabled() {
        entries.push(("SE_STARTUP_LOG".into(), "1".into()));
    }
    // The host launches configured providers. Each child is filtered again through
    // its own provider allowlist, so Codex login/config does not reach Claude.
    for (name, value) in se_host::codex_input::provider_environment() {
        if !entries
            .iter()
            .any(|(existing, _)| existing.eq_ignore_ascii_case(&name))
        {
            entries.push((name, value));
        }
    }
    // The detached host must retain human-selected protocol context too;
    // each protocol child still receives only its neutral and configured names.
    let selected = crate::config::load::<se_core::config_policy::ConfigFile>(
        configuration,
        configuration != files.root().join("config.toml"),
    )?;
    selected.value.validate()?;
    let named = selected
        .value
        .harnesses
        .values()
        .flat_map(|descriptor| &descriptor.environment);
    for name in selected.value.acp.environment.iter().chain(named) {
        if let Some(value) = std::env::var_os(name) {
            entries.retain(|(old, _)| !old.eq_ignore_ascii_case(std::ffi::OsStr::new(name)));
            entries.push((name.into(), value));
        }
    }
    entries.retain(|(name, _)| {
        !["TMPDIR", "TEMP", "TMP", "SystemRoot", "windir"]
            .iter()
            .any(|managed| managed.eq_ignore_ascii_case(&name.to_string_lossy()))
    });
    #[cfg(unix)]
    entries.push(("TMPDIR".into(), temporary.into_os_string()));
    #[cfg(windows)]
    {
        let windows = se_proc::windows_directory().map_err(native_error)?;
        entries.extend([
            ("SystemRoot".into(), windows.as_os_str().into()),
            ("windir".into(), windows.into_os_string()),
            ("TEMP".into(), temporary.as_os_str().into()),
            ("TMP".into(), temporary.into_os_string()),
        ]);
    }
    Ok(se_proc::Environment { entries })
}
