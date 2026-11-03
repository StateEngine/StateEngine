//! The detached host retains the provider's allowlisted user paths/login
//! configuration, plus native protected temporary storage. Fleet and session
//! authority never crosses this environment boundary.
use super::*;

pub(super) fn prepare(files: &se_proc::NativeStateFiles) -> Result<se_proc::Environment> {
    let temporary = files.root().join("tmp");
    files.prepare_directory(&temporary).map_err(|error| {
        se_core::scope::unreadable("protected host temporary directory", &error.to_string())
            .with_cause(error)
    })?;
    let mut entries = se_host::provider_environment();
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
