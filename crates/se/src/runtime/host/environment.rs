//! The detached host gets only native system paths and protected temporary
//! storage. Session credentials and caller configuration never cross launch.
use super::*;

pub(super) fn prepare(files: &se_proc::NativeStateFiles) -> Result<se_proc::Environment> {
    let temporary = files.root().join("tmp");
    files.prepare_directory(&temporary).map_err(|error| {
        se_core::scope::unreadable("protected host temporary directory", &error.to_string())
            .with_cause(error)
    })?;
    #[cfg(unix)]
    let entries = vec![("TMPDIR".into(), temporary.into_os_string())];
    #[cfg(windows)]
    let entries = {
        let windows = se_proc::windows_directory().map_err(native_error)?;
        vec![
            ("SystemRoot".into(), windows.as_os_str().into()),
            ("windir".into(), windows.into_os_string()),
            ("TEMP".into(), temporary.as_os_str().into()),
            ("TMP".into(), temporary.into_os_string()),
        ]
    };
    Ok(se_proc::Environment { entries })
}
