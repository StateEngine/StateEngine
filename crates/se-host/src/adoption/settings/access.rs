//! Provider-specific recovery steps around the native file boundary.
use super::*;

fn refusal(path: &Path, reason: String, next_step: String) -> SeError {
    SeError::new(se_types::Detail::SourceUnreadable(
        se_types::details::SourceUnreadable {
            subject: path.display().to_string(),
            reason,
            next_step,
        },
    ))
}
pub(super) fn native(error: se_proc::StateFileError) -> SeError {
    let path = &error.path;
    let next = if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        "Point CODEX_HOME (or the provider settings home) at the directory containing the real configuration file, or replace the symbolic link with a regular file; then retry init --adopt.".into()
    } else if error.operation == "require owner-only native regular file/directory" {
        #[cfg(unix)]
        {
            format!(
                "Make this directory private with chmod 700 -- {}; then retry init --adopt.",
                quoted(path)
            )
        }
        #[cfg(windows)]
        {
            "In the directory's Security properties, disable inherited access and allow only your account; then retry init --adopt.".into()
        }
    } else {
        "Restore access to this exact provider settings path, keeping regular files and directories in place of links; then retry init --adopt.".into()
    };
    refusal(path, error.to_string(), next).with_cause(error)
}
pub(super) fn writable(path: &Path, file: &se_proc::OwnedFile) -> Result<()> {
    let permissions = file.permissions().map_err(native)?;
    #[cfg(unix)]
    let readonly = {
        use std::os::unix::fs::PermissionsExt;
        permissions.mode() & 0o200 == 0
    };
    #[cfg(windows)]
    let readonly = permissions.readonly();
    if readonly {
        #[cfg(unix)]
        let next = format!(
            "Allow owner writes with chmod u+w -- {}; then retry the original command.",
            quoted(path)
        );
        #[cfg(windows)]
        let next = format!(
            "Clear the read-only attribute of {} in its Properties, then retry the original command.",
            path.display()
        );
        return Err(refusal(
            path,
            "Provider configuration is read-only; its bytes were preserved.".into(),
            next,
        ));
    }
    Ok(())
}
#[cfg(unix)]
fn quoted(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}
pub(super) fn prepare(home: &Path, path: &Path) -> Result<()> {
    // Check before even --version: the provider can create temporary directories.
    if let (Some(file), _, _) = read_document(path)? {
        writable(path, &file)?;
    } else {
        se_proc::NativeStateFiles::create(home).map_err(native)?;
    }
    Ok(())
}
