//! Only called for newly created native objects, before publishing any bytes.
use super::*;
pub(in crate::state_files) fn clear(file: &File, path: &Path, directory: bool) -> Result<()> {
    let meta = file
        .metadata()
        .map_err(|e| io_error("inspect new Darwin object", path, e))?;
    // SAFETY: immutable process identity query, with no pointers.
    if meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || if directory {
            !meta.is_dir()
        } else {
            !meta.is_file() || meta.nlink() != 1
        }
    {
        return Err(unsafe_path(
            "new Darwin object is not current-user private custody",
            path,
        ));
    }
    acl::clear(file, path)?;
    metadata(file, path, directory)?;
    Ok(())
}
