//! Finite, held-parent directory enumeration. Reparse entries are names, not followed.
use super::*;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

pub(in crate::state_files) fn scan_recovery(path: &Path) -> Result<Vec<PathBuf>> {
    scan(path, false)
}
pub(in crate::state_files) fn scan_temporary(path: &Path) -> Result<Vec<PathBuf>> {
    scan(path, true)
}
fn scan(path: &Path, temporary: bool) -> Result<Vec<PathBuf>> {
    let parent = Parent::open(path)?;
    let before = parent
        .file()?
        .metadata()
        .map_err(|e| io_error("inspect recovery directory", path, e))?;
    let mut pattern: Vec<u16> = parent.path.as_os_str().encode_wide().collect();
    pattern.extend("\\*".encode_utf16());
    pattern.push(0);
    // SAFETY: initialized native result and retained terminated search pattern.
    let mut entry: WIN32_FIND_DATAW = unsafe { zeroed() };
    // SAFETY: finite native name search beneath the retained physical directory.
    let raw = unsafe { FindFirstFileW(pattern.as_ptr(), &mut entry) };
    if raw == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
            Ok(Vec::new())
        } else {
            Err(io_error("open recovery inventory", path, error))
        };
    }
    struct Search(HANDLE);
    impl Drop for Search {
        fn drop(&mut self) {
            // SAFETY: exclusively owned successful search handle.
            unsafe {
                FindClose(self.0);
            }
        }
    }
    let search = Search(raw);
    let mut found = Vec::new();
    let mut count = 0;
    loop {
        count += 1;
        if count > 4096 {
            return Err(unsafe_path(
                "recovery scan exceeds 4096 directory entries",
                path,
            ));
        }
        let length = entry
            .cFileName
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| unsafe_path("unterminated native recovery name", path))?;
        let name = std::ffi::OsString::from_wide(&entry.cFileName[..length]);
        if if temporary {
            name.to_string_lossy().starts_with(".se-profile-")
                || name.to_string_lossy().starts_with(".se-publish-")
        } else {
            name.to_string_lossy().starts_with(".se-edit-backup-")
        } {
            if found.len() == 256 {
                return Err(unsafe_path("recovery inventory exceeds 256 siblings", path));
            }
            found.push(path.join(name));
        }
        // SAFETY: retained search handle and writable result with the native layout.
        if unsafe { FindNextFileW(search.0, &mut entry) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                return Err(io_error("read recovery directory", path, error));
            }
            break;
        }
    }
    let outside = Parent::open(path)?;
    let after = outside
        .file()?
        .metadata()
        .map_err(|e| io_error("recheck recovery directory", path, e))?;
    if outside.identity != parent.identity
        || before
            .modified()
            .map_err(|e| io_error("read recovery directory clock", path, e))?
            != after
                .modified()
                .map_err(|e| io_error("recheck recovery directory clock", path, e))?
    {
        return Err(changed("recovery directory changed while scanning", path));
    }
    found.sort();
    Ok(found)
}
