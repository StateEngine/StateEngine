//! The path form SQLite needs for a database file on this platform.
//!
//! Rust's `std` adds the `\\?\` prefix itself for long paths, but SQLite opens
//! files through its own Win32 calls, so a database reached by an ordinary
//! drive path is limited to `MAX_PATH` (260 characters including the
//! terminating NUL). SQLite also appends `-wal` and `-shm` to the name it is
//! given, which is what puts the sidecars over the limit first.
//!
//! Handing SQLite an absolute, verbatim (`\\?\`) path keeps every database and
//! its sidecars openable at any length the filesystem allows. No layout,
//! directory or filename changes: only the form of the string passed to
//! SQLite.
use std::path::{Path, PathBuf};

/// The path to hand SQLite for an existing-or-new database file.
///
/// On Windows an absolute drive or UNC path becomes verbatim. A path that is
/// already verbatim, or any path on another platform, is returned unchanged.
/// A relative path stays relative: the caller owns its working directory, and
/// silently resolving it here would change which file is opened.
pub fn sqlite_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        verbatim(path)
    }
    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
}

#[cfg(windows)]
fn verbatim(path: &Path) -> PathBuf {
    use std::{
        ffi::OsString,
        os::windows::ffi::{OsStrExt, OsStringExt},
        path::{Component, Prefix},
    };
    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return path.to_path_buf();
    };
    let mut units: Vec<u16> = Vec::with_capacity(path.as_os_str().len() + 8);
    match prefix.kind() {
        // Already verbatim: keep the caller's exact form.
        Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) => return path.to_path_buf(),
        Prefix::Disk(_) if path.is_absolute() => {
            units.extend("\\\\?\\".encode_utf16());
            units.extend(path.as_os_str().encode_wide());
        }
        Prefix::UNC(_, _) => {
            units.extend("\\\\?\\UNC\\".encode_utf16());
            // Skip the leading `\\` of `\\server\share`.
            units.extend(path.as_os_str().encode_wide().skip(2));
        }
        _ => return path.to_path_buf(),
    }
    // Win32 does not normalize forward slashes once a path is verbatim, so
    // SQLite would read `/` as an ordinary name character. Normalize here.
    for unit in &mut units {
        if *unit == b'/' as u16 {
            *unit = b'\\' as u16;
        }
    }
    PathBuf::from(OsString::from_wide(&units))
}

#[cfg(test)]
mod tests {
    use super::sqlite_path;
    use std::path::{Path, PathBuf};

    #[cfg(windows)]
    #[test]
    fn absolute_drive_path_becomes_verbatim() {
        assert_eq!(
            sqlite_path(Path::new(r"C:\state\atlas.db")),
            PathBuf::from(r"\\?\C:\state\atlas.db")
        );
    }

    #[cfg(windows)]
    #[test]
    fn forward_slashes_are_normalized_for_verbatim() {
        assert_eq!(
            sqlite_path(Path::new("C:/state/atlas.db")),
            PathBuf::from(r"\\?\C:\state\atlas.db")
        );
    }

    #[cfg(windows)]
    #[test]
    fn verbatim_path_is_returned_unchanged() {
        let already = Path::new(r"\\?\C:\state\atlas.db");
        assert_eq!(sqlite_path(already), PathBuf::from(already));
    }

    #[cfg(windows)]
    #[test]
    fn unc_path_becomes_verbatim_unc() {
        assert_eq!(
            sqlite_path(Path::new(r"\\server\share\atlas.db")),
            PathBuf::from(r"\\?\UNC\server\share\atlas.db")
        );
    }

    #[cfg(windows)]
    #[test]
    fn relative_path_is_left_alone() {
        assert_eq!(
            sqlite_path(Path::new(r"state\atlas.db")),
            PathBuf::from(r"state\atlas.db")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn other_platforms_pass_the_path_through() {
        assert_eq!(
            sqlite_path(Path::new("/state/atlas.db")),
            PathBuf::from("/state/atlas.db")
        );
    }
}
