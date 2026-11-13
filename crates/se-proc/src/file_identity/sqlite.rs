//! Observe SQLite's opened file through its standard native VFS controls.
use super::NativeFileIdentity;
use rusqlite::{Connection, ffi};
use std::io;

impl NativeFileIdentity {
    /// Whether the Unix VFS's retained file no longer matches its pathname.
    /// This does not open, duplicate or close a descriptor. The caller must
    /// separately compare the pathname with its expected native identity.
    /// Concurrent renames that restore the name between observations cannot
    /// be excluded by these separate checks.
    #[cfg(unix)]
    pub fn sqlite_path_moved(connection: &Connection) -> io::Result<bool> {
        let mut moved: i32 = 0;
        // SAFETY: this standard Unix VFS control writes one integer to the
        // initialized output; the connection remains borrowed and open.
        let code = unsafe {
            ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_HAS_MOVED,
                (&mut moved as *mut i32).cast(),
            )
        };
        checked(code, "SQLITE_FCNTL_HAS_MOVED")?;
        Ok(moved != 0)
    }

    /// Identity of the main database's retained Windows SQLite handle.
    /// The observation never duplicates or closes SQLite's handle.
    #[cfg(windows)]
    pub fn observe_sqlite(connection: &Connection) -> io::Result<Self> {
        use std::{fs::File, mem::ManuallyDrop, os::windows::io::FromRawHandle, ptr};
        let mut handle: *mut std::ffi::c_void = ptr::null_mut();
        // SAFETY: this documented control writes one native HANDLE to the
        // typed output; the connection remains borrowed and open.
        let code = unsafe {
            ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
                (&mut handle as *mut *mut std::ffi::c_void).cast(),
            )
        };
        checked(code, "SQLITE_FCNTL_WIN32_GET_HANDLE")?;
        if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(io::Error::other(
                "SQLite returned no native database handle",
            ));
        }
        // SAFETY: this is a borrowed SQLite handle, never transferred or
        // closed. The wrapper exists only for the existing metadata adapter.
        let file = ManuallyDrop::new(unsafe { File::from_raw_handle(handle) });
        let revision = crate::observe_file_revision(&file)?;
        Ok(Self {
            volume: revision.volume,
            file: revision.file,
        })
    }
}

fn checked(code: i32, capability: &str) -> io::Result<()> {
    if code == ffi::SQLITE_NOTFOUND {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("SQLite {capability} native database identity capability is unavailable"),
        ));
    }
    if code != ffi::SQLITE_OK {
        return Err(io::Error::other(format!(
            "SQLite {capability} native database identity control failed (result {code})"
        )));
    }
    Ok(())
}
