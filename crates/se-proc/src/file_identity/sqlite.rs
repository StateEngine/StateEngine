//! Observe the database object SQLite actually opened, without reopening its name.
use super::NativeFileIdentity;
use rusqlite::{Connection, ffi};
use std::{fs::File, io, mem::ManuallyDrop, ptr};

impl NativeFileIdentity {
    /// Identity of the main database's retained SQLite descriptor/handle.
    /// No descriptor is duplicated, opened or closed by this observation.
    pub fn observe_sqlite(connection: &Connection) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            let descriptor = unix_descriptor(connection)?;
            // SAFETY: the live borrowed connection retains this SQLite-owned
            // descriptor throughout the call. ManuallyDrop prevents closing it,
            // which would also disturb this process's POSIX record locks.
            let file = ManuallyDrop::new(unsafe { File::from_raw_fd(descriptor) });
            Self::from_metadata(&file.metadata()?)
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::FromRawHandle;
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
            checked(code)?;
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
}

fn checked(code: i32) -> io::Result<()> {
    if code != ffi::SQLITE_OK {
        return Err(io::Error::other(format!(
            "SQLite native database identity control is unavailable (result {code})"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn unix_descriptor(connection: &Connection) -> io::Result<i32> {
    use std::ffi::CStr;
    #[derive(serde::Deserialize)]
    struct FileStat {
        h: i32,
    }
    struct Text(*mut std::ffi::c_char);
    impl Drop for Text {
        fn drop(&mut self) {
            // SAFETY: sqlite3_str_finish transfers this allocation to its caller;
            // sqlite3_free accepts null and is its matching release operation.
            unsafe { ffi::sqlite3_free(self.0.cast()) };
        }
    }
    // SAFETY: a null database selects SQLite's ordinary string allocator.
    let builder = unsafe { ffi::sqlite3_str_new(ptr::null_mut()) };
    if builder.is_null() {
        return Err(io::Error::other("SQLite native identity allocation failed"));
    }
    // SAFETY: FILESTAT appends to an initialized sqlite3_str. It describes the
    // main database's real descriptor; no private SQLite struct layout is used.
    let code = unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_FILESTAT,
            builder.cast(),
        )
    };
    // SAFETY: finish always releases the builder, including a failed control.
    let text = Text(unsafe { ffi::sqlite3_str_finish(builder) });
    checked(code)?;
    if text.0.is_null() {
        return Err(io::Error::other(
            "SQLite returned no native database identity",
        ));
    }
    // SAFETY: successful finish returns an owned, terminated allocation retained
    // by Text until after the parser has consumed its bytes.
    let bytes = unsafe { CStr::from_ptr(text.0) }.to_bytes();
    let stat: FileStat = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    if stat.h < 0 {
        return Err(io::Error::other(
            "SQLite returned an invalid database descriptor",
        ));
    }
    Ok(stat.h)
}
