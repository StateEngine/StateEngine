//! Existing directories may use the current user's private primary group.
//! This changes no permissions and never relaxes the final owned state root.
use super::*;
mod proof;
use std::{ffi::CStr, ptr};

fn account_error(path: &Path, operation: &'static str, code: i32) -> StateFileError {
    io_error(operation, path, io::Error::from_raw_os_error(code))
}
fn private_group(gid: libc::gid_t, path: &Path) -> Result<bool> {
    let mut size = 1024;
    let (username, primary) = loop {
        let mut buffer = vec![0u8; size];
        // SAFETY: native POD is filled by the reentrant account lookup below.
        let mut user: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found = ptr::null_mut();
        // SAFETY: exact writable record/buffer/result; geteuid has no mutation.
        let rc = unsafe {
            libc::getpwuid_r(
                libc::geteuid(),
                &mut user,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if rc == libc::ERANGE && size < 1048576 {
            size *= 2;
            continue;
        }
        if rc != 0 {
            return Err(account_error(path, "read current native account", rc));
        }
        if found.is_null() || user.pw_name.is_null() {
            return Err(unsafe_path("current native account is absent", path));
        }
        // SAFETY: successful lookup returns a terminated name in the retained buffer.
        let name = unsafe { CStr::from_ptr(user.pw_name) }.to_bytes().to_vec();
        break (name, user.pw_gid);
    };
    if gid != primary {
        return Ok(false);
    }
    size = 1024;
    loop {
        let mut buffer = vec![0u8; size];
        // SAFETY: native POD is filled by the reentrant group lookup below.
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut found = ptr::null_mut();
        // SAFETY: exact writable record/buffer/result storage, no shared NSS cursor.
        let rc = unsafe {
            libc::getgrgid_r(
                gid,
                &mut group,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if rc == libc::ERANGE && size < 1048576 {
            size *= 2;
            continue;
        }
        if rc != 0 {
            return Err(account_error(path, "read private native group", rc));
        }
        if found.is_null() || group.gr_name.is_null() || group.gr_mem.is_null() {
            return Err(unsafe_path(
                "private native group is absent or unreadable",
                path,
            ));
        }
        // SAFETY: successful lookup supplies a terminated name inside the retained buffer.
        if unsafe { CStr::from_ptr(group.gr_name) }.to_bytes() != username {
            return Ok(false);
        }
        // SAFETY: successful native group lookup supplies a null-terminated pointer array.
        let mut member = group.gr_mem;
        for _ in 0..1048576 / std::mem::size_of::<*mut libc::c_char>() {
            // SAFETY: traverses the native result's terminated member array, retained above.
            let value = unsafe { *member };
            if value.is_null() {
                return sole_primary_member(gid, path);
            }
            // SAFETY: non-null member pointers returned by NSS name terminated strings.
            if unsafe { CStr::from_ptr(value) }.to_bytes() != username {
                return Ok(false);
            }
            // SAFETY: bounded forward traversal of the retained native member array.
            member = unsafe { member.add(1) };
        }
        return Err(unsafe_path(
            "private group membership exceeds native bound",
            path,
        ));
    }
}
pub(super) fn validate(file: &File, path: &Path) -> Result<()> {
    // Other agents can create siblings while NSS proves a private group. A
    // changed directory epoch requires a complete fresh proof, never reuse of
    // the old permissions/account result. Persistent drift still refuses.
    let mut result = validate_once(file, path);
    for _ in 0..2 {
        if !matches!(&result, Err(error) if error.code == StateFileErrorCode::SourceChanged) {
            break;
        }
        result = validate_once(file, path);
    }
    result
}
fn validate_once(file: &File, path: &Path) -> Result<()> {
    let meta = file
        .metadata()
        .map_err(|e| io_error("inspect existing ancestor", path, e))?;
    // SAFETY: immutable query of this process's actual OS user.
    if !meta.is_dir() || (meta.uid() != 0 && meta.uid() != unsafe { libc::geteuid() }) {
        return Err(unsafe_path(
            "ancestor owner is not root or current user",
            path,
        ));
    }
    if meta.mode() & 0o002 != 0 {
        if meta.mode() & 0o1000 != 0 {
            return Ok(());
        }
        return Err(unsafe_path(
            "ancestor is world-writable without sticky protection",
            path,
        ));
    }
    if meta.mode() & 0o020 != 0 && !proof::private_group(file, &meta, path)? {
        return Err(unsafe_path(
            "ancestor is writable by a group other than the user's private primary group",
            path,
        ));
    }
    Ok(())
}

// gr_mem lists supplemental members; another account may also use this GID
// as its primary group. Check the native account database before calling it
// private. This module owns the workspace's only NSS enumeration cursor.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn sole_primary_member(gid: libc::gid_t, path: &Path) -> Result<bool> {
    static ACCOUNTS: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _lock = ACCOUNTS
        .lock()
        .map_err(|_| unsafe_path("native account enumeration lock poisoned", path))?;
    struct Enumeration;
    impl Drop for Enumeration {
        fn drop(&mut self) {
            // SAFETY: the module mutex still owns this native enumeration cursor.
            unsafe {
                libc::endpwent();
            }
        }
    }
    // SAFETY: serialized native account enumeration, separate from reentrant lookups.
    unsafe {
        libc::setpwent();
    }
    let _enumeration = Enumeration;
    let mut size = 1024;
    let mut buffer = vec![0u8; size];
    for _ in 0..65536 {
        loop {
            // SAFETY: native POD is initialized by the reentrant call below.
            let mut account: libc::passwd = unsafe { std::mem::zeroed() };
            let mut found = ptr::null_mut();
            // SAFETY: exact writable record and retained bounded buffer; the
            // process-wide NSS enumeration cursor is serialized by ACCOUNTS.
            let rc = unsafe {
                libc::getpwent_r(
                    &mut account,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut found,
                )
            };
            if rc == libc::ERANGE && size < 1048576 {
                size *= 2;
                buffer.resize(size, 0);
                continue;
            }
            if (rc == 0 || rc == libc::ENOENT) && found.is_null() {
                return Ok(true);
            }
            if rc != 0 {
                return Err(account_error(
                    path,
                    "enumerate private primary-group accounts",
                    rc,
                ));
            }
            // SAFETY: immutable native current-user observation.
            if account.pw_gid == gid && account.pw_uid != unsafe { libc::geteuid() } {
                return Ok(false);
            }
            break;
        }
    }
    Err(unsafe_path(
        "private primary-group account enumeration exceeds 65536 records",
        path,
    ))
}
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn sole_primary_member(_gid: libc::gid_t, path: &Path) -> Result<bool> {
    Err(failure(
        StateFileErrorCode::Unsupported,
        "complete private primary-group account enumeration unavailable on this platform",
        path,
    ))
}
