//! Preserve security metadata on the replacement's held descriptor, before rename.
use crate::state_files::{Result, io_error};
use std::{
    fs::File,
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};

pub(super) fn stamp(meta: &std::fs::Metadata) -> (u32, u32, u32, i64, i64) {
    (
        meta.uid(),
        meta.gid(),
        meta.mode(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}

#[cfg(target_os = "macos")]
pub(super) fn copy(source: &File, destination: &File, path: &Path) -> Result<()> {
    // SAFETY: both descriptors are retained regular files. Metadata-only fcopyfile
    // preserves POSIX ownership/mode, ACLs and xattrs without overwriting new text.
    if unsafe {
        libc::fcopyfile(
            source.as_raw_fd(),
            destination.as_raw_fd(),
            std::ptr::null_mut(),
            libc::COPYFILE_METADATA,
        )
    } < 0
    {
        return Err(io_error(
            "preserve profile ownership, ACLs and attributes",
            path,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) fn copy(source: &File, destination: &File, path: &Path) -> Result<()> {
    use std::ffi::CString;
    let meta = source
        .metadata()
        .map_err(|e| io_error("read original profile security", path, e))?;
    // SAFETY: only the new staging descriptor is changed; original user/group
    // identity comes from the retained original file, never command input.
    if unsafe { libc::fchown(destination.as_raw_fd(), meta.uid(), meta.gid()) } < 0 {
        return Err(io_error(
            "preserve profile owner and group",
            path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: retained private staging descriptor, copying only ordinary rwx bits.
    if unsafe {
        libc::fchmod(
            destination.as_raw_fd(),
            (meta.mode() & 0o777) as libc::mode_t,
        )
    } < 0
    {
        return Err(io_error(
            "preserve profile mode",
            path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: documented native sizing query, no writable buffer is supplied.
    let count = unsafe { libc::flistxattr(source.as_raw_fd(), std::ptr::null_mut(), 0) };
    if count < 0 {
        let error = io::Error::last_os_error();
        return Err(io_error("list original profile attributes", path, error));
    }
    let mut names = vec![0u8; count as usize];
    // SAFETY: retained source FD and exactly sized initialized native output.
    let read =
        unsafe { libc::flistxattr(source.as_raw_fd(), names.as_mut_ptr().cast(), names.len()) };
    if read < 0 {
        return Err(io_error(
            "read original profile attribute names",
            path,
            io::Error::last_os_error(),
        ));
    }
    if read as usize > names.len() {
        return Err(crate::state_files::effects::changed(
            "profile attribute list changed while reading",
            path,
        ));
    }
    names.truncate(read as usize);
    let mut access_acl = false;
    for name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        access_acl |= name == b"system.posix_acl_access";
        let name = CString::new(name).map_err(|_| {
            io_error(
                "decode native profile attribute name",
                path,
                io::Error::from(io::ErrorKind::InvalidData),
            )
        })?;
        let value = read_attr(source, &name, path)?.ok_or_else(|| {
            io_error(
                "original profile attribute changed",
                path,
                io::Error::from(io::ErrorKind::NotFound),
            )
        })?;
        if read_attr(destination, &name, path)?.as_ref() == Some(&value) {
            continue;
        }
        // SAFETY: retained new file, terminated native attribute name and bounded
        // value read from the original. Failures preserve the original profile.
        if unsafe {
            libc::fsetxattr(
                destination.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        } < 0
        {
            return Err(io_error(
                "preserve profile attribute",
                path,
                io::Error::last_os_error(),
            ));
        }
    }
    if !access_acl {
        let name = c"system.posix_acl_access";
        // SAFETY: remove only an inherited staging ACL absent from the original;
        // otherwise fchmod could activate unintended entries inherited from parent.
        if unsafe { libc::fremovexattr(destination.as_raw_fd(), name.as_ptr()) } < 0 {
            let error = io::Error::last_os_error();
            if !matches!(
                error.raw_os_error(),
                Some(libc::ENODATA) | Some(libc::ENOTSUP)
            ) {
                return Err(io_error(
                    "remove foreign inherited profile ACL",
                    path,
                    error,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_attr(file: &File, name: &std::ffi::CStr, path: &Path) -> Result<Option<Vec<u8>>> {
    // SAFETY: sizing query on a retained file and valid terminated attribute name.
    let count =
        unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if count < 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENODATA) {
            Ok(None)
        } else {
            Err(io_error("inspect profile attribute", path, error))
        };
    }
    let mut value = vec![0; count as usize];
    // SAFETY: retained file, native name, and owned output sized by the first call.
    let count = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if count < 0 {
        return Err(io_error(
            "read profile attribute",
            path,
            io::Error::last_os_error(),
        ));
    }
    if count as usize > value.len() {
        return Err(crate::state_files::effects::changed(
            "profile attribute changed while reading",
            path,
        ));
    }
    value.truncate(count as usize);
    Ok(Some(value))
}

/// Darwin ACL grants need an explicit check: they are not bounded by POSIX mode.
/// Refuse mutation/security grants conservatively, including an allow qualified
/// only to the owner; ordinary read grants and deny-only home ACLs remain valid.
#[cfg(target_os = "macos")]
pub(super) fn check_directory_acl(file: &File, path: &Path) -> Result<()> {
    super::super::acl::verify_mutation_directory(file, path)
}
