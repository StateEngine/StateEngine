//! Darwin extended ACLs are independent of BSD mode bits. All observations and
//! changes use a held descriptor, never a path resolved for a second time.
//! ABI: Apple Libc include/sys/acl.h, gen/filesec.c and XNU bsd/sys/fcntl.h.
use crate::state_files::{Result, io_error, unsafe_path};
use std::{ffi::c_void, fs::File, io, os::fd::AsRawFd, path::Path};

const EXTENDED: i32 = 0x100;
const ALLOW: i32 = 1;
const DENY: i32 = 2;
unsafe extern "C" {
    fn acl_get_fd_np(fd: i32, kind: i32) -> *mut c_void;
    fn acl_free(value: *mut c_void) -> i32;
    fn acl_get_entry(acl: *mut c_void, index: i32, entry: *mut *mut c_void) -> i32;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut i32) -> i32;
    fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> i32;
    fn acl_get_qualifier(entry: *mut c_void) -> *mut c_void;
    fn acl_size(acl: *mut c_void) -> isize;
    fn acl_copy_ext(buffer: *mut c_void, acl: *mut c_void, size: isize) -> isize;
    fn mbr_uid_to_uuid(uid: u32, uuid: *mut u8) -> i32;
    fn filesec_init() -> *mut c_void;
    fn filesec_free(value: *mut c_void);
    fn filesec_set_property(value: *mut c_void, property: i32, data: *const c_void) -> i32;
    fn fchmodx_np(fd: i32, security: *mut c_void) -> i32;
}
struct Acl(*mut c_void);
impl Drop for Acl {
    fn drop(&mut self) {
        // SAFETY: owned allocation from acl_get_fd_np or acl_get_qualifier.
        unsafe { acl_free(self.0) };
    }
}
fn read(file: &File, path: &Path) -> Result<Option<Acl>> {
    // SAFETY: live descriptor and the native extended-ACL selector.
    let raw = unsafe { acl_get_fd_np(file.as_raw_fd(), EXTENDED) };
    if !raw.is_null() {
        return Ok(Some(Acl(raw)));
    }
    let error = io::Error::last_os_error();
    // On a held FD, Libc filesec_get_property reports ENOENT when the ACL
    // property is absent. Unsupported/unreadable ACLs are never called absent.
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(io_error("read pinned Darwin extended ACL", path, error))
    }
}
fn owner_only(acl: &Acl, uid: u32, path: &Path) -> Result<bool> {
    let mut owner = None;
    let mut index = 0; // ACL_FIRST_ENTRY; ACL_NEXT_ENTRY below.
    loop {
        let mut entry = std::ptr::null_mut();
        // SAFETY: valid owned ACL and initialized entry output.
        if unsafe { acl_get_entry(acl.0, index, &mut entry) } < 0 {
            let error = io::Error::last_os_error();
            // Apple's iterator returns -1/EINVAL at the end, including an empty ACL.
            return if error.raw_os_error() == Some(libc::EINVAL) {
                Ok(true)
            } else {
                Err(io_error("iterate pinned Darwin ACL", path, error))
            };
        }
        index = -1;
        let mut tag = 0;
        // SAFETY: entry is borrowed from the retained ACL and output is native-width.
        if unsafe { acl_get_tag_type(entry, &mut tag) } < 0 {
            return Err(io_error(
                "read Darwin ACL tag",
                path,
                io::Error::last_os_error(),
            ));
        }
        if tag == DENY {
            continue;
        }
        if tag != ALLOW {
            return Err(unsafe_path("unknown Darwin ACL entry type", path));
        }
        // No flag exemption: inherited and inherit-only allows must also name
        // the owner, so children cannot inherit a foreign grant from a private root.
        let owner = match owner {
            Some(value) => value,
            None => {
                let mut value = [0u8; 16];
                // SAFETY: native UID and an initialized 16-byte uuid_t output.
                let code = unsafe { mbr_uid_to_uuid(uid, value.as_mut_ptr()) };
                if code != 0 {
                    return Err(io_error(
                        "resolve Darwin ACL owner UUID",
                        path,
                        io::Error::from_raw_os_error(code),
                    ));
                }
                owner = Some(value);
                value
            }
        };
        // SAFETY: native entry returns an owned allocation containing a uuid_t.
        let qualifier = unsafe { acl_get_qualifier(entry) };
        if qualifier.is_null() {
            return Err(io_error(
                "read Darwin ACL qualifier",
                path,
                io::Error::last_os_error(),
            ));
        }
        let qualifier = Acl(qualifier);
        // SAFETY: acl_get_qualifier allocates exactly one native 16-byte UUID.
        let actual = unsafe { std::ptr::read_unaligned(qualifier.0.cast::<[u8; 16]>()) };
        if actual != owner {
            return Ok(false);
        }
    }
}
pub(super) fn is_owner_only(file: &File, uid: u32, path: &Path) -> Result<bool> {
    read(file, path)?.map_or(Ok(true), |acl| owner_only(&acl, uid, path))
}
pub(super) fn verify(file: &File, uid: u32, path: &Path) -> Result<()> {
    if !is_owner_only(file, uid, path)? {
        return Err(unsafe_path(
            "Darwin ACL allows access to someone other than the owner; use the named doctor permission repair",
            path,
        ));
    }
    Ok(())
}
/// Mutation parents may allow ordinary reads, but no additional authority to
/// replace names or change security. Share the private reader's absent-ACL rule.
pub(super) fn verify_mutation_directory(file: &File, path: &Path) -> Result<()> {
    let Some(acl) = read(file, path)? else {
        return Ok(());
    };
    let mut index = 0;
    loop {
        let mut entry = std::ptr::null_mut();
        // SAFETY: owned ACL and initialized native entry output.
        if unsafe { acl_get_entry(acl.0, index, &mut entry) } < 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::EINVAL) {
                Ok(())
            } else {
                Err(io_error("iterate mutation directory ACL", path, error))
            };
        }
        index = -1;
        let mut tag = 0;
        let mut mask = 0;
        // SAFETY: entry belongs to the held ACL and outputs have native widths.
        if unsafe { acl_get_tag_type(entry, &mut tag) } < 0
            // SAFETY: the same borrowed entry and initialized native mask output.
            || unsafe { acl_get_permset_mask_np(entry, &mut mask) } < 0
        {
            return Err(io_error(
                "inspect mutation directory ACL grant",
                path,
                io::Error::last_os_error(),
            ));
        }
        const MUTATION: u64 = (1 << 2)
            | (1 << 4)
            | (1 << 5)
            | (1 << 6)
            | (1 << 8)
            | (1 << 10)
            | (1 << 12)
            | (1 << 13);
        if tag != DENY && (tag != ALLOW || mask & MUTATION != 0) {
            return Err(unsafe_path(
                "mutation directory ACL grants additional name/security authority",
                path,
            ));
        }
    }
}
/// Portable native ACL bytes preserve ordering, principals, permissions and all
/// inheritance flags. No name-service formatting can erase a metadata change.
pub(super) fn snapshot(file: &File, path: &Path) -> Result<String> {
    let Some(acl) = read(file, path)? else {
        return Ok(String::new());
    };
    // SAFETY: sizing query on a retained ACL allocation.
    let size = unsafe { acl_size(acl.0) };
    if size < 0 {
        return Err(io_error(
            "size pinned Darwin ACL",
            path,
            io::Error::last_os_error(),
        ));
    }
    if size > 64 * 1024 {
        return Err(unsafe_path(
            "Darwin ACL exceeds bounded metadata snapshot",
            path,
        ));
    }
    let mut words = vec![0u64; (size as usize).div_ceil(8)];
    // SAFETY: initialized output sized by acl_size; the same owned ACL is immutable.
    let count = unsafe { acl_copy_ext(words.as_mut_ptr().cast(), acl.0, size) };
    if count < 0 || count != size {
        return Err(io_error(
            "copy pinned Darwin ACL",
            path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: aligned initialized storage holds at least size bytes; the native
    // copy initialized that exact prefix, which remains borrowed from words.
    let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), size as usize) };
    Ok(se_types::hex_lower(bytes))
}
pub(super) fn clear(file: &File, path: &Path) -> Result<()> {
    struct Security(*mut c_void);
    impl Drop for Security {
        fn drop(&mut self) {
            // SAFETY: uniquely owned filesec_init allocation.
            unsafe { filesec_free(self.0) };
        }
    }
    // SAFETY: native allocator without input pointers.
    let raw = unsafe { filesec_init() };
    if raw.is_null() {
        return Err(io_error(
            "allocate Darwin ACL removal",
            path,
            io::Error::last_os_error(),
        ));
    }
    let security = Security(raw);
    // SAFETY: FILESEC_ACL=5 and _FILESEC_REMOVE_ACL=(void*)1 are documented
    // native selectors, not dereferenced Rust objects; no other metadata is set.
    if unsafe { filesec_set_property(security.0, 5, std::ptr::without_provenance(1)) } < 0 {
        return Err(io_error(
            "prepare Darwin ACL removal",
            path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: held FD; only the ACL property is present (same effect as chmod -N).
    if unsafe { fchmodx_np(file.as_raw_fd(), security.0) } < 0 {
        return Err(io_error(
            "clear pinned Darwin ACL",
            path,
            io::Error::last_os_error(),
        ));
    }
    if let Some(acl) = read(file, path)? {
        let mut entry = std::ptr::null_mut();
        // SAFETY: owned ACL and an initialized native entry output.
        if unsafe { acl_get_entry(acl.0, 0, &mut entry) } == 0 {
            return Err(unsafe_path(
                "Darwin ACL entries remained after removal",
                path,
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINVAL) {
            return Err(io_error("verify Darwin ACL removal", path, error));
        }
    }
    Ok(())
}
