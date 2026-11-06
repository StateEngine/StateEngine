//! Landlock confines all helper object opens, including symlink races, to the
//! registered object inode hierarchy. Runtime grants name individual ELF files.
use super::*;
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::PathBuf,
};
const EXECUTE: u64 = 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
#[repr(C, packed)]
struct Beneath {
    access: u64,
    parent: i32,
}
pub(super) struct Filesystem(File);
impl Filesystem {
    pub(super) fn new(image: &Path, roots: [&crate::NativeSourceRoot; 2]) -> io::Result<Self> {
        // ABI 1 contains every read/execute right this boundary needs. Refuse
        // unavailable Landlock; never fall back to pathname-only validation.
        let rights: u64 = (1 << 13) - 1;
        // SAFETY: initialized ABI-1 ruleset attribute and its exact size.
        let fd = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &rights, 8, 0) };
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "Git object confinement requires Landlock: {}",
                    io::Error::last_os_error()
                ),
            ));
        }
        // SAFETY: create_ruleset returned a fresh owned descriptor.
        let rules = Self(unsafe { File::from_raw_fd(fd as i32) });
        for root in roots {
            root.check()?;
            rules.allow_handle(root.directory_handle(), READ_FILE | READ_DIR)?;
        }
        rules.allow(Path::new("/dev/null"), READ_FILE | (1 << 1))?;
        match rules.allow(Path::new("/etc/ld.so.cache"), READ_FILE) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        let mut pending = vec![image.canonicalize()?];
        let mut seen = Vec::<PathBuf>::new();
        while let Some(path) = pending.pop() {
            let path = path.canonicalize()?;
            if seen.contains(&path) {
                continue;
            }
            if seen.len() == 32 {
                return Err(invalid("Git runtime library set exceeds 32 images"));
            }
            pending.extend(super::elf::dependencies(&path)?);
            rules.allow(&path, READ_FILE | EXECUTE)?;
            seen.push(path);
        }
        Ok(rules)
    }
    fn allow(&self, path: &Path, access: u64) -> io::Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        if file.metadata()?.file_type().is_symlink() {
            return Err(invalid("Git confinement root must not be a link"));
        }
        self.allow_handle(&file, access)
    }
    fn allow_handle(&self, file: &File, access: u64) -> io::Result<()> {
        let rule = Beneath {
            access,
            parent: file.as_raw_fd(),
        };
        // SAFETY: retained file and ruleset descriptors; packed ABI attribute.
        if unsafe { libc::syscall(libc::SYS_landlock_add_rule, self.0.as_raw_fd(), 1, &rule, 0) }
            < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub(super) fn enter(&self) -> io::Result<()> {
        // SAFETY: pre-exec uses only native calls over the retained ruleset.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a live retained ruleset descriptor with no optional flags.
        if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, self.0.as_raw_fd(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
