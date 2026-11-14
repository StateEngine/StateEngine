//! One invocation can retain the opened ancestor chain instead of reopening
//! every prefix. Names, ownership and permissions remain fresh on every access.
use super::*;

struct Entry {
    parent: File,
    name: CString,
    path: PathBuf,
    symlink: bool,
}
#[derive(Default)]
pub(super) struct PinnedPath(Vec<Entry>);
impl PinnedPath {
    pub(super) fn push(&mut self, parent: File, name: CString, path: PathBuf, symlink: bool) {
        self.0.push(Entry {
            parent,
            name,
            path,
            symlink,
        });
    }
    pub(super) fn check(&self, root: &File, path: &Path) -> Result<()> {
        for (index, entry) in self.0.iter().enumerate() {
            let final_component = index + 1 == self.0.len();
            let child = self.0.get(index + 1).map_or(root, |next| &next.parent);
            let held = if final_component {
                metadata(child, path, true)?
            } else {
                ancestors::inspect(child, &entry.path)?
            };
            // SAFETY: initialized stat storage; one retained parent and one
            // original, NUL-terminated component. Never follow a new link.
            let mut named: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: the parent descriptor and component remain live.
            if unsafe {
                libc::fstatat(
                    entry.parent.as_raw_fd(),
                    entry.name.as_ptr(),
                    &mut named,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } < 0
            {
                return Err(io_error(
                    "recheck held directory name",
                    &entry.path,
                    io::Error::last_os_error(),
                ));
            }
            if entry.symlink {
                // SAFETY: immutable observation of the current native user.
                let user = unsafe { libc::geteuid() };
                if named.st_mode & libc::S_IFMT != libc::S_IFLNK
                    || (named.st_uid != 0 && named.st_uid != user)
                {
                    return Err(unsafe_path("trusted ancestor link changed", &entry.path));
                }
                // SAFETY: only the freshly checked trusted system-ancestor
                // link may resolve; its target must still be the held child.
                if unsafe {
                    libc::fstatat(entry.parent.as_raw_fd(), entry.name.as_ptr(), &mut named, 0)
                } < 0
                {
                    return Err(io_error(
                        "recheck trusted ancestor target",
                        &entry.path,
                        io::Error::last_os_error(),
                    ));
                }
            }
            // Native stat device widths differ between Unix platforms.
            #[allow(clippy::unnecessary_cast)]
            let named_identity = (named.st_dev as u64, named.st_ino as u64);
            if named.st_mode & libc::S_IFMT != libc::S_IFDIR
                || named_identity != (held.dev(), held.ino())
            {
                return Err(failure(
                    StateFileErrorCode::SourceChanged,
                    "held directory binding changed",
                    &entry.path,
                ));
            }
        }
        metadata(root, path, true)?;
        Ok(())
    }
}
