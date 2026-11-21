//! A completed private-group proof belongs to this process and one unchanged
//! ancestor. Directory metadata and the private final root are still checked
//! on every traversal; account authority is never serialized or shared.
use super::*;
use std::{fs::Metadata, sync::Mutex};

#[derive(Clone, Copy, Eq, PartialEq)]
struct Stamp {
    process: u32,
    user: libc::uid_t,
    group: libc::gid_t,
    device: u64,
    inode: u64,
    owner: u32,
    directory_group: u32,
    mode: u32,
    changed: (i64, i64),
}
impl Stamp {
    fn read(meta: &Metadata) -> Self {
        Self {
            process: std::process::id(),
            // SAFETY: immutable observations of the actual process credentials.
            user: unsafe { libc::geteuid() },
            // SAFETY: immutable observation; credential changes invalidate reuse.
            group: unsafe { libc::getegid() },
            device: meta.dev(),
            inode: meta.ino(),
            owner: meta.uid(),
            directory_group: meta.gid(),
            mode: meta.mode(),
            changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}
pub(super) fn private_group(file: &File, meta: &Metadata, path: &Path) -> Result<bool> {
    static PROOFS: Mutex<Vec<Stamp>> = Mutex::new(Vec::new());
    const MAX_PROOFS: usize = 64;
    let stamp = Stamp::read(meta);
    let mut proofs = PROOFS
        .lock()
        .map_err(|_| unsafe_path("native ancestor proof lock poisoned", path))?;
    if proofs.contains(&stamp) {
        return Ok(true);
    }
    // Never remember false, incomplete or unreadable account observations.
    if !super::private_group(meta.gid(), path)? {
        return Ok(false);
    }
    let after = file
        .metadata()
        .map_err(|e| io_error("recheck proven ancestor", path, e))?;
    if Stamp::read(&after) != stamp {
        return Err(failure(
            StateFileErrorCode::SourceChanged,
            "ancestor changed during native account proof",
            path,
        ));
    }
    // Retain only the newest epoch for this directory and process. The bound
    // limits memory; an uncached ancestor always performs the complete proof.
    proofs.retain(|prior| {
        prior.process == stamp.process
            && !(prior.device == stamp.device && prior.inode == stamp.inode)
    });
    if proofs.len() < MAX_PROOFS {
        proofs.push(stamp);
    }
    Ok(true)
}
