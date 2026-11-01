//! Verify an inherited native-account claim without accepting a busy stranger.
use super::*;

pub(in crate::state_files) fn inherited_installation_claim(raw: libc::c_int) -> Result<File> {
    use std::os::fd::FromRawFd;
    let path = installation_claim_path()?;
    // SAFETY: duplicate a caller-designated descriptor without taking ownership
    // of the shell's original retained claim. Invalid descriptors refuse.
    let duplicate = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io_error(
            "duplicate inherited installation claim",
            &path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: fcntl transferred this newly allocated descriptor to us.
    let inherited = unsafe { File::from_raw_fd(duplicate) };
    let (directory, name) = parent(&path)?;
    let observed = leaf(&directory, &name, &path, false)?;
    if id(&inherited, &path, false, true)? != id(&observed, &path, false, true)?
        || inherited
            .metadata()
            .map_err(|e| io_error("inspect inherited claim protection", &path, e))?
            .mode()
            & 0o077
            != 0
    {
        return Err(unsafe_path(
            "inherited descriptor is not the private native account claim",
            &path,
        ));
    }
    #[cfg(target_os = "macos")]
    metadata::check_directory_acl(&inherited, &path)?;
    // A fresh open must be excluded, while the inherited open file description
    // must already own the exclusive lock. A busy unrelated holder is no proof.
    // SAFETY: nonblocking locks on retained descriptors for this exact claim.
    if unsafe { libc::flock(observed.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Err(unsafe_path(
            "installation worker has no live inherited claim",
            &path,
        ));
    }
    let busy = io::Error::last_os_error();
    if busy.kind() != io::ErrorKind::WouldBlock {
        return Err(io_error("observe inherited claim exclusion", &path, busy));
    }
    lock(&inherited, &path)?;
    Ok(inherited)
}
