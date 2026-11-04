//! Protect a new account claim before its predictable name is published.
//! The file is created only after its temporary directory's ACL is cleared;
//! even a foreign user who opened that directory earlier must recheck search
//! permission to open a child. The claim is never exposed with an inherited grant.
use super::*;

pub(super) fn create(path: &Path) -> Result<()> {
    let (destination, target) = parent(path)?;
    let nonce = se_types::hex_lower(&super::super::super::random(path)?);
    let private_path = path.with_file_name(format!(".se-claim-stage-{nonce}"));
    let private_name = name(
        private_path
            .file_name()
            .ok_or_else(|| unsafe_path("claim staging name missing", path))?,
        path,
    )?;
    let mut created = Vec::new();
    prepare_created_directory(&private_path, &mut created)?;
    if created.len() != 1 {
        return Err(changed(
            "exclusive claim staging directory was not created; preserved",
            &private_path,
        ));
    }
    let directory = leaf(&destination, &private_name, &private_path, true)?;
    super::super::super::metadata(&directory, &private_path, true)?;
    let source = name(std::ffi::OsStr::new("claim"), path)?;
    let source_path = private_path.join("claim");
    let mut file = None;
    let published = (|| {
        // SAFETY: exclusive literal name beneath the held, ACL-cleared private
        // directory. No child exists before directory privacy is witnessed.
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                source.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        file = Some(owned(
            raw,
            "create unpublished account claim",
            &source_path,
        )?);
        let held = file
            .as_ref()
            .ok_or_else(|| changed("claim staging descriptor unavailable", &source_path))?;
        super::super::super::clear_created_acl(held, &source_path, false)?;
        held.sync_all()
            .map_err(|error| io_error("sync private account claim", &source_path, error))?;
        let (outside, _) = parent(path)?;
        if id(&outside, path, true, false)? != id(&destination, path, true, false)? {
            return Err(changed(
                "account claim parent changed before publication",
                path,
            ));
        }
        // SAFETY: both parents retained, source private and verified, destination
        // one literal name. RENAME_EXCL preserves an independently published winner.
        if unsafe {
            libc::renameatx_np(
                directory.as_raw_fd(),
                source.as_ptr(),
                destination.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_EXCL,
            )
        } < 0
        {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(io_error(
                    "publish protected account claim without replacement",
                    path,
                    error,
                ));
            }
        }
        directory.sync_all().map_err(|error| {
            io_error("sync account claim staging directory", &private_path, error)
        })?;
        destination
            .sync_all()
            .map_err(|error| io_error("sync protected account claim parent", path, error))?;
        Ok(())
    })();
    // A no-replace loser removes only its own held staging file. A changed
    // name refuses and retains the directory rather than deleting an incumbent.
    let cleanup = (|| {
        if let Some(held) = &file {
            match leaf(&directory, &source, &source_path, false) {
                Ok(named) => {
                    if id(&named, &source_path, false, true)?
                        != id(held, &source_path, false, true)?
                    {
                        return Err(changed(
                            "claim staging file changed; preserved",
                            &source_path,
                        ));
                    }
                    // SAFETY: exact private name matches the retained created file.
                    if unsafe { libc::unlinkat(directory.as_raw_fd(), source.as_ptr(), 0) } < 0 {
                        return Err(io_error(
                            "remove unpublished claim loser",
                            &source_path,
                            io::Error::last_os_error(),
                        ));
                    }
                }
                Err(error) if absent(&error) => (),
                Err(error) => return Err(error),
            }
        }
        for custody in created {
            match custody.cleanup()? {
                DirectoryRemoval::Removed | DirectoryRemoval::AlreadyAbsent => (),
                DirectoryRemoval::NotEmpty => {
                    return Err(changed(
                        "private claim staging directory is not empty; preserved",
                        &private_path,
                    ));
                }
            }
        }
        Ok(())
    })();
    cleanup?;
    published
}
