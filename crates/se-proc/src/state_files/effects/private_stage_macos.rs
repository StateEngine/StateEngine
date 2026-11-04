//! Publish new Darwin files only after private creation and verified protection.
//! The file is created only after its temporary directory's ACL is cleared;
//! even a foreign user who opened that directory earlier must recheck search
//! permission to open a child. Public profile permissions are copied before publication.
use super::*;

pub(super) fn create_claim(path: &Path) -> Result<()> {
    create(path, None, true, |_| Ok(())).map(drop)
}
pub(super) fn create_profile(
    path: &Path,
    source: &File,
    write: impl FnOnce(&mut File) -> Result<()>,
) -> Result<File> {
    create(path, Some(source), false, write)?
        .ok_or_else(|| changed("exclusive profile staging was not published", path))
}
fn create(
    path: &Path,
    protection_source: Option<&File>,
    accept_winner: bool,
    write: impl FnOnce(&mut File) -> Result<()>,
) -> Result<Option<File>> {
    let (destination, target) = parent(path)?;
    let nonce = se_types::hex_lower(&super::super::random(path)?);
    let private_path = path.with_file_name(format!(".se-private-file-{nonce}"));
    let private_name = name(
        private_path
            .file_name()
            .ok_or_else(|| unsafe_path("private file staging name missing", path))?,
        path,
    )?;
    let mut created = Vec::new();
    prepare_created_directory(&private_path, &mut created)?;
    if created.len() != 1 {
        return Err(changed(
            "exclusive private file staging directory was not created; preserved",
            &private_path,
        ));
    }
    let directory = leaf(&destination, &private_name, &private_path, true)?;
    super::super::metadata(&directory, &private_path, true)?;
    let source = name(std::ffi::OsStr::new("file"), path)?;
    let source_path = private_path.join("file");
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
        file = Some(owned(raw, "create unpublished private file", &source_path)?);
        let held = file
            .as_mut()
            .ok_or_else(|| changed("private file staging descriptor unavailable", &source_path))?;
        super::super::clear_created_acl(held, &source_path, false)?;
        write(held)?;
        if let Some(source) = protection_source {
            copy_profile_protection(source, held, path)?;
        }
        held.sync_all()
            .map_err(|error| io_error("sync private file", &source_path, error))?;
        let (outside, _) = parent(path)?;
        if id(&outside, path, true, false)? != id(&destination, path, true, false)? {
            return Err(changed(
                "private file parent changed before publication",
                path,
            ));
        }
        // SAFETY: both parents retained, source private and verified, destination
        // one literal name. RENAME_EXCL preserves an independently published winner.
        let renamed = unsafe {
            libc::renameatx_np(
                directory.as_raw_fd(),
                source.as_ptr(),
                destination.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if renamed < 0 {
            let error = io::Error::last_os_error();
            if !accept_winner || error.kind() != io::ErrorKind::AlreadyExists {
                return Err(io_error(
                    "publish protected private file without replacement",
                    path,
                    error,
                ));
            }
        }
        directory.sync_all().map_err(|error| {
            io_error("sync private file staging directory", &private_path, error)
        })?;
        destination
            .sync_all()
            .map_err(|error| io_error("sync protected private file parent", path, error))?;
        Ok(renamed == 0)
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
                            "private file staging file changed; preserved",
                            &source_path,
                        ));
                    }
                    // SAFETY: exact private name matches the retained created file.
                    if unsafe { libc::unlinkat(directory.as_raw_fd(), source.as_ptr(), 0) } < 0 {
                        return Err(io_error(
                            "remove unpublished private file loser",
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
                        "private file staging directory is not empty; preserved",
                        &private_path,
                    ));
                }
            }
        }
        Ok(())
    })();
    cleanup?;
    if published? { Ok(file) } else { Ok(None) }
}

fn copy_profile_protection(source: &File, target: &File, path: &Path) -> Result<()> {
    let original = source
        .metadata()
        .map_err(|error| io_error("inspect original profile protection", path, error))?;
    let acl = super::super::acl::snapshot(source, path)?;
    metadata::copy(source, target, path)?;
    let current = source
        .metadata()
        .map_err(|error| io_error("recheck original profile protection", path, error))?;
    let copied = target
        .metadata()
        .map_err(|error| io_error("read back staged profile protection", path, error))?;
    if metadata::stamp(&original) != metadata::stamp(&current)
        || acl != super::super::acl::snapshot(source, path)?
        || (original.uid(), original.gid(), original.mode())
            != (copied.uid(), copied.gid(), copied.mode())
        || acl != super::super::acl::snapshot(target, path)?
    {
        return Err(changed(
            "profile protection changed or staging copy differs; unpublished",
            path,
        ));
    }
    Ok(())
}
