use super::*;
use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};

pub(in crate::state_files) struct CreatedDirectory {
    path: PathBuf,
    parent: File,
    name: CString,
    file: File,
    identity: (u64, u64),
}
fn random_name(path: &Path, prefix: &str) -> Result<CString> {
    let nonce = super::super::random(path)?;
    let suffix: String = se_types::hex_lower(&nonce);
    name(std::ffi::OsStr::new(&format!("{prefix}{suffix}")), path)
}
impl CreatedDirectory {
    pub(in crate::state_files) fn path(&self) -> &Path {
        &self.path
    }
    pub(in crate::state_files) fn cleanup(&self) -> Result<DirectoryRemoval> {
        let (parent, _) = creation_parent(&self.path)?;
        if id(&parent, &self.path, true, false)? != id(&self.parent, &self.path, true, false)? {
            return Err(changed(
                "created directory parent was replaced; preserved",
                &self.path,
            ));
        }
        let named = match leaf(&self.parent, &self.name, &self.path, true) {
            Ok(file) => file,
            Err(error) if absent(&error) => return Ok(DirectoryRemoval::AlreadyAbsent),
            Err(error) => return Err(error),
        };
        if id(&named, &self.path, true, true)? != self.identity
            || id(&self.file, &self.path, true, true)? != self.identity
        {
            return Err(changed(
                "created directory identity differs; preserved",
                &self.path,
            ));
        }
        let quarantine = random_name(&self.path, ".se-dir-cleanup-")?;
        move_no_replace(&self.parent, &self.name, &quarantine, &self.path)?;
        let moved = leaf(&self.parent, &quarantine, &self.path, true)?;
        if id(&moved, &self.path, true, true)? != self.identity {
            move_no_replace(&self.parent, &quarantine, &self.name, &self.path)?;
            return Err(changed(
                "created directory changed at cleanup; restored",
                &self.path,
            ));
        }
        // SAFETY: retained trusted parent and exclusive random quarantine name,
        // verified against the exact created directory; no recursive deletion.
        if unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                quarantine.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } < 0
        {
            let cause = io::Error::last_os_error();
            move_no_replace(&self.parent, &quarantine, &self.name, &self.path)?;
            return if matches!(
                cause.raw_os_error(),
                Some(libc::ENOTEMPTY) | Some(libc::EEXIST)
            ) {
                Ok(DirectoryRemoval::NotEmpty)
            } else {
                Err(io_error(
                    "remove retained created directory",
                    &self.path,
                    cause,
                ))
            };
        }
        self.parent
            .sync_all()
            .map_err(|error| io_error("sync created-directory cleanup", &self.path, error))?;
        match leaf(&self.parent, &self.name, &self.path, true) {
            Err(error) if absent(&error) => Ok(DirectoryRemoval::Removed),
            Err(error) => Err(error),
            Ok(_) => Err(changed(
                "directory pathname reappeared after cleanup; preserved",
                &self.path,
            )),
        }
    }
}
pub(in crate::state_files) fn prepare_created_directory(
    path: &Path,
    created: &mut Vec<CreatedDirectory>,
) -> Result<()> {
    let (parent, target) = creation_parent(path)?;
    // Inspect the actual named entry first: a trusted system-ancestor symlink
    // is the owning walk's to resolve under the same ownership rule, and it
    // must not be mistaken for an owned child. A foreign link refuses here with
    // the walk's own verdict instead of the leaf's.
    // SAFETY: initialized no-follow stat output, retained parent, literal name.
    let mut entry: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the same no-follow entry query into the initialized stat above.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            target.as_ptr(),
            &mut entry,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
        && entry.st_mode & libc::S_IFMT == libc::S_IFLNK
    {
        // SAFETY: geteuid has no pointers or process-wide mutation.
        if entry.st_uid != 0 && entry.st_uid != unsafe { libc::geteuid() } {
            return Err(unsafe_path("untrusted or private-directory symlink", path));
        }
        return Ok(());
    }
    match leaf(&parent, &target, path, true) {
        Ok(file) => return trusted_directory(&file, path, false),
        Err(error) if absent(&error) => (),
        Err(error) => return Err(error),
    }
    let staging = random_name(path, ".se-dir-stage-")?;
    // SAFETY: exclusive random private directory beneath the retained trusted
    // parent. The final name is published only after opening this staging object.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), staging.as_ptr(), 0o700) } < 0 {
        return Err(io_error(
            "create unpublished directory staging",
            path,
            io::Error::last_os_error(),
        ));
    }
    let stage_path = path.with_file_name(std::ffi::OsStr::from_bytes(staging.to_bytes()));
    let file = leaf(&parent, &staging, &stage_path, true)?;
    let identity = id(&file, &stage_path, true, true)?;
    // Creation mode is masked by the caller's umask. Publish only after an
    // explicit handle-based 0700 update and a native metadata readback.
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(|error| io_error("protect created staging directory", &stage_path, error))?;
    #[cfg(target_os = "macos")]
    super::super::clear_created_acl(&file, &stage_path, true)?;
    let stat = file
        .metadata()
        .map_err(|error| io_error("inspect created staging directory", path, error))?;
    if stat.mode() & 0o777 != 0o700 {
        return Err(unsafe_path(
            "created directory staging is not private",
            path,
        ));
    }
    file.sync_all()
        .map_err(|error| io_error("flush private directory staging", path, error))?;
    if let Err(error) = move_no_replace(&parent, &staging, &target, path) {
        let stage_path = path.with_file_name(std::ffi::OsStr::from_bytes(staging.to_bytes()));
        let custody = CreatedDirectory {
            path: stage_path,
            parent,
            name: staging,
            file,
            identity,
        };
        match custody.cleanup() {
            Ok(DirectoryRemoval::Removed | DirectoryRemoval::AlreadyAbsent) => (),
            Ok(DirectoryRemoval::NotEmpty) => {
                created.push(custody);
                return Err(error);
            }
            Err(cleanup) => {
                created.push(custody);
                return Err(cleanup);
            }
        }
        if error
            .source
            .as_ref()
            .is_some_and(|cause| cause.kind() == io::ErrorKind::AlreadyExists)
        {
            return Ok(());
        }
        return Err(error);
    }
    let custody = CreatedDirectory {
        path: path.into(),
        parent,
        name: target,
        file,
        identity,
    };
    created.push(custody);
    let held = created
        .last()
        .ok_or_else(|| changed("created directory custody unavailable", path))?;
    let outside = leaf(&held.parent, &held.name, path, true)?;
    if id(&outside, path, true, true)? != held.identity {
        return Err(changed(
            "created directory publication identity differs",
            path,
        ));
    }
    held.parent
        .sync_all()
        .map_err(|error| io_error("flush created directory publication", path, error))
}

fn creation_parent(path: &Path) -> Result<(File, CString)> {
    components(path)?;
    let directory = path
        .parent()
        .ok_or_else(|| unsafe_path("directory parent missing", path))?;
    let leaf_name = path
        .file_name()
        .ok_or_else(|| unsafe_path("directory leaf missing", path))?;
    Ok((
        super::super::walk_effect_parent_for_creation(directory)?,
        name(leaf_name, path)?,
    ))
}

pub(in crate::state_files) fn validate_creation_target(path: &Path) -> Result<()> {
    let (parent, name) = creation_parent(path)?;
    let file = leaf(&parent, &name, path, true)?;
    id(&file, path, true, true)?;
    trusted_directory(&file, path, true)
}
