use super::*;

fn final_path(file: &File, path: &Path) -> Result<PathBuf> {
    let mut buffer = vec![0u16; 32768];
    // SAFETY: retained directory handle and initialized owned UTF-16 output buffer.
    let count = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    } as usize;
    if count == 0 || count >= buffer.len() {
        return Err(last("resolve pinned installation parent", path));
    }
    use std::os::windows::ffi::OsStringExt;
    Ok(PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..count],
    )))
}
pub(super) struct Parent {
    pins: Vec<File>,
    pub(super) path: PathBuf,
    pub(super) identity: Identity,
}
impl Parent {
    fn open(path: &Path) -> Result<Self> {
        Self::open_with_access(path, true)
    }
    pub(super) fn open_with_access(path: &Path, writable: bool) -> Result<Self> {
        Self::walk(path, writable, true, true, false)
    }
    pub(super) fn open_for_permission_repair(path: &Path) -> Result<Self> {
        Self::walk(path, false, false, false, false)
    }
    /// Open (and optionally create missing tail directories of) an external
    /// user-owned directory, verifying every pinned ancestor before creating
    /// beneath it and always refusing a reparse point at the final directory.
    pub(super) fn open_external(path: &Path, writable: bool, create_missing: bool) -> Result<Self> {
        Self::walk(path, writable, true, false, create_missing)
    }
    fn open_root(prefix: &Path, access: u32, share: u32) -> Result<File> {
        let name = wide(prefix)?;
        // SAFETY: validated NUL-terminated UTF-16 volume root path; never follows reparse points.
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                READ_CONTROL | FILE_READ_ATTRIBUTES | access,
                share,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(last("pin volume root", prefix));
        }
        // SAFETY: successful CreateFileW transferred unique ownership of `raw`.
        Ok(unsafe { File::from_raw_handle(raw) })
    }
    fn open_component(
        pins: &[File],
        prefix: &Path,
        normal_leaf: Option<&std::ffi::OsStr>,
        create_missing: bool,
        share: u32,
    ) -> Result<File> {
        let Some(leaf) = normal_leaf else {
            return Self::open_root(prefix, 0, share);
        };
        let parent_handle = pins
            .last()
            .ok_or_else(|| unsafe_path("ancestor pin missing", prefix))?;
        let read_access = FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
        match created::open_directory_at(parent_handle, leaf, prefix, read_access, share, true) {
            Ok(file) => Ok(file),
            Err(err) if create_missing && absent(&err) => {
                let create_access = GENERIC_READ | GENERIC_WRITE | READ_CONTROL | SYNCHRONIZE;
                // SAFETY: `None` security descriptor inherits the verified
                // parent user directory's normal DACL under `parent_handle`.
                match unsafe {
                    created::create_directory_at_optional(
                        parent_handle,
                        leaf,
                        prefix,
                        None,
                        create_access,
                        share,
                    )
                } {
                    Ok(created_dir) => {
                        created_dir
                            .sync_all()
                            .map_err(|e| io_error("flush created user directory", prefix, e))?;
                        Ok(created_dir)
                    }
                    Err(mk_err)
                        if mk_err
                            .source
                            .as_ref()
                            .is_some_and(|cause| cause.kind() == io::ErrorKind::AlreadyExists) =>
                    {
                        created::open_directory_at(
                            parent_handle,
                            leaf,
                            prefix,
                            read_access,
                            share,
                            true,
                        )
                    }
                    Err(mk_err) => Err(mk_err),
                }
            }
            Err(err) => Err(err),
        }
    }
    fn follow_reparse(
        pins: &mut Vec<File>,
        file: File,
        prefix: &Path,
        normal_leaf: Option<&std::ffi::OsStr>,
        prev_idx: Option<usize>,
        share: u32,
    ) -> Result<File> {
        if let (Some(leaf), Some(p_idx)) = (normal_leaf, prev_idx) {
            // Re-pin the reparse entry itself with FILE_SHARE_READ only (denying
            // both write and delete sharing) and re-verify its identity and
            // system-ancestor trust so its target cannot be rewritten before follow.
            let write_locked = created::open_directory_at(
                &pins[p_idx],
                leaf,
                prefix,
                FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                FILE_SHARE_READ,
                true,
            )?;
            if metadata(&write_locked, prefix, true, false)?
                != metadata(&file, prefix, true, false)?
            {
                return Err(changed("reparse ancestor changed before follow", prefix));
            }
            security::verify_system_ancestor(&write_locked, prefix)?;
            let target = created::open_directory_at(
                &pins[p_idx],
                leaf,
                prefix,
                FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                share,
                false,
            )?;
            pins.push(write_locked);
            pins.push(file);
            return Ok(target);
        }
        security::verify_system_ancestor(&file, prefix)?;
        let raw_name = wide(prefix)?;
        // SAFETY: retained volume root pathname; explicit open follows trusted reparse.
        let raw = unsafe {
            CreateFileW(
                raw_name.as_ptr(),
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                share,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(last("resolve trusted installation ancestor", prefix));
        }
        pins.push(file);
        // SAFETY: successful open transfers one uniquely owned handle.
        Ok(unsafe { File::from_raw_handle(raw) })
    }
    fn walk(
        path: &Path,
        writable: bool,
        allow_reparse: bool,
        allow_final_reparse: bool,
        create_missing: bool,
    ) -> Result<Self> {
        wide(path)?;
        let components: Vec<_> = path.components().collect();
        let mut prefix = PathBuf::new();
        let mut pins = Vec::new();
        let mut last_normal: Option<(&std::ffi::OsStr, usize)> = None;
        // Keep FILE_SHARE_DELETE on existing state-home walks; external user
        // directory walks deny delete sharing on traversed and final pins.
        let walk_share = if allow_final_reparse {
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        } else {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        };
        for (index, component) in components.iter().enumerate() {
            let final_component = index + 1 == components.len();
            let normal_leaf = match component {
                Component::Prefix(p) => {
                    prefix.push(p.as_os_str());
                    continue;
                }
                Component::RootDir => {
                    prefix.push(component.as_os_str());
                    None
                }
                Component::Normal(n) => {
                    prefix.push(n);
                    Some(*n)
                }
                _ => return Err(unsafe_path("normalized installation parent required", path)),
            };
            let prev_idx = pins.len().checked_sub(1);
            let file =
                Self::open_component(&pins, &prefix, normal_leaf, create_missing, walk_share)?;
            // SAFETY: native POD output and retained file handle.
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
            // SAFETY: correctly typed writable metadata buffer for this live handle.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
                return Err(last("inspect installation ancestor", &prefix));
            }
            let file = if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                if !allow_reparse || (final_component && !allow_final_reparse) {
                    return Err(unsafe_path(
                        "directory custody refuses reparse point",
                        &prefix,
                    ));
                }
                let target = Self::follow_reparse(
                    &mut pins,
                    file,
                    &prefix,
                    normal_leaf,
                    prev_idx,
                    walk_share,
                )?;
                metadata(&target, &prefix, true, false)?;
                prefix = final_path(&target, &prefix)?;
                last_normal = None;
                target
            } else {
                if let (Some(leaf), Some(p_idx)) = (normal_leaf, prev_idx) {
                    last_normal = Some((leaf, p_idx));
                } else {
                    last_normal = None;
                }
                file
            };
            metadata(&file, &prefix, true, false)?;
            pins.push(file);
        }
        let held = pins
            .last()
            .ok_or_else(|| unsafe_path("installation parent missing", path))?;
        let physical = final_path(held, path)?;
        let identity = metadata(held, path, true, false)?;
        if writable {
            let write_access = GENERIC_READ | GENERIC_WRITE | READ_CONTROL | SYNCHRONIZE;
            let writable = if let Some((leaf, p_idx)) = last_normal {
                created::open_directory_at(
                    &pins[p_idx],
                    leaf,
                    &physical,
                    write_access,
                    walk_share,
                    true,
                )?
            } else {
                Self::open_root(&physical, GENERIC_READ | GENERIC_WRITE, walk_share)?
            };
            if metadata(&writable, path, true, false)? != identity {
                return Err(changed("installation parent changed during open", path));
            }
            pins.push(writable);
        }
        Ok(Self {
            pins,
            path: physical,
            identity,
        })
    }
    pub(super) fn file(&self) -> Result<&File> {
        self.pins
            .last()
            .ok_or_else(|| unsafe_path("installation parent pin missing", &self.path))
    }
    pub(super) fn sync(&self, path: &Path) -> Result<()> {
        self.file()?
            .sync_all()
            .map_err(|e| io_error("flush installation parent", path, e))
    }
}
pub(super) fn location(path: &Path) -> Result<(Parent, PathBuf)> {
    let parent = path
        .parent()
        .ok_or_else(|| unsafe_path("cannot mutate volume root", path))?;
    let name = path
        .file_name()
        .ok_or_else(|| unsafe_path("installation leaf missing", path))?;
    wide(path)?;
    let parent = Parent::open(parent)?;
    let physical = parent.path.join(name);
    Ok((parent, physical))
}
