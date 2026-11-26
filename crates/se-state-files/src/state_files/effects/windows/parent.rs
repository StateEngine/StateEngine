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
    fn open_component(
        pins: &[File],
        prefix: &Path,
        normal_leaf: Option<&std::ffi::OsStr>,
        create_missing: bool,
    ) -> Result<File> {
        match open(prefix, true, 0, false) {
            Ok(file) => Ok(file),
            Err(err) if create_missing && absent(&err) => {
                let Some(leaf) = normal_leaf else {
                    return Err(err);
                };
                let parent_handle = pins
                    .last()
                    .ok_or_else(|| unsafe_path("external ancestor pin missing", prefix))?;
                let access = GENERIC_READ | GENERIC_WRITE | READ_CONTROL | SYNCHRONIZE;
                // SAFETY: `None` security descriptor inherits the verified
                // parent user directory's normal DACL under `parent_handle`.
                match unsafe {
                    created::create_directory_at_optional(parent_handle, leaf, prefix, None, access)
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
                        open(prefix, true, 0, false)
                    }
                    Err(mk_err) => Err(mk_err),
                }
            }
            Err(err) => Err(err),
        }
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
            let file = Self::open_component(&pins, &prefix, normal_leaf, create_missing)?;
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
                security::verify_system_ancestor(&file, &prefix)?;
                // Resolve a trusted ancestor once, then use its held target's final
                // physical path. Later operations never traverse the junction again.
                let raw_name = wide(&prefix)?;
                // SAFETY: retained pathname; this explicit open alone follows the
                // trusted ancestor. All resulting operations use final_path instead.
                let raw = unsafe {
                    CreateFileW(
                        raw_name.as_ptr(),
                        FILE_READ_ATTRIBUTES | READ_CONTROL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        ptr::null(),
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS,
                        ptr::null_mut(),
                    )
                };
                if raw.is_null() || raw == INVALID_HANDLE_VALUE {
                    return Err(last("resolve trusted installation ancestor", &prefix));
                }
                // SAFETY: successful open transfers one uniquely owned handle.
                let target = unsafe { File::from_raw_handle(raw) };
                metadata(&target, &prefix, true, false)?;
                pins.push(file);
                prefix = final_path(&target, &prefix)?;
                target
            } else {
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
        // A separate write-capable pin is used only for the actual final parent,
        // never for drive/system ancestors. It retains native directory flushing.
        if writable {
            let writable = open(&physical, true, GENERIC_READ | GENERIC_WRITE, false)?;
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
