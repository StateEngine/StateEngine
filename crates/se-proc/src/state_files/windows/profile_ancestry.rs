//! Hold and recheck the profile's named and resolved ancestors.
use super::*;

pub(super) struct Pin {
    path: PathBuf,
    file: File,
    identity: crate::windows_native::FileIdentity,
    reparse: bool,
}

pub(super) fn pin(root: &Path) -> Result<Vec<Pin>> {
    let mut pins = pin_ancestors(root)?;
    let resolved = std::fs::canonicalize(root)
        .map_err(|cause| io_error("resolve private profile ancestry", root, cause))?;
    pins.extend(pin_ancestors(&resolved)?);
    Ok(pins)
}

fn pin_ancestors(root: &Path) -> Result<Vec<Pin>> {
    let parent = root
        .parent()
        .ok_or_else(|| unsafe_path("profile parent missing", root))?;
    let mut prefix = PathBuf::new();
    let mut pins: Vec<Pin> = Vec::new();
    for component in parent.components() {
        match component {
            Component::Prefix(value) => {
                prefix.push(value.as_os_str());
                continue;
            }
            Component::RootDir => prefix.push(component.as_os_str()),
            Component::Normal(value) => prefix.push(value),
            _ => return Err(unsafe_path("normalized profile ancestry required", root)),
        }
        let observed = open_link(
            &prefix,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
        let info = crate::windows_native::file_information(&observed)
            .map_err(|cause| io_error("inspect profile ancestor", &prefix, cause))?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(unsafe_path("profile ancestor is not a directory", &prefix));
        }
        let reparse = info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        if reparse {
            security::verify_trusted_reparse(&observed, &prefix)?;
            let prior = pins
                .last()
                .ok_or_else(|| unsafe_path("reparse parent missing", &prefix))?;
            security::verify_trusted_reparse(&prior.file, &prior.path)?;
        }
        let before = crate::windows_native::file_id(&observed)
            .map_err(|cause| io_error("identify profile ancestor", &prefix, cause))?;
        let held = open_link(&prefix, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
        let after = crate::windows_native::file_id(&held)
            .map_err(|cause| io_error("identify held profile ancestor", &prefix, cause))?;
        let info = crate::windows_native::file_information(&held)
            .map_err(|cause| io_error("inspect held profile ancestor", &prefix, cause))?;
        if before != after
            || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0) != reparse
        {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "profile ancestor was replaced",
                &prefix,
            ));
        }
        pins.push(Pin {
            path: prefix.clone(),
            file: held,
            identity: after,
            reparse,
        });
    }
    Ok(pins)
}

pub(super) fn verify(pins: &[Pin]) -> Result<()> {
    for (index, pin) in pins.iter().enumerate() {
        let current = open_link(
            &pin.path,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
        let info = crate::windows_native::file_information(&current)
            .map_err(|cause| io_error("inspect current profile ancestor", &pin.path, cause))?;
        let current_id = crate::windows_native::file_id(&current)
            .map_err(|cause| io_error("identify current profile ancestor", &pin.path, cause))?;
        let held_id = crate::windows_native::file_id(&pin.file)
            .map_err(|cause| io_error("identify held profile ancestor", &pin.path, cause))?;
        if current_id != pin.identity
            || held_id != pin.identity
            || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0) != pin.reparse
        {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "profile ancestor was replaced",
                &pin.path,
            ));
        }
        if pin.reparse {
            security::verify_trusted_reparse(&current, &pin.path)?;
            let prior = index
                .checked_sub(1)
                .and_then(|i| pins.get(i))
                .ok_or_else(|| unsafe_path("reparse parent missing", &pin.path))?;
            security::verify_trusted_reparse(&prior.file, &prior.path)?;
        }
    }
    Ok(())
}

fn open_link(path: &Path, share: u32) -> Result<File> {
    let path_wide = wide(path)?;
    // SAFETY: the terminated name and fixed no-follow flags live through the call.
    let raw = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            share,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(last("pin profile ancestor", path));
    }
    // SAFETY: successful creation transfers one owned handle.
    Ok(unsafe { File::from_raw_handle(raw) })
}
