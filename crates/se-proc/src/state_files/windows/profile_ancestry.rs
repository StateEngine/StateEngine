//! Hold and recheck the profile's named and resolved ancestors.
use super::*;

pub(super) struct Pin {
    path: PathBuf,
    file: File,
    identity: crate::windows_native::FileIdentity,
    reparse: bool,
    parent: Option<PathBuf>,
}

pub(super) fn pin(root: &Path) -> Result<Vec<Pin>> {
    let mut pins = Vec::new();
    pin_ancestors(root, &mut pins, 0)?;
    Ok(pins)
}

fn pin_ancestors(root: &Path, pins: &mut Vec<Pin>, depth: usize) -> Result<()> {
    if depth >= 32 {
        return Err(unsafe_path(
            "profile reparse chain too deep; remove the redirect loop and retry",
            root,
        ));
    }
    let parent = root
        .parent()
        .ok_or_else(|| unsafe_path("profile parent missing", root))?;
    let mut prefix = PathBuf::new();
    let mut previous: Option<PathBuf> = None;
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
            let prior = previous
                .as_ref()
                .ok_or_else(|| unsafe_path("reparse parent missing", &prefix))?;
            let parent = open_follow(prior)?;
            security::verify_trusted_reparse(&parent, prior)?;
            let target = std::fs::read_link(&prefix)
                .map_err(|cause| io_error("read profile redirect", &prefix, cause))?;
            let target = if target.is_absolute() {
                target
            } else {
                prior.join(target)
            };
            let target = normalize(&target)?;
            pin_ancestors(&target.join("profile-ancestry-probe"), pins, depth + 1)?;
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
            parent: previous.clone(),
        });
        previous = Some(prefix.clone());
    }
    Ok(())
}

pub(super) fn verify(pins: &[Pin]) -> Result<()> {
    for pin in pins {
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
            let prior = pin
                .parent
                .as_ref()
                .ok_or_else(|| unsafe_path("reparse parent missing", &pin.path))?;
            let parent = open_follow(prior)?;
            security::verify_trusted_reparse(&parent, prior)?;
        }
    }
    Ok(())
}

fn normalize(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(part.as_os_str())
            }
            Component::CurDir => (),
            Component::ParentDir if normalized.pop() => (),
            Component::ParentDir => {
                return Err(unsafe_path(
                    "profile redirect escapes its volume; repair the redirect and retry",
                    path,
                ));
            }
        }
    }
    if !normalized.is_absolute() {
        return Err(unsafe_path(
            "absolute profile redirect required; repair the redirect and retry",
            path,
        ));
    }
    Ok(normalized)
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

pub(super) fn open_follow(path: &Path) -> Result<File> {
    let path_wide = wide(path)?;
    // SAFETY: the terminated path and query-only directory flags live through the call.
    let raw = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(last("inspect resolved reparse parent", path));
    }
    // SAFETY: successful creation transfers one owned handle.
    Ok(unsafe { File::from_raw_handle(raw) })
}
