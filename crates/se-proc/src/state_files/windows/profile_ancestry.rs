//! Hold every reparse ancestor while a private profile name is in use.
use super::*;

pub(super) fn pin(root: &Path) -> Result<Vec<File>> {
    let parent = root
        .parent()
        .ok_or_else(|| unsafe_path("profile parent missing", root))?;
    let mut prefix = PathBuf::new();
    let mut pins = Vec::new();
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
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
            continue;
        }
        security::verify_system_ancestor(&observed, &prefix)?;
        let before = crate::windows_native::file_id(&observed)
            .map_err(|cause| io_error("identify profile ancestor", &prefix, cause))?;
        // Denying writes and deletion prevents changing or replacing the
        // reparse point while any provider uses the profile by name.
        let held = open_link(&prefix, FILE_SHARE_READ)?;
        let info = crate::windows_native::file_information(&held)
            .map_err(|cause| io_error("inspect held profile ancestor", &prefix, cause))?;
        if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
            != FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY
        {
            return Err(unsafe_path("profile reparse ancestor changed", &prefix));
        }
        security::verify_system_ancestor(&held, &prefix)?;
        let after = crate::windows_native::file_id(&held)
            .map_err(|cause| io_error("identify held profile ancestor", &prefix, cause))?;
        if before != after {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "profile reparse ancestor was replaced",
                &prefix,
            ));
        }
        pins.push(held);
    }
    Ok(pins)
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
