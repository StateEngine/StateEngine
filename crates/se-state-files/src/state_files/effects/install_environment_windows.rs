use crate::state_files::{Result, StateFileErrorCode, failure, io_error};
use std::{cmp::Ordering, ffi::OsStr, os::windows::ffi::OsStrExt, path::Path};
use windows_sys::Win32::Globalization::CompareStringOrdinal;

pub(super) fn build(created: Option<&OsStr>, path: &Path) -> Result<Option<Vec<u16>>> {
    let Some(created) = created else {
        return Ok(None);
    };
    let mut rows: Vec<(Vec<u16>, Vec<u16>)> = std::env::vars_os()
        .filter(|(name, _)| {
            !name
                .to_string_lossy()
                .eq_ignore_ascii_case("SE_INSTALL_CREATED_DIRECTORIES")
        })
        .map(|(name, value)| (name.encode_wide().collect(), value.encode_wide().collect()))
        .collect();
    rows.push((
        "SE_INSTALL_CREATED_DIRECTORIES".encode_utf16().collect(),
        created.encode_wide().collect(),
    ));
    let mut sort_error = None;
    rows.sort_by(|left, right| {
        // SAFETY: retained UTF-16 key slices and explicit bounded capacities.
        let comparison = unsafe {
            CompareStringOrdinal(
                left.0.as_ptr(),
                left.0.len() as i32,
                right.0.as_ptr(),
                right.0.len() as i32,
                1,
            )
        };
        match comparison {
            1 => Ordering::Less,
            2 => Ordering::Equal,
            3 => Ordering::Greater,
            _ => {
                sort_error = Some(std::io::Error::last_os_error());
                Ordering::Equal
            }
        }
    });
    if let Some(error) = sort_error {
        return Err(io_error("sort installer environment", path, error));
    }
    let mut block = Vec::new();
    for (name, value) in rows {
        if name.contains(&0) || value.contains(&0) {
            return Err(failure(
                StateFileErrorCode::Unsupported,
                "installer environment contains NUL",
                path,
            ));
        }
        block.extend(name);
        block.push(b'=' as u16);
        block.extend(value);
        block.push(0);
        if block.len() > 1024 * 1024 {
            return Err(failure(
                StateFileErrorCode::Unsupported,
                "installer environment exceeds two MiB",
                path,
            ));
        }
    }
    block.push(0);
    Ok(Some(block))
}
