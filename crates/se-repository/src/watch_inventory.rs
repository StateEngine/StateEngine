//! Bound the initial walk before libgit2 materializes its status inventory.
use git2::Repository;
use se_proc::{NativeSourceKind, NativeSourceRoot, NativeWatchDirectory};
use std::{collections::HashSet, path::Path};

const MAX_ENTRIES: usize = 32_768;

pub(super) fn check(
    repository: &Repository,
    root: &Path,
    tracked: &HashSet<String>,
    directories: &HashSet<String>,
    untracked: bool,
) -> Result<(), String> {
    let source = NativeSourceRoot::open(root).map_err(|error| error.to_string())?;
    let mut pending = vec![String::new()];
    let mut pending_bytes = 0usize;
    let mut scanned_bytes = 0usize;
    let mut count = 0usize;
    while let Some(directory) = pending.pop() {
        pending_bytes = pending_bytes.saturating_sub(directory.len());
        let mut cursor = NativeWatchDirectory::open(&source, &directory)
            .map_err(|error| error.to_string())?
            .ok_or("working-tree directory disappeared during inventory")?;
        while let Some(entry) = cursor.next_entry().map_err(|error| error.to_string())? {
            count += 1;
            if count > MAX_ENTRIES {
                return Err("working tree exceeds the watched inventory bound".into());
            }
            let name = entry
                .name
                .to_str()
                .ok_or("working-tree path is not UTF-8")?;
            if !name.is_ascii() {
                return Err("non-ASCII paths require a fresh observation".into());
            }
            if directory.is_empty() && name.eq_ignore_ascii_case(".git") {
                continue;
            }
            let relative = if directory.is_empty() {
                name.to_owned()
            } else {
                format!("{directory}/{name}")
            };
            if relative.len() > 4096 {
                return Err("working-tree path exceeds the watched bound".into());
            }
            scanned_bytes = scanned_bytes.saturating_add(relative.len());
            if scanned_bytes > 4_000_000 {
                return Err("working-tree path inventory exceeds its memory bound".into());
            }
            let folded = relative.to_ascii_lowercase();
            let is_tracked = tracked.contains(&folded);
            let tracked_child = directories.contains(&folded);
            if !untracked && !is_tracked && !tracked_child {
                continue;
            }
            if !is_tracked
                && !tracked_child
                && repository
                    .status_should_ignore(Path::new(&relative))
                    .map_err(|error| error.message().to_owned())?
            {
                continue;
            }
            match entry.kind {
                NativeSourceKind::Directory => {
                    pending_bytes = pending_bytes.saturating_add(relative.len());
                    if pending_bytes > 4_000_000 {
                        return Err("working-tree traversal exceeds its memory bound".into());
                    }
                    pending.push(relative);
                }
                NativeSourceKind::File => (),
                _ => {
                    return Err(
                        "linked or special working-tree paths require a fresh observation".into(),
                    );
                }
            }
        }
    }
    Ok(())
}
