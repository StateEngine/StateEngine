//! Deterministic, bounded global package directory discovery for npm, pnpm,
//! Bun, Yarn, and Volta installations on Unix and Windows.
use std::{
    io::{self, ErrorKind},
    path::{Path, PathBuf},
};

const MAX_LAYOUT_ENTRIES: usize = 256;

/// Candidate `<node_modules>/<package_name>` directories belonging to the
/// global installation that owns `directory` (the bin/shim directory).
/// Listings are sorted and bounded, and an unreadable or oversized directory
/// refuses instead of silently returning absence.
pub fn global_package_roots(directory: &Path, package_name: &str) -> io::Result<Vec<PathBuf>> {
    let parent = directory.parent().unwrap_or(directory);
    let mut modules = vec![
        directory.join("node_modules"),
        parent.join("lib/node_modules"),
        parent.join("install/global/node_modules"),
        parent.join("Data/global/node_modules"),
        parent.join("global/node_modules"),
    ];
    if parent
        .file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new(".yarn"))
        && let Some(home) = parent.parent()
    {
        modules.push(home.join(".config/yarn/global/node_modules"));
    }
    let volta_package = parent.join("tools/image/packages").join(package_name);
    modules.push(volta_package.join("lib/node_modules"));
    modules.push(volta_package.join("node_modules"));

    for home in [directory, parent] {
        for layout in sorted_entries(&home.join("global"))? {
            let Some(name) = layout.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if is_layout(name) {
                modules.push(layout.join("node_modules"));
            } else if name.strip_prefix('v').is_some_and(is_layout) {
                modules.extend(
                    sorted_entries(&layout)?
                        .into_iter()
                        .map(|group| group.join("node_modules")),
                );
            }
        }
    }
    Ok(modules
        .into_iter()
        .map(|base| base.join(package_name))
        .collect())
}

/// Whether `root/package.json` is a regular file. Absence returns `Ok(false)`;
/// unreadable paths or non-file manifests refuse.
pub fn holds_package_manifest(root: &Path) -> io::Result<bool> {
    let manifest = root.join("package.json");
    match std::fs::metadata(&manifest) {
        Ok(meta) if meta.is_file() => Ok(true),
        Ok(_) => Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("{} is not a regular file", manifest.display()),
        )),
        Err(error) if absent(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Find the unique canonical installed package directory under `directory`'s
/// global layouts. Returns `Ok(None)` when absent and refuses on ambiguity.
pub fn unique_installed_root(directory: &Path, package_name: &str) -> io::Result<Option<PathBuf>> {
    let mut holding = Vec::new();
    for root in global_package_roots(directory, package_name)? {
        if holds_package_manifest(&root)? {
            let canonical = se_proc::canonicalize_path(&root)?;
            if !holding.contains(&canonical) {
                holding.push(canonical);
            }
        }
    }
    match holding.as_slice() {
        [] => Ok(None),
        [root] => Ok(Some(root.clone())),
        several => Err(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "several global installs beside {} hold {package_name}: {}; remove the extra installs, then retry",
                directory.display(),
                several
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

/// A missing path, or one whose parent is a file, holds nothing.
pub fn absent(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

fn sorted_entries(directory: &Path) -> io::Result<Vec<PathBuf>> {
    let listing = match std::fs::read_dir(directory) {
        Ok(listing) => listing,
        Err(error) if absent(&error) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut entries = Vec::new();
    for entry in listing {
        let entry = entry?;
        if entries.len() == MAX_LAYOUT_ENTRIES {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "{} lists more than {MAX_LAYOUT_ENTRIES} entries; discovery is incomplete",
                    directory.display()
                ),
            ));
        }
        entries.push(entry.path());
    }
    entries.sort();
    Ok(entries)
}

/// pnpm names each global store layout with a version number.
fn is_layout(name: &str) -> bool {
    !name.is_empty() && name.len() <= 4 && name.bytes().all(|byte| byte.is_ascii_digit())
}
