//! Resolve installed package data without shell shims, installation or credential reads.
use se_core::harness_selection::catalog::NodePackage;
use se_types::{Result, SeError};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

fn unreadable(error: impl std::fmt::Display) -> SeError {
    se_core::scope::unreadable("installed harness package", &error.to_string())
}

/// Installed package metadata supplies its bin entry; no shim source is executed.
/// Every candidate root still passes the package name and contained-bin checks.
pub fn node_entrypoint(package: &NodePackage, executable: &Path) -> Result<PathBuf> {
    let paths = std::env::var_os("PATH").ok_or_else(|| unreadable("PATH is unavailable"))?;
    let mut directories: Vec<_> = std::env::split_paths(&paths)
        .filter(|p| p.is_absolute())
        .collect();
    if let Some(parent) = executable.parent() {
        directories.push(parent.to_path_buf());
    }
    let mut seen = BTreeSet::new();
    for directory in directories {
        for root in package_roots(&directory, package)? {
            if !seen.insert(root.clone()) {
                continue;
            }
            let manifest = root.join("package.json");
            let bytes = match se_proc::file_access::read_bounded_regular_file(&manifest, 65536) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(unreadable(error)),
            };
            let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(unreadable)?;
            if value.get("name").and_then(serde_json::Value::as_str) != Some(package.name.as_str())
            {
                return Err(unreadable(
                    "installed package name differs from the selected harness",
                ));
            }
            let bin = value
                .get("bin")
                .and_then(|v| v.get(&package.bin).or_else(|| v.as_str().map(|_| v)))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| unreadable("installed package has no selected bin entry"))?;
            let relative = Path::new(bin);
            if relative.is_absolute()
                || relative.components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir
                            | std::path::Component::Prefix(_)
                            | std::path::Component::RootDir
                    )
                })
            {
                return Err(unreadable(
                    "package bin entry is not a relative file inside the package",
                ));
            }
            let selected = se_proc::canonicalize_path(root.join(relative)).map_err(unreadable)?;
            let root = se_proc::canonicalize_path(root).map_err(unreadable)?;
            if !selected.starts_with(&root)
                || !std::fs::metadata(&selected).map_err(unreadable)?.is_file()
            {
                return Err(unreadable(
                    "package bin entry escapes the installed package or is not a file",
                ));
            }
            se_proc::file_access::with_readable_regular_file(&selected, |_| Ok(()))
                .map_err(unreadable)?;
            return Ok(selected);
        }
    }
    Err(SeError::new(se_types::Detail::ProviderCliNotFound(
        se_types::details::ProviderCliNotFound {
            provider: package.name.clone(),
            searched: seen.into_iter().map(|p| p.display().to_string()).collect(),
        },
    )))
}

/// Where global installs from one command directory keep the named package:
/// npm (`node_modules` beside Windows `.cmd`/`.ps1` shims, `lib/node_modules`
/// elsewhere), pnpm (`global/<layout>/node_modules`, or pnpm 11's
/// `global/v<layout>/<group>/node_modules`, under its home or the home above a
/// `bin` directory), Bun (`install/global/node_modules` under `~/.bun`), Yarn
/// on Windows (`Data/global/node_modules`), and any symlinked bin that resolves
/// into a package directory, as Bun and Yarn create outside Windows. Listings
/// are sorted and bounded, and an unreadable or oversized one refuses by name.
fn package_roots(directory: &Path, package: &NodePackage) -> Result<Vec<PathBuf>> {
    let parent = directory.parent().unwrap_or(directory);
    let mut modules = vec![
        directory.join("node_modules"),
        parent.join("lib/node_modules"),
        parent.join("install/global/node_modules"),
        parent.join("Data/global/node_modules"),
    ];
    for home in [directory, parent] {
        modules.extend(pnpm_modules(&home.join("global"), package)?);
    }
    let mut roots: Vec<_> = modules
        .into_iter()
        .map(|modules| modules.join(&package.name))
        .collect();
    let shim = directory.join(&package.bin);
    if std::fs::symlink_metadata(&shim).is_ok_and(|meta| meta.file_type().is_symlink())
        && let Ok(target) = se_proc::canonicalize_path(&shim)
        && let Some(root) = target
            .ancestors()
            .find(|path| path.ends_with(Path::new("node_modules").join(&package.name)))
    {
        roots.push(root.to_path_buf());
    }
    Ok(roots)
}

/// pnpm global stores: `<n>/node_modules` layouts, and pnpm 11 `v<n>/<group>`
/// install groups. Two groups holding the package refuse as ambiguous.
fn pnpm_modules(global: &Path, package: &NodePackage) -> Result<Vec<PathBuf>> {
    let mut modules = Vec::new();
    for layout in sorted_entries(global)? {
        let Some(name) = layout.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if is_layout(name) {
            modules.push(layout.join("node_modules"));
        } else if name.strip_prefix('v').is_some_and(is_layout) {
            let holding: Vec<_> = sorted_entries(&layout)?
                .into_iter()
                .map(|group| group.join("node_modules"))
                .filter(|modules| modules.join(&package.name).join("package.json").is_file())
                .collect();
            if holding.len() > 1 {
                return Err(unreadable(format!(
                    "several pnpm install groups hold {}: {}; remove the extra global installs, then retry",
                    package.name,
                    holding
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
            modules.extend(holding);
        }
    }
    Ok(modules)
}

/// A directory's entries in name order; absent is empty, unreadable refuses.
fn sorted_entries(directory: &Path) -> Result<Vec<PathBuf>> {
    let listing = match std::fs::read_dir(directory) {
        Ok(listing) => listing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(unreadable(format!("{}: {error}", directory.display()))),
    };
    let mut entries = Vec::new();
    for entry in listing {
        let entry =
            entry.map_err(|error| unreadable(format!("{}: {error}", directory.display())))?;
        if entries.len() == 256 {
            return Err(unreadable(format!(
                "{} lists more than 256 entries; discovery is incomplete",
                directory.display()
            )));
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
