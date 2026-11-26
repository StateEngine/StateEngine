//! Resolve installed package data without shell shims, installation or credential reads.
use se_core::harness_selection::catalog::NodePackage;
use se_types::{Result, SeError};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

fn unreadable(error: impl std::fmt::Display) -> SeError {
    se_core::scope::unreadable("installed harness package", &error.to_string())
}

/// Installed package metadata supplies its bin entry; no shim source is executed.
/// Only the installation the resolved executable belongs to is searched.
pub fn node_entrypoint(package: &NodePackage, executable: &Path) -> Result<PathBuf> {
    let root = installed_root(package, executable)?;
    let manifest = root.join("package.json");
    let bytes = se_proc::file_access::read_bounded_regular_file(&manifest, 65536)
        .map_err(|error| unreadable(format!("{}: {error}", manifest.display())))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(unreadable)?;
    if value.get("name").and_then(serde_json::Value::as_str) != Some(package.name.as_str()) {
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
    if !selected.starts_with(&root) || !std::fs::metadata(&selected).map_err(unreadable)?.is_file()
    {
        return Err(unreadable(
            "package bin entry escapes the installed package or is not a file",
        ));
    }
    se_proc::file_access::with_readable_regular_file(&selected, |_| Ok(())).map_err(unreadable)?;
    Ok(selected)
}

/// The package directory of the installation the package's own command comes
/// from: the first PATH directory holding it, as a shell would choose, or the
/// runtime's directory when no command is on PATH. A command that resolves into
/// the package (a symlink, as npm, Bun and Yarn create outside Windows) names it
/// directly. Otherwise every layout of that one installation is checked:
/// exactly one holding the package is selected, none is not found, and more
/// than one refuses as ambiguous instead of picking by name order.
fn installed_root(package: &NodePackage, executable: &Path) -> Result<PathBuf> {
    let command = command_on_path(&package.bin);
    if let Some(command) = &command
        && let Ok(resolved) = se_proc::canonicalize_path(command)
    {
        let package_dir = Path::new("node_modules").join(&package.name);
        if let Some(root) = resolved.ancestors().find(|p| p.ends_with(&package_dir)) {
            return Ok(root.to_path_buf());
        }
    }
    let directory = command
        .as_deref()
        .unwrap_or(executable)
        .parent()
        .ok_or_else(|| unreadable("the installed command has no directory"))?;
    let searched: Vec<PathBuf> = package_roots(directory)?
        .into_iter()
        .map(|modules| modules.join(&package.name))
        .collect();
    let mut holding = Vec::new();
    for root in &searched {
        if holds(root)? {
            let canonical = se_proc::canonicalize_path(root).map_err(unreadable)?;
            if !holding.contains(&canonical) {
                holding.push(canonical);
            }
        }
    }
    match holding.as_slice() {
        [root] => Ok(root.clone()),
        [] => Err(SeError::new(se_types::Detail::ProviderCliNotFound(
            se_types::details::ProviderCliNotFound {
                provider: package.name.clone(),
                searched: searched.iter().map(|p| p.display().to_string()).collect(),
            },
        ))),
        several => Err(unreadable(format!(
            "several global installs beside {} hold {}: {}; remove the extra installs, then retry",
            directory.display(),
            package.name,
            several
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// The first absolute PATH entry holding a runnable copy of the package's
/// command, as a shell chooses: a regular file (through any symlink) that is
/// executable outside Windows, or on Windows its `.exe`, `.cmd`, `.bat` or
/// `.ps1` shim. A directory, broken link or non-executable file of that name,
/// and an entry that cannot be read, are passed over.
fn command_on_path(bin: &str) -> Option<PathBuf> {
    command_in(&std::env::var_os("PATH")?, bin)
}

fn command_in(search_path: &std::ffi::OsStr, bin: &str) -> Option<PathBuf> {
    let names: Vec<String> = if cfg!(windows) {
        ["exe", "cmd", "bat", "ps1"]
            .iter()
            .map(|extension| format!("{bin}.{extension}"))
            .collect()
    } else {
        vec![bin.to_owned()]
    };
    std::env::split_paths(search_path)
        .filter(|directory| directory.is_absolute())
        .find_map(|directory| {
            names
                .iter()
                .map(|name| directory.join(name))
                .find(|candidate| runnable(candidate))
        })
}

/// A regular file the caller may execute with its effective identity, as the
/// operating system decides: owner, group and other classes, and ACLs.
fn runnable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
        && se_proc::file_access::require_executable_access(path).is_ok()
}

/// Whether a candidate package directory has a manifest. A missing path is
/// absence; any other failure to look refuses rather than reading as absent.
fn holds(root: &Path) -> Result<bool> {
    let manifest = root.join("package.json");
    match std::fs::metadata(&manifest) {
        Ok(meta) if meta.is_file() => Ok(true),
        Ok(_) => Err(unreadable(format!(
            "{} is not a regular file",
            manifest.display()
        ))),
        Err(error) if absent(&error) => Ok(false),
        Err(error) => Err(unreadable(format!("{}: {error}", manifest.display()))),
    }
}

/// A missing path, or one whose parent is a file, holds nothing.
fn absent(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

/// The `node_modules` folders a global install from `directory` can use: npm
/// (beside Windows `.cmd`/`.ps1` shims, `lib/node_modules` elsewhere), pnpm
/// (`global/<layout>/node_modules`, or pnpm 11's `global/v<layout>/<group>/
/// node_modules`, under its home or the home above a `bin` directory), Bun
/// (`install/global/node_modules` under `~/.bun`) and Yarn on Windows
/// (`Data/global/node_modules`). Listings are sorted and bounded, and an
/// unreadable or oversized one refuses by name.
fn package_roots(directory: &Path) -> Result<Vec<PathBuf>> {
    let parent = directory.parent().unwrap_or(directory);
    let mut modules = vec![
        directory.join("node_modules"),
        parent.join("lib/node_modules"),
        parent.join("install/global/node_modules"),
        parent.join("Data/global/node_modules"),
    ];
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
    Ok(modules)
}

/// A directory's entries in name order; absent is empty, unreadable refuses.
fn sorted_entries(directory: &Path) -> Result<Vec<PathBuf>> {
    let listing = match std::fs::read_dir(directory) {
        Ok(listing) => listing,
        Err(error) if absent(&error) => return Ok(Vec::new()),
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

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    /// Execute permission for another class does not make a file runnable for
    /// its owner; the search moves on to a copy the caller can execute.
    #[test]
    fn execute_bit_for_another_class_falls_through() -> Result<(), Box<dyn std::error::Error>> {
        let base = std::env::temp_dir().join(format!(
            "se-command-in-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let (first, second) = (base.join("first"), base.join("second"));
        for (directory, mode) in [(&first, 0o001), (&second, 0o755)] {
            std::fs::create_dir_all(directory)?;
            let command = directory.join("tool");
            std::fs::write(&command, b"#!/bin/sh\n")?;
            std::fs::set_permissions(&command, std::fs::Permissions::from_mode(mode))?;
        }
        let search = std::env::join_paths([&first, &second])?;
        let found = super::command_in(&search, "tool");
        // A superuser may execute any file with an execute bit; the selection
        // still follows the operating system's effective answer.
        let owner_may_run =
            se_proc::file_access::require_executable_access(&first.join("tool")).is_ok();
        std::fs::remove_dir_all(&base)?;
        let expected = if owner_may_run { first } else { second };
        assert_eq!(found, Some(expected.join("tool")));
        Ok(())
    }
}
