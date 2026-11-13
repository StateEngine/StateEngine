//! Resolve installed package data without shell shims, installation or credential reads.
use se_core::harness_selection::catalog::NodePackage;
use se_types::{Result, SeError};
use std::{
    collections::BTreeSet,
    io::Read,
    path::{Path, PathBuf},
};

fn unreadable(error: impl std::fmt::Display) -> SeError {
    se_core::scope::unreadable("installed harness package", &error.to_string())
}

/// Installed package metadata supplies its bin entry; no shim source is executed.
pub fn node_entrypoint(package: &NodePackage, executable: &Path) -> Result<PathBuf> {
    let paths = std::env::var_os("PATH").ok_or_else(|| unreadable("PATH is unavailable"))?;
    let mut directories: Vec<_> = std::env::split_paths(&paths)
        .filter(|p| p.is_absolute())
        .collect();
    if let Some(parent) = executable.parent() {
        directories.insert(0, parent.to_path_buf());
    }
    let mut seen = BTreeSet::new();
    for directory in directories {
        let roots = [
            directory.join("node_modules"),
            directory
                .parent()
                .unwrap_or(&directory)
                .join("lib/node_modules"),
        ];
        for root in roots {
            let root = root.join(&package.name);
            if !seen.insert(root.clone()) {
                continue;
            }
            let manifest = root.join("package.json");
            let mut file = match std::fs::File::open(&manifest) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(unreadable(error)),
            };
            let mut bytes = Vec::new();
            file.by_ref()
                .take(65537)
                .read_to_end(&mut bytes)
                .map_err(unreadable)?;
            if bytes.len() > 65536 {
                return Err(unreadable("package metadata exceeds 64 KiB"));
            }
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
