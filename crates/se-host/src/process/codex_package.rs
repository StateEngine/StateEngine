//! Preserve the installed package launcher's environment when selecting its
//! native payload. Discovery runs in the existing bounded filesystem job.
use std::{
    ffi::OsString,
    fs, io,
    io::Read,
    path::{Path, PathBuf},
};

pub(in crate::process) struct PackageLaunch {
    root: PathBuf,
    marker: &'static str,
    search: Option<PathBuf>,
}
impl PackageLaunch {
    pub(in crate::process) fn observe(
        root: PathBuf,
        image: &Path,
        launcher: &Path,
    ) -> io::Result<Self> {
        let root = fs::canonicalize(root)?;
        let marker = manager(&root, launcher)?;
        // Ownership uses canonical spelling; the launcher exports a plain
        // Windows path when that spelling names the same destination.
        #[cfg(windows)]
        let root = se_proc::canonicalize_path(&root)?;
        let search = image
            .parent()
            .and_then(Path::parent)
            .map(|path| path.join("path"));
        let search = match search {
            Some(path) if directory(&path)? => Some(path),
            _ => None,
        };
        Ok(Self {
            root,
            marker,
            search,
        })
    }
    pub(in crate::process) fn apply(
        self,
        environment: &mut se_proc::Environment,
    ) -> io::Result<()> {
        environment.entries.retain(|(key, _)| {
            !matches!(
                key.to_string_lossy().to_ascii_uppercase().as_str(),
                "CODEX_MANAGED_PACKAGE_ROOT"
                    | "CODEX_MANAGED_BY_NPM"
                    | "CODEX_MANAGED_BY_BUN"
                    | "CODEX_MANAGED_BY_PNPM"
                    | "CODEX_MANAGED_BY_VITE_PLUS"
            )
        });
        environment.entries.push((
            "CODEX_MANAGED_PACKAGE_ROOT".into(),
            self.root.into_os_string(),
        ));
        environment.entries.push((self.marker.into(), "1".into()));
        if let Some(search) = self.search {
            let prior = environment
                .entries
                .iter()
                .find(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case("PATH"))
                .map(|(_, value)| value.clone());
            let paths = std::iter::once(search)
                .chain(prior.as_deref().into_iter().flat_map(std::env::split_paths));
            let path = std::env::join_paths(paths)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            environment
                .entries
                .retain(|(key, _)| !key.to_string_lossy().eq_ignore_ascii_case("PATH"));
            environment.entries.push((OsString::from("PATH"), path));
        }
        Ok(())
    }
}
fn directory(path: &Path) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
fn same_package(node_modules: &Path, root: &Path) -> io::Result<bool> {
    match fs::canonicalize(node_modules.join("@openai/codex")) {
        Ok(package) => Ok(package == root),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
fn metadata(path: &Path) -> io::Result<Option<serde_json::Value>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Codex package ownership metadata exceeds 64 KiB",
        ));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}
fn alternate_owner(ancestor: &Path, root: &Path) -> io::Result<bool> {
    if ancestor.file_name().is_none_or(|name| name != "packages") {
        return Ok(false);
    }
    let Some(value) = metadata(&ancestor.join("@openai/codex.json"))? else {
        return Ok(false);
    };
    if value.get("name").and_then(serde_json::Value::as_str) != Some("@openai/codex") {
        return Ok(false);
    }
    let id = value
        .get("installId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let directory = if id.starts_with('#') {
        ancestor.join(format!("@openai/codex{id}"))
    } else {
        ancestor.join("@openai/codex").join(id)
    };
    for modules in [
        directory.join("lib/node_modules"),
        directory.join("node_modules"),
    ] {
        if same_package(&modules, root)? {
            return Ok(true);
        }
    }
    Ok(false)
}
fn manager(root: &Path, launcher: &Path) -> io::Result<&'static str> {
    for start in [root, launcher.parent().unwrap_or(root)] {
        for ancestor in start.ancestors() {
            if alternate_owner(ancestor, root)? {
                return Ok("CODEX_MANAGED_BY_VITE_PLUS");
            }
            let modules = ancestor.join("node_modules");
            if modules.join(".modules.yaml").try_exists()? && same_package(&modules, root)? {
                return Ok("CODEX_MANAGED_BY_PNPM");
            }
        }
    }
    let spelling = root.to_string_lossy().replace('\\', "/");
    if spelling.contains(".bun/install/global") {
        Ok("CODEX_MANAGED_BY_BUN")
    } else {
        // The provider's admitted environment excludes package-manager user
        // agents; the launcher likewise defaults to this marker without one.
        Ok("CODEX_MANAGED_BY_NPM")
    }
}
