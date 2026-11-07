use super::args::{invalid, path};
use se_proc::NativeDirectoryCreation;
use se_types::{Result, SeError, Sha256};
use serde::Deserialize;
use sha2::{Digest, Sha256 as Hasher};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
const MAX_MANIFEST: usize = 2 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    variant: String,
    trust: String,
    version: String,
    target: String,
    source_commit: String,
    files: BTreeMap<String, Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    sha256: Sha256,
    bytes: u64,
}
fn read_error(path: &Path, error: impl std::fmt::Display) -> SeError {
    se_core::scope::unreadable(&path.display().to_string(), &error.to_string())
}
fn plain(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        let metadata =
            std::fs::symlink_metadata(ancestor).map_err(|error| read_error(ancestor, error))?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("an archive without linked path components"));
        }
    }
    Ok(())
}
fn checked_file(file: &Path, entry: &Entry) -> Result<()> {
    plain(file)?;
    let mut reader = File::open(file).map_err(|error| read_error(file, error))?;
    let before = reader.metadata().map_err(|error| read_error(file, error))?;
    if !before.is_file() || before.len() != entry.bytes || entry.bytes > 512 * 1024 * 1024 {
        return Err(invalid(
            "bounded regular archive files with their exact recorded sizes",
        ));
    }
    let mut hash = Hasher::new();
    let mut count = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| read_error(file, error))?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if count > entry.bytes {
            return Err(invalid("stable archive file sizes"));
        }
        hash.update(&buffer[..read]);
    }
    let after = reader.metadata().map_err(|error| read_error(file, error))?;
    if count != entry.bytes
        || before.len() != after.len()
        || before.modified().map_err(|error| read_error(file, error))?
            != after.modified().map_err(|error| read_error(file, error))?
        || <[u8; 32]>::from(hash.finalize()) != *entry.sha256.as_bytes()
    {
        return Err(invalid("archive bytes matching every manifest checksum"));
    }
    Ok(())
}
pub(super) fn prepare(creation: &mut NativeDirectoryCreation) -> Result<()> {
    let directories = verify()?;
    let (bin, assets) = program_paths()?;
    creation.prepare(&bin).map_err(native)?;
    creation.prepare(&assets).map_err(native)?;
    for relative in directories {
        creation.prepare(&assets.join(relative)).map_err(native)?;
    }
    Ok(())
}
pub(super) fn verify() -> Result<BTreeSet<PathBuf>> {
    let executable = std::env::current_exe()
        .map_err(|error| read_error(Path::new("archive executable"), error))?;
    let archive = executable
        .parent()
        .ok_or_else(|| invalid("the running archive binary beside its manifest"))?;
    let manifest_path = archive.join("manifest.json");
    plain(&manifest_path)?;
    let mut bytes = Vec::new();
    File::open(&manifest_path)
        .map_err(|error| read_error(&manifest_path, error))?
        .take((MAX_MANIFEST + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| read_error(&manifest_path, error))?;
    if bytes.len() > MAX_MANIFEST {
        return Err(invalid("an archive manifest of at most 2 MiB"));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|error| invalid("the closed se.release/v1 manifest").with_cause(error))?;
    let target = if cfg!(windows) {
        "x86_64-pc-windows-msvc"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(target_os = "macos") {
        "x86_64-apple-darwin"
    } else {
        "x86_64-unknown-linux-gnu"
    };
    if manifest.schema != "se.release/v1"
        || manifest.variant != "standalone"
        || manifest.trust != "unsigned"
        || manifest.target != target
        || manifest.version.is_empty()
        || manifest.source_commit.len() != 40
        || !manifest
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || manifest.files.len() > 4096
    {
        return Err(invalid(
            "a bounded standalone manifest for this native platform",
        ));
    }
    let binary = if cfg!(windows) { "se.exe" } else { "se" };
    if !manifest.files.contains_key(binary)
        || executable.file_name() != Some(std::ffi::OsStr::new(binary))
    {
        return Err(invalid("the manifest's running archive binary"));
    }
    let mut directories = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    for (name, entry) in &manifest.files {
        if name.is_empty()
            || name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_./+-".contains(&byte))
            || !names.insert(if cfg!(windows) {
                name.to_ascii_lowercase()
            } else {
                name.clone()
            })
        {
            return Err(invalid("unique normalized relative archive file paths"));
        }
        total = total
            .checked_add(entry.bytes)
            .ok_or_else(|| invalid("bounded archive payload bytes"))?;
        if total > 4 * 1024 * 1024 * 1024 {
            return Err(invalid("an archive payload of at most 4 GiB"));
        }
        checked_file(&archive.join(name), entry)?;
        if name.starts_with("notices/") {
            let mut parent = Path::new(name).parent();
            while let Some(value) = parent {
                if value.as_os_str().is_empty() {
                    break;
                }
                directories.insert(value.to_owned());
                parent = value.parent();
            }
        }
    }
    Ok(directories)
}
pub(super) fn program_paths() -> Result<(PathBuf, PathBuf)> {
    #[cfg(windows)]
    {
        let root = path(
            &std::env::var_os("LOCALAPPDATA").ok_or_else(|| invalid("an absolute LOCALAPPDATA"))?,
        )?
        .join("StateEngine");
        Ok((root.join("bin"), root.join("installation")))
    }
    #[cfg(not(windows))]
    {
        let home = path(&std::env::var_os("HOME").ok_or_else(|| invalid("an absolute HOME"))?)?;
        Ok((
            home.join(".local/bin"),
            home.join(".local/share/stateengine/installation"),
        ))
    }
}
fn native(error: se_proc::StateFileError) -> SeError {
    se_core::scope::unreadable("native program directory preparation", &error.to_string())
        .with_cause(error)
}
