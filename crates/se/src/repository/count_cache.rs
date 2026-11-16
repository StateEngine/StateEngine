//! Optional exact history counts. Branch and working-tree facts are never cached.
use se_proc::NativeSourceRoot;
use se_store::StateFiles;
use se_types::Read as StateRead;
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const MAX_ENTRY: u64 = 256;
const MAX_METADATA: u64 = 4_000_000;

pub(super) struct CountCache<'a> {
    repository: &'a Path,
    files: &'a dyn StateFiles,
    path: PathBuf,
    identity: [u8; 32],
    head: &'a str,
    previous: Option<Vec<u8>>,
}

impl<'a> CountCache<'a> {
    pub(super) fn open(
        repository: &'a Path,
        head: &'a str,
        files: &'a dyn StateFiles,
        home: &Path,
    ) -> Option<Self> {
        let identity = identity(repository).ok()?;
        let name: String = identity.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = home.join(format!("git-count-{name}"));
        let previous = protected_read(files, &path).ok()?;
        Some(Self {
            repository,
            files,
            path,
            identity,
            head,
            previous,
        })
    }

    pub(super) fn count(&self) -> Option<u64> {
        let text = std::str::from_utf8(self.previous.as_ref()?).ok()?;
        let mut fields = text.lines();
        if fields.next()? != "git-count-v1" || fields.next()? != self.head {
            return None;
        }
        let count = fields.next()?.parse().ok()?;
        if fields.next().is_some() {
            return None;
        }
        Some(count)
    }

    pub(super) fn save(self, count: u64) {
        // Recheck history interpretation after the authoritative walk. Cache
        // failure never changes or suppresses the fresh observation.
        if identity(self.repository).ok() != Some(self.identity) {
            return;
        }
        let bytes = format!("git-count-v1\n{}\n{count}\n", self.head).into_bytes();
        if let Some(previous) = self.previous {
            let _ =
                self.files
                    .replace_owned(&self.path, Some(Sha256::digest(previous).into()), &bytes);
        } else {
            self.publish(&bytes);
        }
    }

    fn publish(&self, bytes: &[u8]) {
        let Some(directory) = self.path.parent() else {
            return;
        };
        let Ok(mut staged) = self.files.create_staging(directory) else {
            return;
        };
        let written = staged
            .file
            .write_all(bytes)
            .and_then(|()| staged.file.sync_all());
        drop(staged.file);
        if written.is_ok()
            && self
                .files
                .publish_no_replace(&staged.path, &self.path)
                .is_ok()
        {
            return;
        }
        // Another observer may have won the publication. Retire only our own
        // bounded staging bytes; leave its count and every other file intact.
        if let Ok(Some(bytes)) = protected_read(self.files, &staged.path) {
            let _ = self
                .files
                .remove_owned(&staged.path, Sha256::digest(bytes).into());
        }
    }
}

fn protected_read(files: &dyn StateFiles, path: &Path) -> io::Result<Option<Vec<u8>>> {
    match files.readback(path).map_err(io::Error::other)? {
        StateRead::Absent { .. } => Ok(None),
        StateRead::Present { value } => {
            let mut bytes = Vec::new();
            value.take(MAX_ENTRY + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_ENTRY {
                return Err(unsupported());
            }
            Ok(Some(bytes))
        }
        _ => Err(unsupported()),
    }
}

/// A commit object's ancestry is immutable, except when Git interprets it
/// through shallow boundaries, grafts or replacement refs. Unsupported or
/// unreadable metadata simply retains the original bounded Git walk.
fn identity(repository: &Path) -> io::Result<[u8; 32]> {
    if std::env::vars_os().any(|(name, _)| {
        let name = name.to_string_lossy().to_ascii_uppercase();
        name.starts_with("GIT_")
            && !matches!(
                name.as_str(),
                "GIT_DIR"
                    | "GIT_WORK_TREE"
                    | "GIT_INDEX_FILE"
                    | "GIT_OPTIONAL_LOCKS"
                    | "GIT_CONFIG_NOSYSTEM"
                    | "GIT_CONFIG_GLOBAL"
                    | "GIT_CONFIG_SYSTEM"
            )
    }) {
        return Err(unsupported());
    }
    let repository = repository.canonicalize()?;
    let source = NativeSourceRoot::open(&repository)?;
    let git_path = match source.open_directory(".git") {
        Ok(Some(_)) => repository.join(".git"),
        Err(error) if error.kind() == io::ErrorKind::NotADirectory => {
            let pointer = small(&source, ".git", 4096)?.ok_or_else(unsupported)?;
            let pointer = std::str::from_utf8(&pointer).map_err(|_| unsupported())?;
            let spelling = pointer
                .trim()
                .strip_prefix("gitdir: ")
                .ok_or_else(unsupported)?;
            repository.join(spelling).canonicalize()?
        }
        _ => return Err(unsupported()),
    };
    let git = NativeSourceRoot::open(&git_path)?;
    let common_path = match small(&git, "commondir", 4096)? {
        Some(pointer) => {
            let pointer = std::str::from_utf8(&pointer).map_err(|_| unsupported())?;
            git_path.join(pointer.trim()).canonicalize()?
        }
        None => git_path.clone(),
    };
    let common = NativeSourceRoot::open(&common_path)?;
    for metadata in [&git, &common] {
        if metadata.open_relative("shallow")?.is_some()
            || metadata.open_relative("info/grafts")?.is_some()
            || metadata.open_directory("refs/replace")?.is_some()
            || metadata.open_directory("reftable")?.is_some()
        {
            return Err(unsupported());
        }
        if let Some(packed) = small(metadata, "packed-refs", MAX_METADATA)?
            && packed.split(|&byte| byte == b'\n').any(|line| {
                line.split(|&byte| byte == b' ')
                    .nth(1)
                    .is_some_and(|name| name.starts_with(b"refs/replace/"))
            })
        {
            return Err(unsupported());
        }
    }
    let objects = NativeSourceRoot::open(&common_path.join("objects"))?;
    if objects.open_relative("info/alternates")?.is_some()
        || objects.open_relative("info/http-alternates")?.is_some()
    {
        return Err(unsupported());
    }
    let mut hash = Sha256::new();
    hash.update(b"Git count cache v1\0");
    hash.update(git.physical_identity()?);
    hash.update(common.physical_identity()?);
    hash.update(objects.physical_identity()?);
    Ok(hash.finalize().into())
}

fn small(root: &NativeSourceRoot, path: &str, maximum: u64) -> io::Result<Option<Vec<u8>>> {
    let Some(mut file) = root.open_relative(path)? else {
        return Ok(None);
    };
    let before = file.revision()?;
    let mut bytes = Vec::new();
    file.by_ref().take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum || file.revision()? != before || !file.validate_name()? {
        return Err(unsupported());
    }
    Ok(Some(bytes))
}

fn unsupported() -> io::Error {
    io::Error::other("Git history is not eligible for exact count caching")
}
