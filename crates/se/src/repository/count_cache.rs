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
/// Variables that change how Git evaluates a count are refused, because the
/// cached answer would not describe this evaluation.
///
/// Purely cosmetic and paging variables are not in that set: `GIT_PAGER`,
/// `GIT_EDITOR`, `GIT_TERMINAL_PROMPT` and the like never reach `rev-list`
/// output, and refusing on them made an ordinary terminal environment — which
/// sets `GIT_PAGER` by default — re-walk the whole history on every status.
fn affects_count(name: &str) -> bool {
    if !name.starts_with("GIT_") {
        return false;
    }
    // `GIT_DIR`, `GIT_WORK_TREE` and `GIT_INDEX_FILE` are not here: they select
    // which repository and index Git reads, so a count cached for this checkout
    // does not describe that evaluation.
    !matches!(
        name,
        "GIT_OPTIONAL_LOCKS"
            | "GIT_CONFIG_NOSYSTEM"
            | "GIT_CONFIG_GLOBAL"
            | "GIT_CONFIG_SYSTEM"
            | "GIT_PAGER"
            | "GIT_EDITOR"
            | "GIT_SEQUENCE_EDITOR"
            | "GIT_TERMINAL_PROMPT"
            | "GIT_ASKPASS"
            | "GIT_SSH"
            | "GIT_SSH_COMMAND"
            | "GIT_SSL_CAINFO"
            | "GIT_SSL_NO_VERIFY"
            | "GIT_HTTP_LOW_SPEED_LIMIT"
            | "GIT_HTTP_LOW_SPEED_TIME"
            | "GIT_TRACE"
            | "GIT_TRACE_PERFORMANCE"
            | "GIT_TRACE_SETUP"
            | "GIT_TRACE_PACKET"
            | "GIT_TRACE_CURL"
            | "GIT_TRACE2"
            | "GIT_TRACE2_EVENT"
            | "GIT_TRACE2_PERF"
            | "GIT_ADVICE"
            | "GIT_FLUSH"
            | "GIT_MERGE_AUTOEDIT"
            | "GIT_PAGER_IN_USE"
            | "GIT_LITERAL_PATHSPECS"
            | "GIT_GLOB_PATHSPECS"
            | "GIT_NOGLOB_PATHSPECS"
            | "GIT_ICASE_PATHSPECS"
    )
}

/// True when the environment could change what a commit count means, so the
/// cache must not be used.
fn count_interpretation_is_fixed(
    mut environment: impl Iterator<Item = (impl AsRef<std::ffi::OsStr>, impl Sized)>,
) -> bool {
    !environment
        .any(|(name, _)| affects_count(&name.as_ref().to_string_lossy().to_ascii_uppercase()))
}

fn identity(repository: &Path) -> io::Result<[u8; 32]> {
    if !count_interpretation_is_fixed(std::env::vars_os()) {
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

#[cfg(test)]
mod tests {
    use super::{affects_count, count_interpretation_is_fixed};

    fn environment(names: &[&str]) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        names
            .iter()
            .map(|name| (std::ffi::OsString::from(*name), std::ffi::OsString::new()))
            .collect()
    }

    /// An ordinary terminal sets a pager, and that was enough to make every
    /// status re-walk the whole history. A cosmetic variable must not do that.
    #[test]
    fn cosmetic_git_variables_keep_the_exact_count_cache() {
        for name in [
            "GIT_PAGER",
            "GIT_EDITOR",
            "GIT_TERMINAL_PROMPT",
            "GIT_TRACE",
            "GIT_ASKPASS",
        ] {
            assert!(!affects_count(name), "{name} cannot change a commit count");
            assert!(
                count_interpretation_is_fixed(environment(&[name]).into_iter()),
                "{name} must not disable the exact count cache"
            );
        }
    }

    /// The variables that do change what a count means must still disable it,
    /// because a cached answer would then describe a different evaluation.
    #[test]
    fn history_interpreting_git_variables_disable_the_cache() {
        for name in [
            "GIT_DIR",
            "GIT_REPLACE_REF_BASE",
            "GIT_GRAFT_FILE",
            "GIT_NO_REPLACE_OBJECTS",
        ] {
            assert!(affects_count(name), "{name} can change a commit count");
            assert!(
                !count_interpretation_is_fixed(environment(&[name]).into_iter()),
                "{name} must disable the exact count cache"
            );
        }
    }

    /// A non-Git variable is never the observer's business.
    #[test]
    fn unrelated_variables_are_ignored() {
        assert!(!affects_count("HOME"));
        assert!(count_interpretation_is_fixed(
            environment(&["HOME", "PATH"]).into_iter()
        ));
    }
}
