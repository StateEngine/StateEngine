//! The replaceable native-library backend. It returns owned facts, never a
//! library handle or status entry across the repository-observation interface.
use super::Facts;
use git2::{ErrorCode, Repository, RepositoryOpenFlags, Status, StatusOptions};
#[cfg(windows)]
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub(super) struct Prepared {
    repository: Repository,
    key: PathBuf,
    facts: Facts,
    untracked: bool,
    #[cfg(windows)]
    config_token: [u8; 32],
}
impl Prepared {
    pub(super) fn open(root: &Path) -> Result<Self, String> {
        // Opening without FROM_ENV also omits command-scoped configuration and
        // alternate global/system files. Preserve that entire configuration
        // family through Git rather than silently observing different values.
        if std::env::vars_os().any(|(name, _)| {
            name.as_encoded_bytes()
                .get(..b"GIT_CONFIG".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"GIT_CONFIG"))
        }) {
            return Err("environment configuration requires the command-line observer".into());
        }
        // Deliberately omit FROM_ENV: GIT_DIR, GIT_WORK_TREE and GIT_INDEX_FILE
        // cannot redirect an observation of the caller's selected repository.
        let repository = Repository::open_ext(
            root,
            RepositoryOpenFlags::empty(),
            &[] as &[&std::ffi::OsStr],
        )
        .map_err(describe)?;
        let config = repository.config().map_err(describe)?;
        // The library follows plain includes and these conditional includes.
        // Inspect inactive directives too: unknown conditions must select Git
        // rather than silently omitting configuration it could have applied.
        let mut entries = config.entries(None).map_err(describe)?;
        let mut gitdir_condition = false;
        #[cfg(windows)]
        let mut config_hash = Sha256::new();
        while let Some(entry) = entries.next() {
            let entry = entry.map_err(describe)?;
            let name = entry.name_bytes();
            #[cfg(windows)]
            if status_config_key(name) {
                let value = entry.value_bytes();
                config_hash.update((name.len() as u64).to_le_bytes());
                config_hash.update(name);
                config_hash.update((value.len() as u64).to_le_bytes());
                config_hash.update(value);
            }
            if let Some(condition) = name
                .strip_prefix(b"includeif.")
                .and_then(|name| name.strip_suffix(b".path"))
            {
                let mut parts = condition.splitn(2, |byte| *byte == b':');
                match (parts.next(), parts.next()) {
                    (Some(b"gitdir" | b"gitdir/i"), Some(pattern)) if !pattern.is_empty() => {
                        gitdir_condition = true;
                    }
                    (Some(b"onbranch"), Some(pattern)) if !pattern.is_empty() => {}
                    _ => {
                        return Err(
                            "unsupported include condition requires the command-line observer"
                                .into(),
                        );
                    }
                }
            }
        }
        drop(entries);
        if gitdir_condition {
            // Git matches both selected and resolved directory names. The
            // library does not preserve both identities for aliased paths.
            // Use the shared Windows-aware canonicalizer so an ordinary drive
            // path is not mistaken for an alias of its verbatim spelling.
            let canonical = se_proc::canonicalize_path(root)
                .map_err(|error| format!("cannot resolve conditional Git directory: {error}"))?;
            if root != canonical {
                return Err(
                    "aliased Git directory condition requires the command-line observer".into(),
                );
            }
        }
        for name in [
            "core.sparseCheckout",
            "index.sparse",
            "extensions.worktreeConfig",
        ] {
            match config.get_bool(name) {
                Ok(true) => return Err(format!("{name} requires the command-line observer")),
                Ok(false) => {}
                Err(error) if error.code() == ErrorCode::NotFound => {}
                Err(error) => return Err(describe(error)),
            }
        }
        let untracked = match config.get_string("status.showUntrackedFiles") {
            Ok(value) => match value.as_str() {
                "no" => false,
                "normal" | "all" => true,
                _ => return Err("unsupported status.showUntrackedFiles value".into()),
            },
            Err(error) if error.code() == ErrorCode::NotFound => true,
            Err(error) => return Err(describe(error)),
        };
        let key = repository
            .workdir()
            .ok_or("repository has no working tree")?
            .canonicalize()
            .map_err(|error| format!("cannot identify working tree: {error}"))?;
        let facts = header(&repository)?;
        drop(config);
        Ok(Self {
            repository,
            key,
            facts,
            untracked,
            #[cfg(windows)]
            config_token: config_hash.finalize().into(),
        })
    }
    pub(super) fn facts(&self) -> &Facts {
        &self.facts
    }
    pub(super) fn key(&self) -> &Path {
        &self.key
    }
    #[cfg(windows)]
    pub(super) fn metadata_directory(&self) -> &Path {
        self.repository.path()
    }
    #[cfg(windows)]
    pub(super) fn common_directory(&self) -> &Path {
        self.repository.commondir()
    }
    #[cfg(windows)]
    pub(super) fn ticket(&self) -> Result<String, String> {
        let mut hash = Sha256::new();
        for bytes in [
            self.key.as_os_str().as_encoded_bytes(),
            self.repository.path().as_os_str().as_encoded_bytes(),
            self.repository.commondir().as_os_str().as_encoded_bytes(),
            &self.config_token,
        ] {
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        for value in [self.facts.head.as_deref(), self.facts.branch.as_deref()] {
            let bytes = value.unwrap_or("").as_bytes();
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        hash.update([u8::from(self.untracked)]);
        Ok(hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }
    #[cfg(windows)]
    pub(super) fn watchable(&self) -> Result<(), String> {
        if std::env::vars_os().any(|(name, _)| {
            name.as_encoded_bytes()
                .get(..4)
                .is_some_and(|v| v.eq_ignore_ascii_case(b"GIT_"))
                || name
                    .as_encoded_bytes()
                    .eq_ignore_ascii_case(b"XDG_CONFIG_HOME")
        }) {
            return Err("Git environment overrides require a fresh observation".into());
        }
        let claim = se_proc::installation_claim_path().map_err(|e| e.to_string())?;
        let profile = claim
            .parent()
            .ok_or("native user profile has no directory")?;
        let expected = se_proc::canonicalize_path(profile).map_err(|e| e.to_string())?;
        for key in ["HOME", "USERPROFILE"] {
            if let Some(value) = std::env::var_os(key) {
                let actual =
                    se_proc::canonicalize_path(Path::new(&value)).map_err(|e| e.to_string())?;
                if actual != expected {
                    return Err("Git user profile differs from the native account".into());
                }
            }
        }
        let config = self.repository.config().map_err(describe)?;
        match config.get_bool("core.ignorecase") {
            Ok(true) => (),
            Ok(false) => {
                return Err("case-sensitive Git status requires a fresh observation".into());
            }
            Err(error) if error.code() == ErrorCode::NotFound => {
                return Err("unknown Git path case policy requires a fresh observation".into());
            }
            Err(error) => return Err(describe(error)),
        }
        for name in ["core.excludesfile", "core.attributesfile"] {
            match config.get_string(name) {
                Ok(_) => return Err("external Git rules require a fresh observation".into()),
                Err(error) if error.code() == ErrorCode::NotFound => (),
                Err(error) => return Err(describe(error)),
            }
        }
        for name in [".config/git/ignore", ".config/git/attributes"] {
            match std::fs::symlink_metadata(profile.join(name)) {
                Ok(_) => return Err("global Git rules require a fresh observation".into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }
    #[cfg(windows)]
    pub(super) fn inventory(&self) -> Result<std::collections::HashSet<String>, String> {
        let index = self.repository.index().map_err(describe)?;
        if index.iter().any(|entry| entry.mode & 0o170000 == 0o160000) {
            return Err("submodules require a fresh observation".into());
        }
        let mut names = std::collections::HashMap::new();
        let mut directories = std::collections::HashSet::new();
        let mut bytes = 0usize;
        for entry in index.iter() {
            let path = std::str::from_utf8(&entry.path)
                .map_err(|_| "non-UTF-8 Git paths require a fresh observation")?;
            if !path.is_ascii() {
                return Err("non-ASCII Git paths require a fresh observation".into());
            }
            if path.len() > 4096 {
                return Err("Git path exceeds the watched path bound".into());
            }
            let folded = path.to_ascii_lowercase();
            for (position, _) in folded.match_indices('/') {
                let prefix = &folded[..position];
                if !directories.contains(prefix) {
                    bytes = bytes.saturating_add(prefix.len());
                    if bytes > 4_000_000 {
                        return Err("Git path inventory exceeds its memory bound".into());
                    }
                    directories.insert(prefix.to_owned());
                }
            }
            bytes = bytes.saturating_add(folded.len().saturating_mul(2));
            if bytes > 4_000_000 {
                return Err("Git path inventory exceeds its memory bound".into());
            }
            if names
                .insert(folded, path.to_owned())
                .is_some_and(|old| old != path)
            {
                return Err("case-colliding Git paths require a fresh observation".into());
            }
            if names.len() > 32768 {
                return Err("Git index exceeds the watched inventory bound".into());
            }
        }
        let tracked = names.into_keys().collect();
        crate::watch_inventory::check(
            &self.repository,
            &self.key,
            &tracked,
            &directories,
            self.untracked,
        )?;
        let mut options = StatusOptions::new();
        options
            .include_untracked(self.untracked)
            .recurse_untracked_dirs(false)
            .include_ignored(false)
            .include_unmodified(false)
            .exclude_submodules(false)
            .renames_head_to_index(false)
            .renames_index_to_workdir(false)
            .include_unreadable(true)
            .include_unreadable_as_untracked(false)
            .no_refresh(false)
            .update_index(false);
        let statuses = self
            .repository
            .statuses(Some(&mut options))
            .map_err(describe)?;
        let mut changed = std::collections::HashSet::new();
        let mut changed_bytes = 0usize;
        for entry in statuses.iter() {
            let status = entry.status();
            if status.contains(Status::WT_UNREADABLE) {
                return Err("working-tree status contains an unreadable path".into());
            }
            if status != Status::CURRENT && status != Status::IGNORED {
                let path = entry.path().map_err(describe)?;
                if changed.len() >= 32768 {
                    return Err("working-tree change set exceeds its bound".into());
                }
                if !path.is_ascii() {
                    return Err("non-ASCII changes require a fresh observation".into());
                }
                changed_bytes = changed_bytes.saturating_add(path.len());
                if path.len() > 4096 || changed_bytes > 4_000_000 {
                    return Err("working-tree change set exceeds its memory bound".into());
                }
                changed.insert(path.to_ascii_lowercase());
            }
        }
        if header(&self.repository)? != self.facts {
            return Err("repository HEAD or branch changed during the working-tree scan".into());
        }
        Ok(changed)
    }
    #[cfg(windows)]
    pub(super) fn changed_file(&self, path: &Path) -> Result<bool, String> {
        let status = match self.repository.status_file(path) {
            Ok(status) => status,
            Err(error) if error.code() == ErrorCode::NotFound => return Ok(false),
            Err(error) => return Err(describe(error)),
        };
        if status.contains(Status::WT_UNREADABLE) {
            return Err("working-tree status contains an unreadable path".into());
        }
        let mut relevant = status & !Status::IGNORED;
        if !self.untracked {
            relevant.remove(Status::WT_NEW);
        }
        Ok(relevant != Status::CURRENT)
    }
    pub(super) fn scan(self) -> Result<bool, String> {
        let mut options = StatusOptions::new();
        options
            .include_untracked(self.untracked)
            // One untracked directory already proves dirtiness. Its contents
            // need not be retained to answer this boolean observation.
            .recurse_untracked_dirs(false)
            .include_ignored(false)
            .include_unmodified(false)
            .exclude_submodules(false)
            .renames_head_to_index(false)
            .renames_index_to_workdir(false)
            .include_unreadable(true)
            .include_unreadable_as_untracked(false)
            .no_refresh(false)
            .update_index(false);
        // This call can block. The interface waits only until its deadline and
        // retains single-flight ownership until the scan actually returns.
        let statuses = self
            .repository
            .statuses(Some(&mut options))
            .map_err(describe)?;
        let mut dirty = false;
        for entry in statuses.iter() {
            let status = entry.status();
            if status.contains(Status::WT_UNREADABLE) {
                return Err("working-tree status contains an unreadable path".into());
            }
            if status != Status::CURRENT && status != Status::IGNORED {
                dirty = true;
                break;
            }
        }
        if header(&self.repository)? != self.facts {
            return Err("repository HEAD or branch changed during the working-tree scan".into());
        }
        Ok(dirty)
    }
}

#[cfg(windows)]
fn status_config_key(name: &[u8]) -> bool {
    [
        b"core.filemode".as_slice(),
        b"core.symlinks",
        b"core.ignorecase",
        b"core.trustctime",
        b"core.checkstat",
        b"core.precomposeunicode",
        b"core.sparsecheckout",
        b"core.autocrlf",
        b"core.eol",
        b"core.safecrlf",
        b"core.excludesfile",
        b"core.attributesfile",
        b"core.untrackedcache",
        b"index.sparse",
        b"extensions.worktreeconfig",
        b"extensions.objectformat",
        b"status.showuntrackedfiles",
        b"status.submodulesummary",
        b"diff.ignoresubmodules",
    ]
    .iter()
    .any(|key| name.eq_ignore_ascii_case(key))
}

fn header(repository: &Repository) -> Result<Facts, String> {
    let (head, branch) = match repository.head() {
        Ok(reference) => {
            let head = reference
                .target()
                .ok_or("HEAD did not resolve to an object")?;
            let branch = reference
                .is_branch()
                .then(|| branch_name(reference.name_bytes()))
                .transpose()?;
            (Some(head.to_string()), branch)
        }
        Err(error) if error.code() == ErrorCode::UnbornBranch => {
            let reference = repository.find_reference("HEAD").map_err(describe)?;
            let name = reference
                .symbolic_target_bytes()
                .ok_or("unborn HEAD has no UTF-8 branch")?;
            (None, Some(branch_name(name)?))
        }
        Err(error) => return Err(describe(error)),
    };
    Ok(Facts {
        head,
        branch,
        dirty: None,
    })
}

fn branch_name(bytes: &[u8]) -> Result<String, String> {
    std::str::from_utf8(bytes)
        .map_err(|error| error.to_string())?
        .strip_prefix("refs/heads/")
        .map(str::to_owned)
        .ok_or_else(|| "invalid branch reference".into())
}

fn describe(error: git2::Error) -> String {
    error.message().to_owned()
}
