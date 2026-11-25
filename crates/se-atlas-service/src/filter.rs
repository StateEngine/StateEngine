//! The watcher's fast path: decide what a reported path means before it
//! reaches the debounce queue or the dirty set. Build output, dependency
//! trees, private files and our own state never enter either; Git's head
//! files and its index lock only signal a checkout, which the writer reads
//! once Git lets go of the lock.
use se_atlas_index::policy;

/// Directory names skipped at any depth, as discovery skips them.
pub const SKIPPED_DIRECTORIES: [&str; 7] = [
    "target",
    "node_modules",
    ".venv",
    ".next",
    "dist",
    "build",
    "vendor",
];

/// The ignore patterns that make discovery agree with [`classify`].
pub fn global_patterns() -> Vec<String> {
    SKIPPED_DIRECTORIES
        .iter()
        .map(|name| format!("{name}/"))
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reported {
    /// Ignored, private, or not ours to index.
    Drop,
    /// Git moved `HEAD` or a branch, or took or released its index lock:
    /// record the commit the tree is at once the lock is gone.
    Head,
    /// A source path the writer should read again.
    Source,
}

/// Classify one root-relative path, `/`-separated.
pub fn classify(path: &str) -> Reported {
    let path = path.trim_start_matches("./").trim_matches('/');
    if path.is_empty() {
        return Reported::Drop;
    }
    if let Some(rest) = path.strip_prefix(".git/") {
        let head = matches!(rest, "HEAD" | "packed-refs" | "index.lock");
        return if head || rest.starts_with("refs/heads/") {
            Reported::Head
        } else {
            Reported::Drop
        };
    }
    let mut parts = path.split('/').peekable();
    while let Some(part) = parts.next() {
        let directory = parts.peek().is_some();
        if part == ".git" || part == ".stateengine" {
            return Reported::Drop;
        }
        if directory && SKIPPED_DIRECTORIES.contains(&part) {
            return Reported::Drop;
        }
    }
    // The policy also refuses any file below a private directory.
    if policy::file_denied(path) {
        return Reported::Drop;
    }
    Reported::Source
}

/// Classify one root-relative directory. Only the built-in directory
/// boundary applies: a folder such as `src/secrets/` holds source, so its
/// coming and going is never dropped because a data file there would be.
pub fn classify_directory(path: &str) -> Reported {
    let path = path.trim_start_matches("./").trim_matches('/');
    if path.is_empty() || path == ".git" {
        return Reported::Drop;
    }
    if let Some(rest) = path.strip_prefix(".git/") {
        return if rest == "refs/heads" || rest.starts_with("refs/heads/") {
            Reported::Head
        } else {
            Reported::Drop
        };
    }
    let skipped = path.split('/').any(|part| {
        part == ".git" || part == ".stateengine" || SKIPPED_DIRECTORIES.contains(&part)
    });
    if skipped || policy::directory_denied(path) {
        return Reported::Drop;
    }
    Reported::Source
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignored_private_and_state_paths_never_reach_the_queue() {
        for path in [
            ".git/objects/ab/cdef",
            "target/debug/se",
            "crates/x/target/release/build.rs",
            "web/node_modules/left-pad/index.js",
            ".stateengine/atlas/atlas.db",
            "deploy/.env",
            "keys/id_ed25519",
            "",
        ] {
            assert_eq!(classify(path), Reported::Drop, "{path}");
        }
    }

    #[test]
    fn sources_and_git_heads_are_kept_apart() {
        assert_eq!(classify("src/live_added.rs"), Reported::Source);
        assert_eq!(classify("target.rs"), Reported::Source);
        assert_eq!(classify("docs/target"), Reported::Source);
        assert_eq!(classify(".git/HEAD"), Reported::Head);
        assert_eq!(classify(".git/refs/heads/main"), Reported::Head);
        assert_eq!(classify(".git/index.lock"), Reported::Head);
    }
}
