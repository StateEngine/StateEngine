//! The watcher's fast path: decide what a reported path means before it
//! reaches the debounce queue or the dirty set. Build output, dependency
//! trees, private files and our own state never enter either; Git's head
//! files only signal a checkout.
use se_atlas_index::policy;

/// Directory names skipped at any depth, as discovery skips them.
pub const SKIPPED_DIRECTORIES: [&str; 2] = ["target", "node_modules"];

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
    /// Git moved `HEAD` or a branch: record the commit the tree is now at.
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
        return if rest == "HEAD" || rest == "packed-refs" || rest.starts_with("refs/heads/") {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignored_private_and_state_paths_never_reach_the_queue() {
        for path in [
            ".git/objects/ab/cdef",
            ".git/index.lock",
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
    }
}
