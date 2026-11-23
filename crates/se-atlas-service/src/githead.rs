//! The commit a worktree is checked out at, read from Git's own files
//! through retained no-follow handles, so `changes --since <commit>` can
//! answer from the generation that observed it. Missing or unusual Git
//! metadata is no commit, never an error: history is optional enrichment.
use se_proc::NativeSourceRoot;
use std::{
    io::Read,
    path::{Component, Path, PathBuf},
};

/// Bytes read from any one Git metadata file.
const MAX_FILE: u64 = 64 * 1024;
const MAX_PACKED_REFS: u64 = 4 << 20;

/// A worktree's Git directory, held through custody.
struct GitDir {
    root: NativeSourceRoot,
    /// Its spelling, to resolve a relative `commondir` against.
    path: PathBuf,
}

/// The worktree's own `.git` directory, or the one a linked worktree's
/// `.git` file names.
fn git_dir(source: &Path) -> Option<GitDir> {
    let tree = NativeSourceRoot::open(source).ok()?;
    if read(&tree, ".git/HEAD", MAX_FILE).is_some() {
        return Some(GitDir {
            root: tree.subroot(".git").ok()?,
            path: source.join(".git"),
        });
    }
    let text = read(&tree, ".git", MAX_FILE)?;
    let path = resolve(source, text.trim().strip_prefix("gitdir:")?.trim())?;
    Some(GitDir {
        root: NativeSourceRoot::open(&path).ok()?,
        path,
    })
}

/// Whether Git holds its index lock: a checkout or commit is under way, so
/// the head may be about to move again.
pub(crate) fn busy(source: &Path) -> bool {
    git_dir(source).is_some_and(|git| matches!(git.root.open_relative("index.lock"), Ok(Some(_))))
}

/// The raw object id `HEAD` names, 20 or 32 bytes.
pub(crate) fn head(source: &Path) -> Option<Vec<u8>> {
    let git = git_dir(source)?;
    let head = read(&git.root, "HEAD", MAX_FILE)?;
    let head = head.trim();
    let Some(reference) = head.strip_prefix("ref:").map(str::trim) else {
        return oid(head);
    };
    if !reference.starts_with("refs/") || reference.split('/').any(|part| part == "..") {
        return None;
    }
    let common = read(&git.root, "commondir", MAX_FILE)
        .and_then(|text| resolve(&git.path, text.trim()))
        .and_then(|dir| NativeSourceRoot::open(&dir).ok());
    let stores = std::iter::once(&git.root).chain(common.as_ref());
    for store in stores {
        if let Some(text) = read(store, reference, MAX_FILE) {
            return oid(text.trim());
        }
        if let Some(packed) = read(store, "packed-refs", MAX_PACKED_REFS) {
            let found = packed.lines().find_map(|line| {
                let (id, name) = line.split_once(' ')?;
                (name.trim() == reference).then(|| oid(id)).flatten()
            });
            if found.is_some() {
                return found;
            }
        }
    }
    None
}

/// A Git-written path, absolute or relative to `base`, with `.` and `..`
/// resolved by name: custody opens only absolute, normalized roots.
fn resolve(base: &Path, spelling: &str) -> Option<PathBuf> {
    let path = Path::new(spelling);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut out = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            other => out.push(other),
        }
    }
    out.is_absolute().then_some(out)
}

fn read(root: &NativeSourceRoot, path: &str, limit: u64) -> Option<String> {
    let mut file = root.open_relative(path).ok()??;
    let mut text = String::new();
    (&mut file).take(limit + 1).read_to_string(&mut text).ok()?;
    (text.len() as u64 <= limit && file.validate_name().ok()?).then_some(text)
}

/// 40 or 64 hex digits as raw bytes.
fn oid(text: &str) -> Option<Vec<u8>> {
    if !matches!(text.len(), 40 | 64) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::oid;

    #[test]
    fn object_ids_are_whole_hex_digests_only() {
        assert_eq!(
            oid("0123456789abcdef0123456789abcdef01234567").map(|id| id.len()),
            Some(20)
        );
        assert!(oid("0123456").is_none());
        assert!(oid("zz23456789abcdef0123456789abcdef01234567").is_none());
    }
}
