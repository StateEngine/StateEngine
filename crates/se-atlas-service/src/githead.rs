//! The commit a worktree is checked out at, read from Git's own files
//! through retained no-follow handles, so `changes --since <commit>` can
//! answer from the generation that observed it. Missing or unusual Git
//! metadata is no commit, never an error: history is optional enrichment.
use se_proc::NativeSourceRoot;
use std::{
    io::Read,
    path::{Path, PathBuf},
};

/// Bytes read from any one Git metadata file.
const MAX_FILE: u64 = 64 * 1024;
const MAX_PACKED_REFS: u64 = 4 << 20;

/// The raw object id `HEAD` names, 20 or 32 bytes.
pub(crate) fn head(source: &Path) -> Option<Vec<u8>> {
    let tree = NativeSourceRoot::open(source).ok()?;
    let git_dir = match read(&tree, ".git/HEAD", MAX_FILE) {
        Some(_) => source.join(".git"),
        None => linked_git_dir(&tree, source)?,
    };
    let git = NativeSourceRoot::open(&git_dir).ok()?;
    let head = read(&git, "HEAD", MAX_FILE)?;
    let head = head.trim();
    let Some(reference) = head.strip_prefix("ref:").map(str::trim) else {
        return oid(head);
    };
    if !reference.starts_with("refs/") || reference.split('/').any(|part| part == "..") {
        return None;
    }
    let common = common_dir(&git, &git_dir);
    let common = common
        .as_deref()
        .and_then(|dir| NativeSourceRoot::open(dir).ok());
    let stores = std::iter::once(&git).chain(common.as_ref());
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

/// A linked worktree's `.git` is a file naming its Git directory.
fn linked_git_dir(tree: &NativeSourceRoot, source: &Path) -> Option<PathBuf> {
    let text = read(tree, ".git", MAX_FILE)?;
    let spelling = text.trim().strip_prefix("gitdir:")?.trim();
    let path = Path::new(spelling);
    Some(if path.is_absolute() {
        path.to_path_buf()
    } else {
        source.join(path)
    })
}

/// Where a linked worktree's shared refs live.
fn common_dir(git: &NativeSourceRoot, git_dir: &Path) -> Option<PathBuf> {
    let text = read(git, "commondir", MAX_FILE)?;
    let path = Path::new(text.trim());
    Some(if path.is_absolute() {
        path.to_path_buf()
    } else {
        git_dir.join(path)
    })
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
