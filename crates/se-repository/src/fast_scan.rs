//! Fast-path fresh working-tree dirty check backed by `.git/index` and `read_dir`.
//!
//! Returns `Ok(Some(dirty))` only when the result is proven without omitting
//! staged, unstaged, deleted, untracked, or unreadable facts. Any unsupported
//! index feature, case mismatch, or error returns `Ok(None)` so the caller
//! falls back to the full `libgit2` status walk.
use crate::index_format::{IndexEntry, ParsedIndex, Timestamp, parse_index};
use git2::{DiffOptions, Oid, Repository, Status};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, DirEntry, File, Metadata},
    io::{self, Read},
    path::Path,
};

const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STAT_CHECKS: usize = 16;
const MAX_UNTRACKED_DIRS: usize = 64;

#[cfg(windows)]
const WINDOWS_EPOCH_OFFSET_100NS: u64 = 116_444_736_000_000_000;
#[cfg(windows)]
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum CasePolicy {
    Sensitive,
    Insensitive,
}

pub(super) struct ScanConfig {
    pub(super) untracked: bool,
    #[cfg(unix)]
    pub(super) filemode: bool,
    pub(super) trustctime: bool,
    pub(super) case_policy: CasePolicy,
}

impl ScanConfig {
    fn ignorecase(&self) -> bool {
        self.case_policy == CasePolicy::Insensitive
    }
}

struct DirIndex<'a> {
    files: HashMap<&'a str, Vec<(&'a str, usize)>>,
    tracked_dirs: HashSet<&'a str>,
}

pub(super) fn try_scan(
    repository: &Repository,
    head_oid: &str,
    config: &ScanConfig,
) -> Result<Option<bool>, String> {
    if head_oid.len() != 40 {
        return Ok(None);
    }
    let Some(workdir) = repository.workdir() else {
        return Ok(None);
    };
    let Some((index_bytes, index_mtime)) = read_index_bytes(repository.path()) else {
        return Ok(None);
    };
    let Some(parsed) = parse_index(&index_bytes) else {
        return Ok(None);
    };
    match check_head_vs_index(repository, head_oid, &parsed) {
        HeadCheck::Matches => {}
        HeadCheck::Dirty => return Ok(Some(true)),
        HeadCheck::Fallback => return Ok(None),
    }
    let dir_index = build_dir_index(&parsed, &index_bytes);
    walk_workdir(
        repository,
        workdir,
        &parsed,
        &index_bytes,
        index_mtime,
        &dir_index,
        config,
    )
}

fn read_index_bytes(git_dir: &Path) -> Option<(Vec<u8>, Timestamp)> {
    let mut file = File::open(git_dir.join("index")).ok()?;
    let index_meta = file.metadata().ok()?;
    if index_meta.len() > MAX_INDEX_BYTES {
        return None;
    }
    let index_mtime = metadata_mtime(&index_meta)?;
    let mut bytes = Vec::with_capacity(usize::try_from(index_meta.len()).unwrap_or(0));
    file.by_ref()
        .take(MAX_INDEX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_INDEX_BYTES {
        return None;
    }
    Some((bytes, index_mtime))
}

enum HeadCheck {
    Matches,
    Dirty,
    Fallback,
}

fn check_head_vs_index(repository: &Repository, head_oid: &str, parsed: &ParsedIndex) -> HeadCheck {
    let Ok(head) = Oid::from_str(head_oid) else {
        return HeadCheck::Fallback;
    };
    let Ok(commit) = repository.find_commit(head) else {
        return HeadCheck::Fallback;
    };
    let head_tree_id = commit.tree_id();
    if parsed
        .root_tree_oid
        .is_some_and(|oid| oid.as_slice() == head_tree_id.as_bytes())
    {
        return HeadCheck::Matches;
    }
    let Ok(tree) = commit.tree() else {
        return HeadCheck::Fallback;
    };
    let mut opts = DiffOptions::new();
    opts.include_unmodified(false);
    let Ok(diff) = repository.diff_tree_to_index(Some(&tree), None, Some(&mut opts)) else {
        return HeadCheck::Fallback;
    };
    if diff.deltas().len() > 0 {
        HeadCheck::Dirty
    } else {
        HeadCheck::Matches
    }
}

fn build_dir_index<'a>(parsed: &'a ParsedIndex, index_bytes: &'a [u8]) -> DirIndex<'a> {
    let mut files: HashMap<&'a str, Vec<(&'a str, usize)>> = HashMap::new();
    let mut tracked_dirs: HashSet<&'a str> = HashSet::new();
    for (idx, entry) in parsed.entries.iter().enumerate() {
        let path = parsed.path(index_bytes, entry);
        let (dir, name) = match path.rfind('/') {
            Some(slash) => (&path[..slash], &path[slash + 1..]),
            None => ("", path),
        };
        files.entry(dir).or_default().push((name, idx));
        if !dir.is_empty() {
            let mut cur = dir;
            while tracked_dirs.insert(cur) {
                match cur.rfind('/') {
                    Some(slash) => cur = &cur[..slash],
                    None => break,
                }
            }
        }
    }
    for list in files.values_mut() {
        if !list.windows(2).all(|w| w[0].0 < w[1].0) {
            list.sort_unstable_by(|a, b| a.0.cmp(b.0));
        }
    }
    DirIndex {
        files,
        tracked_dirs,
    }
}

struct WalkContext<'a> {
    repository: &'a Repository,
    workdir: &'a Path,
    parsed: &'a ParsedIndex,
    index_bytes: &'a [u8],
    index_mtime: Timestamp,
    dir_index: &'a DirIndex<'a>,
    config: &'a ScanConfig,
    visited_files: usize,
    stat_checks: usize,
}

enum Step {
    Continue,
    Dirty,
    Fallback,
}

fn walk_workdir(
    repository: &Repository,
    workdir: &Path,
    parsed: &ParsedIndex,
    index_bytes: &[u8],
    index_mtime: Timestamp,
    dir_index: &DirIndex<'_>,
    config: &ScanConfig,
) -> Result<Option<bool>, String> {
    let mut cx = WalkContext {
        repository,
        workdir,
        parsed,
        index_bytes,
        index_mtime,
        dir_index,
        config,
        visited_files: 0,
        stat_checks: 0,
    };
    let mut stack = vec![String::new()];
    while let Some(rel_dir) = stack.pop() {
        match scan_directory(&mut cx, &rel_dir, &mut stack)? {
            Step::Continue => {}
            Step::Dirty => return Ok(Some(true)),
            Step::Fallback => return Ok(None),
        }
    }
    if cx.visited_files != parsed.entries.len() {
        if !config.ignorecase() {
            return Ok(Some(true));
        }
        return Ok(any_tracked_dir_missing(workdir, &dir_index.tracked_dirs));
    }
    Ok(Some(false))
}

fn any_tracked_dir_missing(workdir: &Path, tracked_dirs: &HashSet<&str>) -> Option<bool> {
    for dir in tracked_dirs {
        if let Err(error) = fs::symlink_metadata(workdir.join(dir))
            && error.kind() == io::ErrorKind::NotFound
        {
            return Some(true);
        }
    }
    None
}

fn any_expected_file_missing(cx: &WalkContext<'_>, expected: &[(&str, usize)]) -> Step {
    for &(_, idx) in expected {
        let path = cx.parsed.path(cx.index_bytes, &cx.parsed.entries[idx]);
        if let Err(error) = fs::symlink_metadata(cx.workdir.join(path))
            && error.kind() == io::ErrorKind::NotFound
        {
            return Step::Dirty;
        }
    }
    Step::Fallback
}

fn scan_directory(
    cx: &mut WalkContext<'_>,
    rel_dir: &str,
    stack: &mut Vec<String>,
) -> Result<Step, String> {
    let abs_dir = if rel_dir.is_empty() {
        cx.workdir.to_path_buf()
    } else {
        cx.workdir.join(rel_dir)
    };
    let Ok(entries_iter) = fs::read_dir(&abs_dir) else {
        return Ok(Step::Fallback);
    };
    let expected = cx
        .dir_index
        .files
        .get(rel_dir)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut matched_in_dir = 0usize;

    for dent in entries_iter {
        let Ok(dent) = dent else {
            return Ok(Step::Fallback);
        };
        match scan_entry(cx, rel_dir, &dent, expected, stack, &mut matched_in_dir)? {
            Step::Continue => {}
            other => return Ok(other),
        }
    }
    if matched_in_dir != expected.len() {
        return Ok(if cx.config.ignorecase() {
            any_expected_file_missing(cx, expected)
        } else {
            Step::Dirty
        });
    }
    Ok(Step::Continue)
}

fn scan_entry(
    cx: &mut WalkContext<'_>,
    rel_dir: &str,
    dent: &DirEntry,
    expected: &[(&str, usize)],
    stack: &mut Vec<String>,
    matched_in_dir: &mut usize,
) -> Result<Step, String> {
    let name_os = dent.file_name();
    let Some(name) = name_os.to_str() else {
        return Ok(Step::Fallback);
    };
    // On macOS, HFS+/APFS may return NFD-decomposed Unicode names that differ
    // byte-for-byte from NFC index entries when core.precomposeunicode applies.
    if cfg!(target_os = "macos") && !name.is_ascii() {
        return Ok(Step::Fallback);
    }
    if rel_dir.is_empty() && is_git_dir_name(name, cx.config.ignorecase()) {
        return Ok(Step::Continue);
    }
    let Ok(ft) = dent.file_type() else {
        return Ok(Step::Fallback);
    };
    if ft.is_dir() {
        if expected.binary_search_by_key(&name, |item| item.0).is_ok() {
            return Ok(Step::Fallback);
        }
        let child_rel = join_rel(rel_dir, name);
        if cx.dir_index.tracked_dirs.contains(child_rel.as_str()) {
            stack.push(child_rel);
        } else if cx.config.untracked {
            return Ok(check_untracked_dir(cx, &child_rel));
        }
        return Ok(Step::Continue);
    }
    if let Ok(pos) = expected.binary_search_by_key(&name, |item| item.0) {
        *matched_in_dir += 1;
        cx.visited_files += 1;
        if !ft.is_file() {
            return Ok(Step::Fallback);
        }
        return check_tracked_file(cx, dent, expected[pos].1);
    }
    if cx.config.ignorecase()
        && expected
            .iter()
            .any(|item| item.0.eq_ignore_ascii_case(name))
    {
        return Ok(Step::Fallback);
    }
    if cx.config.untracked {
        let child_rel = join_rel(rel_dir, name);
        return Ok(
            match cx.repository.status_should_ignore(Path::new(&child_rel)) {
                Ok(true) => Step::Continue,
                Ok(false) => Step::Dirty,
                Err(_) => Step::Fallback,
            },
        );
    }
    Ok(Step::Continue)
}

fn check_tracked_file(
    cx: &mut WalkContext<'_>,
    dent: &DirEntry,
    entry_idx: usize,
) -> Result<Step, String> {
    let Ok(md) = dent.metadata() else {
        return Ok(Step::Fallback);
    };
    if is_reparse_or_dir(&md) {
        return Ok(Step::Fallback);
    }
    let entry = &cx.parsed.entries[entry_idx];
    if stat_matches(&md, entry, cx.index_mtime, cx.config) {
        return Ok(Step::Continue);
    }
    cx.stat_checks += 1;
    if cx.stat_checks > MAX_STAT_CHECKS {
        return Ok(Step::Fallback);
    }
    let path = cx.parsed.path(cx.index_bytes, entry);
    let Ok(status) = cx.repository.status_file(Path::new(path)) else {
        return Ok(Step::Fallback);
    };
    if status.contains(Status::WT_UNREADABLE) {
        return Err("working-tree status contains an unreadable path".into());
    }
    if status != Status::CURRENT && status != Status::IGNORED {
        return Ok(Step::Dirty);
    }
    Ok(Step::Continue)
}

fn check_untracked_dir(cx: &WalkContext<'_>, child_rel: &str) -> Step {
    match cx.repository.status_should_ignore(Path::new(child_rel)) {
        Ok(true) => Step::Continue,
        Ok(false) => match untracked_dir_has_dirty(cx.repository, cx.workdir, child_rel, cx.config)
        {
            Some(true) => Step::Dirty,
            Some(false) => Step::Continue,
            None => Step::Fallback,
        },
        Err(_) => Step::Fallback,
    }
}

fn untracked_dir_has_dirty(
    repository: &Repository,
    workdir: &Path,
    root_rel: &str,
    config: &ScanConfig,
) -> Option<bool> {
    let mut stack = vec![root_rel.to_owned()];
    let mut visited = 0usize;
    while let Some(rel_dir) = stack.pop() {
        visited += 1;
        if visited > MAX_UNTRACKED_DIRS {
            return None;
        }
        let entries = fs::read_dir(workdir.join(&rel_dir)).ok()?;
        for dent in entries {
            let dent = dent.ok()?;
            let name_os = dent.file_name();
            let name = name_os.to_str()?;
            if is_git_dir_name(name, config.ignorecase()) {
                return None;
            }
            let child_rel = join_rel(&rel_dir, name);
            if repository
                .status_should_ignore(Path::new(&child_rel))
                .ok()?
            {
                continue;
            }
            let ft = dent.file_type().ok()?;
            if ft.is_dir() {
                stack.push(child_rel);
            } else {
                return Some(true);
            }
        }
    }
    Some(false)
}

fn join_rel(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

fn is_git_dir_name(name: &str, ignorecase: bool) -> bool {
    if ignorecase {
        name.eq_ignore_ascii_case(".git")
    } else {
        name == ".git"
    }
}

fn time_matches(actual: Timestamp, expected: Timestamp) -> bool {
    actual.sec == expected.sec && (expected.nsec == 0 || actual.nsec == expected.nsec)
}

fn is_racy(actual: Timestamp, index_mtime: Timestamp) -> bool {
    if actual.sec != index_mtime.sec {
        return actual.sec > index_mtime.sec;
    }
    if index_mtime.nsec == 0 || actual.nsec == 0 {
        return true;
    }
    actual.nsec >= index_mtime.nsec
}

#[cfg(unix)]
fn metadata_mtime(md: &Metadata) -> Option<Timestamp> {
    use std::os::unix::fs::MetadataExt;
    let sec = u32::try_from(md.mtime()).ok()?;
    let nsec = u32::try_from(md.mtime_nsec()).ok()?;
    Some(Timestamp { sec, nsec })
}

#[cfg(windows)]
fn filetime_to_timestamp(ft: u64) -> Option<Timestamp> {
    let unix_100ns = ft.checked_sub(WINDOWS_EPOCH_OFFSET_100NS)?;
    let sec = u32::try_from(unix_100ns / 10_000_000).ok()?;
    let nsec = ((unix_100ns % 10_000_000) * 100) as u32;
    Some(Timestamp { sec, nsec })
}

#[cfg(windows)]
fn metadata_mtime(md: &Metadata) -> Option<Timestamp> {
    use std::os::windows::fs::MetadataExt;
    filetime_to_timestamp(md.last_write_time())
}

#[cfg(unix)]
fn is_reparse_or_dir(_md: &Metadata) -> bool {
    false
}

#[cfg(windows)]
fn is_reparse_or_dir(md: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    let attrs = md.file_attributes();
    (attrs & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0
}

#[cfg(unix)]
fn stat_matches(
    md: &Metadata,
    entry: &IndexEntry,
    index_mtime: Timestamp,
    config: &ScanConfig,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    if md.size() != u64::from(entry.file_size) {
        return false;
    }
    if config.filemode && ((md.mode() & 0o100 != 0) != (entry.mode & 0o100 != 0)) {
        return false;
    }
    let Some(mtime) = metadata_mtime(md) else {
        return false;
    };
    if !time_matches(mtime, entry.mtime) || is_racy(mtime, index_mtime) {
        return false;
    }
    if config.trustctime {
        let Ok(csec) = u32::try_from(md.ctime()) else {
            return false;
        };
        let Ok(cnsec) = u32::try_from(md.ctime_nsec()) else {
            return false;
        };
        if !time_matches(
            Timestamp {
                sec: csec,
                nsec: cnsec,
            },
            entry.ctime,
        ) {
            return false;
        }
    }
    (md.ino() as u32) == entry.ino
        && (md.dev() as u32) == entry.dev
        && md.uid() == entry.uid
        && md.gid() == entry.gid
}

#[cfg(windows)]
fn stat_matches(
    md: &Metadata,
    entry: &IndexEntry,
    index_mtime: Timestamp,
    config: &ScanConfig,
) -> bool {
    use std::os::windows::fs::MetadataExt;
    if md.file_size() != u64::from(entry.file_size) {
        return false;
    }
    let Some(mtime) = metadata_mtime(md) else {
        return false;
    };
    if !time_matches(mtime, entry.mtime) || is_racy(mtime, index_mtime) {
        return false;
    }
    if config.trustctime {
        let Some(ctime) = filetime_to_timestamp(md.creation_time()) else {
            return false;
        };
        if !time_matches(ctime, entry.ctime) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{CasePolicy, ScanConfig, try_scan};
    use git2::{Repository, RepositoryOpenFlags};
    use std::{error::Error, fs, path::PathBuf, process::Command};

    type Check = Result<(), Box<dyn Error>>;

    struct TempRepo(PathBuf);
    impl Drop for TempRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    impl TempRepo {
        fn new(label: &str) -> Result<Self, Box<dyn Error>> {
            let mut nonce = [0u8; 8];
            se_proc::fill_entropy(&mut nonce)?;
            let mut hex = String::with_capacity(16);
            for byte in nonce {
                hex.push_str(&format!("{byte:02x}"));
            }
            let root = std::env::temp_dir().join(format!("se-fast-scan-{label}-{hex}"));
            fs::create_dir_all(&root)?;
            let repo = Self(root);
            repo.git(&["init", "-q", "."])?;
            repo.git(&["config", "user.email", "test@example.invalid"])?;
            repo.git(&["config", "user.name", "test"])?;
            Ok(repo)
        }
        fn git(&self, args: &[&str]) -> Result<String, Box<dyn Error>> {
            let out = Command::new("git")
                .args(["-c", "core.fsmonitor=false", "-C"])
                .arg(&self.0)
                .args(args)
                .output()?;
            if !out.status.success() {
                return Err(format!(
                    "git {args:?} failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                )
                .into());
            }
            Ok(String::from_utf8(out.stdout)?)
        }
        fn scan_with_policy(
            &self,
            untracked: bool,
            case_policy: CasePolicy,
        ) -> Result<Option<bool>, Box<dyn Error>> {
            let repo = Repository::open_ext(
                &self.0,
                RepositoryOpenFlags::empty(),
                &[] as &[&std::ffi::OsStr],
            )?;
            let head = repo
                .head()?
                .target()
                .ok_or("HEAD has no target")?
                .to_string();
            let config = ScanConfig {
                untracked,
                #[cfg(unix)]
                filemode: true,
                trustctime: true,
                case_policy,
            };
            Ok(try_scan(&repo, &head, &config)?)
        }
        fn scan(&self, untracked: bool) -> Result<Option<bool>, Box<dyn Error>> {
            let case_policy = if cfg!(any(windows, target_os = "macos")) {
                CasePolicy::Insensitive
            } else {
                CasePolicy::Sensitive
            };
            self.scan_with_policy(untracked, case_policy)
        }
    }

    #[test]
    fn fast_scan_proves_clean_tracked_dirty_staged_deleted_and_untracked() -> Check {
        let repo = TempRepo::new("states")?;
        fs::write(repo.0.join(".gitignore"), "ignored.log\nignored_dir/\n")?;
        fs::create_dir_all(repo.0.join("src"))?;
        fs::write(repo.0.join("src/lib.rs"), "pub fn a() {}\n")?;
        repo.git(&["add", "."])?;
        repo.git(&["commit", "-qm", "initial"])?;

        fs::write(repo.0.join("ignored.log"), "skip")?;
        fs::create_dir_all(repo.0.join("ignored_dir"))?;
        fs::write(repo.0.join("ignored_dir/x"), "skip")?;
        fs::create_dir_all(repo.0.join("empty_dir"))?;
        assert_eq!(repo.scan(true)?, Some(false));

        fs::write(repo.0.join("empty_dir/new.txt"), "hi")?;
        assert_eq!(repo.scan(true)?, Some(true));
        assert_eq!(repo.scan(false)?, Some(false));
        fs::remove_file(repo.0.join("empty_dir/new.txt"))?;
        assert_eq!(repo.scan(true)?, Some(false));

        fs::write(repo.0.join("src/lib.rs"), "pub fn b() {}\n")?;
        assert_eq!(repo.scan(true)?, Some(true));

        repo.git(&["add", "src/lib.rs"])?;
        assert_eq!(repo.scan(true)?, Some(true));
        repo.git(&["commit", "-qm", "second"])?;
        assert_eq!(repo.scan(true)?, Some(false));

        fs::remove_file(repo.0.join("src/lib.rs"))?;
        assert_eq!(repo.scan(true)?, Some(true));
        assert_eq!(
            repo.scan_with_policy(true, CasePolicy::Insensitive)?,
            Some(true)
        );
        Ok(())
    }
}
