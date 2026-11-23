//! Streaming no-follow discovery. Directories are enumerated through retained
//! handles; `.gitignore` and `.atlasignore` are read through the same guarded
//! custody as source files, and the `ignore` crate only matches names.
use crate::{
    IndexError, Result,
    custody::{self, GuardedRead, IndexSourceRoot},
    policy,
};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use se_proc::{NativeRootDirectory, NativeSourceEntry, NativeSourceKind};
use std::{io, path::Path, time::Instant};

const MAX_DEPTH: usize = 128;
const MAX_DIRECTORIES: u32 = 65_536;
const MAX_IGNORE_BYTES: usize = 64 * 1024;
const IGNORE_FILES: [&str; 2] = [".gitignore", ".atlasignore"];

/// Caller-supplied discovery bounds and patterns.
#[derive(Clone, Debug)]
pub struct WalkOptions {
    /// Gitignore-syntax patterns applied below every ignore file.
    pub global_patterns: Vec<String>,
    /// Discovery stops, incomplete, once this many files are found.
    pub max_files: usize,
    /// Discovery stops, incomplete, once this instant has passed.
    pub deadline: Option<Instant>,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            global_patterns: Vec::new(),
            max_files: 200_000,
            deadline: None,
        }
    }
}

/// Everything discovery saw. Skips are counted by reason, never folded
/// together, and `complete` is false when a bound stopped the walk early.
#[derive(Debug, Default)]
pub struct Discovery {
    /// Root-relative slash-separated file paths, sorted.
    pub files: Vec<String>,
    /// Root-relative directories entered, empty ones included, in walk order.
    pub directories: Vec<String>,
    pub denied: u32,
    pub ignored: u32,
    pub links: u32,
    /// Names that are not portable UTF-8 path components.
    pub unnameable: u32,
    /// Ignore-file lines the matcher could not compile, skipped like Git does.
    pub invalid_ignore_lines: u32,
    /// Ignore files that could not be read through custody (a link, a
    /// device, no permission); their rules were not applied.
    pub unreadable_ignore_files: u32,
    /// Directories that disappeared or were replaced between listing and
    /// entering them, or while they were listed.
    pub vanished_dirs: u32,
    /// Directories the walker had no permission to list.
    pub unreadable_dirs: u32,
    /// Directories custody refused to enter, such as one swapped for a link.
    pub refused_dirs: u32,
    /// False when a bound stopped the walk or any directory was skipped.
    pub complete: bool,
}

struct Frame<'a> {
    path: String,
    cursor: NativeRootDirectory<'a>,
    pending: std::vec::IntoIter<NativeSourceEntry>,
    rules: Vec<Gitignore>,
}

/// Walk the registered root depth-first without following any link.
pub fn discover(root: &IndexSourceRoot, options: &WalkOptions) -> Result<Discovery> {
    let mut out = Discovery::default();
    let physical = root.physical_root();
    let global = build_rules(physical, options.global_patterns.iter().map(String::as_str))?;
    out.invalid_ignore_lines += global.1;
    let Some(top) = open_frame(root, String::new(), &mut out)? else {
        let gone = io::Error::new(io::ErrorKind::NotFound, "the source root is gone");
        return Err(gone.into());
    };
    let mut stack = vec![top];
    let mut directories = 1u32;
    let mut skipped = false;
    while let Some(frame) = stack.last_mut() {
        if options
            .deadline
            .is_some_and(|until| Instant::now() >= until)
        {
            out.files.sort_unstable();
            return Ok(out);
        }
        let entry = match next_entry(frame) {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                stack.pop();
                continue;
            }
            // The root itself is exempt: losing it is never a skip.
            Err(error) if stack.len() > 1 => {
                skip(root, &mut out, &error)?;
                skipped = true;
                stack.pop();
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let Some(path) = child_path(&frame.path, &entry, &mut out) else {
            continue;
        };
        let directory = entry.kind == NativeSourceKind::Directory;
        if denied(&path, directory) {
            out.denied += 1;
            continue;
        }
        if ignored(physical, &path, directory, &global.0, &stack) {
            out.ignored += 1;
            continue;
        }
        if !directory {
            out.files.push(path);
            if out.files.len() >= options.max_files {
                out.files.sort_unstable();
                return Ok(out);
            }
            continue;
        }
        directories += 1;
        if stack.len() >= MAX_DEPTH || directories > MAX_DIRECTORIES {
            out.files.sort_unstable();
            return Ok(out);
        }
        match open_frame(root, path, &mut out) {
            Ok(Some(frame)) => {
                out.directories.push(frame.path.clone());
                stack.push(frame);
            }
            Ok(None) => {
                out.vanished_dirs += 1;
                skipped = true;
            }
            Err(IndexError::Io(error)) => {
                skip(root, &mut out, &error)?;
                skipped = true;
            }
            Err(error) => return Err(error),
        }
    }
    out.files.sort_unstable();
    out.complete = !skipped;
    Ok(out)
}

/// Count a directory that could not be entered or listed. Custody's verdict
/// that a directory changed carries no portable kind, so the root is checked
/// again: a changed root is still an error, never a skip.
fn skip(root: &IndexSourceRoot, out: &mut Discovery, error: &io::Error) -> Result<()> {
    root.check()?;
    if error.kind() == io::ErrorKind::NotFound {
        out.vanished_dirs += 1;
    } else if custody::refusal(error) {
        out.refused_dirs += 1;
    } else {
        out.unreadable_dirs += 1;
    }
    Ok(())
}

fn denied(path: &str, directory: bool) -> bool {
    if directory {
        policy::directory_denied(path)
    } else {
        policy::file_denied(path)
    }
}

fn next_entry(frame: &mut Frame<'_>) -> io::Result<Option<NativeSourceEntry>> {
    if let Some(entry) = frame.pending.next() {
        return Ok(Some(entry));
    }
    let batch = frame.cursor.next_batch()?;
    if batch.is_empty() {
        return Ok(None);
    }
    frame.pending = batch.into_iter();
    Ok(frame.pending.next())
}

fn child_path(parent: &str, entry: &NativeSourceEntry, out: &mut Discovery) -> Option<String> {
    if matches!(entry.kind, NativeSourceKind::Link | NativeSourceKind::Other) {
        out.links += 1;
        return None;
    }
    let Some(name) = entry.name.to_str() else {
        out.unnameable += 1;
        return None;
    };
    if name.is_empty() || name == "." || name == ".." || name.contains(['\\', ':', '\0']) {
        out.unnameable += 1;
        return None;
    }
    Some(if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    })
}

fn ignored(
    physical: &Path,
    path: &str,
    directory: bool,
    global: &Gitignore,
    stack: &[Frame<'_>],
) -> bool {
    let absolute = physical.join(path);
    let mut ignored = global.matched(&absolute, directory).is_ignore();
    for rules in stack.iter().flat_map(|frame| frame.rules.iter()) {
        let matched = rules.matched(&absolute, directory);
        if matched.is_ignore() {
            ignored = true;
        } else if matched.is_whitelist() {
            ignored = false;
        }
    }
    ignored
}

/// `None` when the directory vanished before it could be opened.
fn open_frame<'a>(
    root: &'a IndexSourceRoot,
    path: String,
    out: &mut Discovery,
) -> Result<Option<Frame<'a>>> {
    let Some(cursor) = root.native().open_directory(&path)? else {
        return Ok(None);
    };
    let base = root.physical_root().join(&path);
    let mut rules = Vec::new();
    for name in IGNORE_FILES {
        let relative = if path.is_empty() {
            name.to_owned()
        } else {
            format!("{path}/{name}")
        };
        let file = match root.read_guarded_file(&relative) {
            Ok(GuardedRead::Source(file)) => file,
            Ok(GuardedRead::Absent | GuardedRead::Denied) => continue,
            Ok(GuardedRead::Refused) => {
                out.unreadable_ignore_files += 1;
                continue;
            }
            Err(_) => {
                // A changed root is an error; anything else about this one
                // file (no permission, edited mid-read) skips its rules.
                root.check()?;
                out.unreadable_ignore_files += 1;
                continue;
            }
        };
        if file.prefix_only || file.bytes.len() > MAX_IGNORE_BYTES {
            return Err(IndexError::IgnoreRule(format!("{relative} exceeds 64 KiB")));
        }
        let text = String::from_utf8_lossy(&file.bytes);
        let (built, invalid) = build_rules(&base, text.lines())?;
        out.invalid_ignore_lines += invalid;
        rules.push(built);
    }
    Ok(Some(Frame {
        path,
        cursor,
        pending: Vec::new().into_iter(),
        rules,
    }))
}

fn build_rules<'l>(base: &Path, lines: impl Iterator<Item = &'l str>) -> Result<(Gitignore, u32)> {
    let mut builder = GitignoreBuilder::new(base);
    let mut invalid = 0;
    for line in lines {
        if builder.add_line(None, line).is_err() {
            invalid += 1;
        }
    }
    let built = builder
        .build()
        .map_err(|error| IndexError::IgnoreRule(error.to_string()))?;
    Ok((built, invalid))
}
