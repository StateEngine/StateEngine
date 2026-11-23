//! Discovery's ignore rules, applied to paths the watcher reports, so a file
//! that `.gitignore` or `.atlasignore` excludes never enters the index
//! between reconciles. Rule files are read through custody, matched the way
//! discovery matches them (each ancestor directory first, deeper rules
//! last), and cached per directory until any rule file changes.
use crate::filter;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use se_atlas_index::custody::{GuardedRead, IndexSourceRoot};
use std::{collections::HashMap, path::Path};

const RULE_FILES: [&str; 2] = [".gitignore", ".atlasignore"];
/// Rule file bytes discovery accepts.
const MAX_RULE_BYTES: usize = 64 * 1024;
/// Directories whose rules are kept before the cache starts over.
const MAX_CACHED: usize = 1024;

/// Whether `path` names an ignore rule file, whose change re-reads them all.
pub(crate) fn is_rule_file(path: &str) -> bool {
    let leaf = path.rsplit('/').next().unwrap_or(path);
    RULE_FILES.contains(&leaf)
}

#[derive(Default)]
pub(crate) struct Ignores {
    global: Option<Gitignore>,
    rules: HashMap<String, Vec<Gitignore>>,
}

impl Ignores {
    pub fn clear(&mut self) {
        self.rules.clear();
    }

    /// Whether discovery would skip the file `path`, or a directory above it.
    pub fn ignored(&mut self, source: &IndexSourceRoot, path: &str) -> bool {
        self.skipped(source, path, false)
    }

    /// Whether discovery would skip the directory `path` or one above it.
    pub fn ignored_directory(&mut self, source: &IndexSourceRoot, path: &str) -> bool {
        self.skipped(source, path, true)
    }

    fn skipped(&mut self, source: &IndexSourceRoot, path: &str, leaf_directory: bool) -> bool {
        let physical = source.physical_root();
        if self.global.is_none() {
            let patterns = filter::global_patterns();
            self.global = build(physical, patterns.iter().map(String::as_str));
        }
        let parts: Vec<&str> = path.split('/').collect();
        let mut chain = vec![String::new()];
        for at in 0..parts.len() {
            let entry = parts[..=at].join("/");
            let directory = leaf_directory || at + 1 < parts.len();
            for dir in &chain {
                self.load(source, dir);
            }
            if self.matches(physical, &chain, &entry, directory) {
                return true;
            }
            if directory {
                chain.push(entry);
            }
        }
        false
    }

    fn matches(&self, physical: &Path, chain: &[String], entry: &str, directory: bool) -> bool {
        let absolute = physical.join(entry);
        let mut ignored = self
            .global
            .as_ref()
            .is_some_and(|global| global.matched(&absolute, directory).is_ignore());
        for rules in chain.iter().filter_map(|dir| self.rules.get(dir)).flatten() {
            let matched = rules.matched(&absolute, directory);
            if matched.is_ignore() {
                ignored = true;
            } else if matched.is_whitelist() {
                ignored = false;
            }
        }
        ignored
    }

    /// Read one directory's rule files. A file that cannot be read applies
    /// no rules, as discovery counts and skips it.
    fn load(&mut self, source: &IndexSourceRoot, directory: &str) {
        if self.rules.contains_key(directory) {
            return;
        }
        if self.rules.len() >= MAX_CACHED {
            self.rules.clear();
        }
        let base = source.physical_root().join(directory);
        let mut rules = Vec::new();
        for name in RULE_FILES {
            let relative = if directory.is_empty() {
                name.to_owned()
            } else {
                format!("{directory}/{name}")
            };
            let Ok(GuardedRead::Source(file)) = source.read_guarded_file(&relative) else {
                continue;
            };
            if file.prefix_only || file.bytes.len() > MAX_RULE_BYTES {
                continue;
            }
            let text = String::from_utf8_lossy(&file.bytes);
            rules.extend(build(&base, text.lines()));
        }
        self.rules.insert(directory.to_owned(), rules);
    }
}

fn build<'l>(base: &Path, lines: impl Iterator<Item = &'l str>) -> Option<Gitignore> {
    let mut builder = GitignoreBuilder::new(base);
    for line in lines {
        // Git skips a line it cannot read; so does discovery.
        let _ = builder.add_line(None, line);
    }
    builder.build().ok()
}
