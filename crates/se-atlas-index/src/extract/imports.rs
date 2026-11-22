//! Import discovery and in-repository resolution. Spellings come from masked
//! code (so commented-out imports never count) with literal module names read
//! back from the source at the same offsets.
use super::{Grammar, ImportKind, ImportSpec};
use std::collections::{HashMap, HashSet};

const MAX_IMPORTS: usize = 512;
const MAX_STATEMENT: usize = 4096;
const MAX_TREE_LEAVES: usize = 64;

pub(crate) fn extract_imports(grammar: Grammar, text: &str, masked: &str) -> Vec<ImportSpec> {
    let mut out = Vec::new();
    match grammar {
        Grammar::Rust => rust_imports(masked, &mut out),
        Grammar::TypeScript | Grammar::JavaScript => js_imports(text, masked, &mut out),
        Grammar::Python => python_imports(masked, &mut out),
        Grammar::Go => go_imports(text, masked, &mut out),
        Grammar::C | Grammar::Cpp => include_imports(text, masked, &mut out),
        Grammar::Java | Grammar::Kotlin => keyword_lines(masked, "import ", &mut out),
        Grammar::CSharp => keyword_lines(masked, "using ", &mut out),
        Grammar::Zig => zig_imports(text, masked, &mut out),
        _ => {}
    }
    let mut seen = HashSet::new();
    out.retain(|spec| seen.insert(spec.spelling.clone()));
    out.truncate(MAX_IMPORTS);
    out
}

fn push(out: &mut Vec<ImportSpec>, spelling: String, kind: ImportKind, reexport: bool) {
    if !spelling.is_empty() && out.len() < MAX_IMPORTS {
        out.push(ImportSpec {
            spelling,
            kind,
            reexport,
        });
    }
}

/// Offsets of `word` in `text` with identifier boundaries on both sides.
fn word_sites<'t>(text: &'t str, word: &'t str) -> impl Iterator<Item = usize> + 't {
    let bytes = text.as_bytes();
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';
    text.match_indices(word)
        .map(|(at, _)| at)
        .filter(move |at| {
            let before = at.checked_sub(1).map(|p| bytes[p]);
            let after = bytes.get(at + word.len()).copied();
            !before.is_some_and(ident) && !after.is_some_and(ident)
        })
}

fn rust_imports(masked: &str, out: &mut Vec<ImportSpec>) {
    for at in word_sites(masked, "use") {
        let Some(reexport) = rust_item_prefix(&masked[..at]) else {
            continue;
        };
        let rest = &masked[at + 3..];
        let Some(end) = rest.find(';').filter(|end| *end <= MAX_STATEMENT) else {
            continue;
        };
        let mut leaves = Vec::new();
        expand_tree("", &normalize_tree(&rest[..end]), &mut leaves);
        for leaf in leaves {
            push(
                out,
                module_path(&leaf).to_owned(),
                ImportKind::Import,
                reexport,
            );
        }
    }
    for at in word_sites(masked, "mod") {
        let Some(reexport) = rust_item_prefix(&masked[..at]) else {
            continue;
        };
        let rest = masked[at + 3..].trim_start();
        let name = super::outline::ident(rest);
        if !name.is_empty() && rest[name.len()..].trim_start().starts_with(';') {
            push(out, format!("mod {name}"), ImportKind::Module, reexport);
        }
    }
}

/// A `use` leaf naming a type, trait or glob is recorded as its module path:
/// edges join on the target file, and the item name is in the token index.
fn module_path(leaf: &str) -> &str {
    match leaf.rsplit_once("::") {
        Some((module, item))
            if item == "*" || item.starts_with(|c: char| c.is_ascii_uppercase()) =>
        {
            module
        }
        _ => leaf,
    }
}

/// `Some(is_pub)` when the text before a keyword ends a previous item.
fn rust_item_prefix(before: &str) -> Option<bool> {
    let cut = before.rfind([';', '{', '}', ']']).map_or(0, |at| at + 1);
    let chunk = before[cut..].trim();
    if chunk.is_empty() {
        return Some(false);
    }
    let public = chunk == "pub" || (chunk.starts_with("pub") && chunk.ends_with(')'));
    public.then_some(true)
}

/// Collapse whitespace, keeping a space only between two word characters so
/// `x as y` survives and `a :: { b }` becomes `a::{b}`.
fn normalize_tree(tree: &str) -> String {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = String::with_capacity(tree.len());
    let mut pending_space = false;
    for c in tree.chars() {
        if c.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && out.chars().last().is_some_and(word) && word(c) {
            out.push(' ');
        }
        pending_space = false;
        out.push(c);
    }
    out
}

fn expand_tree(prefix: &str, tree: &str, out: &mut Vec<String>) {
    if out.len() >= MAX_TREE_LEAVES {
        return;
    }
    let join = |head: &str| match (prefix.is_empty(), head.is_empty()) {
        (true, _) => head.to_owned(),
        (_, true) => prefix.to_owned(),
        _ => format!("{prefix}::{head}"),
    };
    match tree.find('{') {
        Some(open) if tree.ends_with('}') => {
            let base = join(tree[..open].trim_end_matches("::"));
            for part in split_top_level(&tree[open + 1..tree.len() - 1]) {
                match part {
                    "" => {}
                    "self" => out.push(base.clone()),
                    part => expand_tree(&base, part, out),
                }
            }
        }
        _ => {
            let leaf = tree.split(" as ").next().unwrap_or(tree);
            out.push(join(leaf));
        }
    }
}

fn split_top_level(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, b) in text.bytes().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(text[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(text[start..].trim());
    parts
}

/// The literal whose opening quote sits at `open` in masked text.
fn literal_at<'t>(text: &'t str, masked: &str, open: usize) -> Option<&'t str> {
    let quote = *masked.as_bytes().get(open)?;
    let close = masked[open + 1..].find(quote as char)? + open + 1;
    text.get(open + 1..close)
}

/// The first quote at bracket depth zero after `start`, before a statement end.
fn module_quote(masked: &str, start: usize, need_from: bool) -> Option<usize> {
    let mut depth = 0i32;
    let mut saw_from = !need_from;
    let rest = masked.get(start..)?;
    for (i, b) in rest.bytes().enumerate().take(MAX_STATEMENT) {
        match b {
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => depth -= 1,
            b'\'' | b'"' | b'`' if depth == 0 => return saw_from.then_some(start + i),
            b';' | b'\n' if depth == 0 && i > 0 => {
                if !rest[..i].trim_end().ends_with(['{', ',']) {
                    return None;
                }
            }
            b'f' if depth == 0 && rest[i..].starts_with("from") => saw_from = true,
            _ => {}
        }
    }
    None
}

fn js_imports(text: &str, masked: &str, out: &mut Vec<ImportSpec>) {
    for (word, reexport) in [("import", false), ("export", true)] {
        for at in word_sites(masked, word) {
            let after = masked[at + word.len()..].trim_start();
            if after.starts_with('(') {
                continue;
            }
            let quote = module_quote(masked, at + word.len(), reexport);
            if let Some(spelling) = quote.and_then(|q| literal_at(text, masked, q)) {
                push(out, spelling.to_owned(), ImportKind::Import, reexport);
            }
        }
    }
    for call in ["require", "import"] {
        for at in word_sites(masked, call) {
            let rest = &masked[at + call.len()..];
            let Some(open) = rest.strip_prefix('(').map(str::trim_start) else {
                continue;
            };
            let quote = at + call.len() + (rest.len() - open.len());
            if open.starts_with(['\'', '"', '`'])
                && let Some(spelling) = literal_at(text, masked, quote)
            {
                push(out, spelling.to_owned(), ImportKind::Dynamic, false);
            }
        }
    }
}

fn python_imports(masked: &str, out: &mut Vec<ImportSpec>) {
    for line in logical_lines(masked) {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("import ") {
            for module in rest.split(',') {
                let module = module.split(" as ").next().unwrap_or("").trim();
                push(out, module.to_owned(), ImportKind::Import, false);
            }
        } else if let Some(rest) = line.strip_prefix("from ") {
            let Some((module, names)) = rest.split_once(" import ") else {
                continue;
            };
            let module = module.trim();
            if module == "__future__" {
                continue;
            }
            if module.trim_start_matches('.').is_empty() {
                for name in names.trim_matches(['(', ')', ' ']).split(',') {
                    let name = name.split(" as ").next().unwrap_or("").trim();
                    if !name.is_empty() && name != "*" {
                        push(out, format!("{module}{name}"), ImportKind::Import, false);
                    }
                }
            } else {
                push(out, module.to_owned(), ImportKind::Import, false);
            }
        }
    }
}

/// Physical lines joined while brackets are open or a backslash continues.
fn logical_lines(masked: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    for line in masked.lines() {
        let trimmed = line.trim_end();
        depth += trimmed.bytes().fold(0, |sum, b| match b {
            b'(' | b'[' | b'{' => sum + 1,
            b')' | b']' | b'}' => sum - 1,
            _ => sum,
        });
        current.push_str(trimmed.trim_end_matches('\\'));
        current.push(' ');
        if depth <= 0 && !trimmed.ends_with('\\') {
            out.push(std::mem::take(&mut current));
            depth = 0;
        }
    }
    out.push(current);
    out
}

fn go_imports(text: &str, masked: &str, out: &mut Vec<ImportSpec>) {
    for at in word_sites(masked, "import") {
        let rest = masked[at + 6..].trim_start();
        let start = masked.len() - rest.len();
        let end = if rest.starts_with('(') {
            rest.find(')').map_or(masked.len(), |close| start + close)
        } else {
            rest.find('\n').map_or(masked.len(), |close| start + close)
        };
        let mut i = start;
        while let Some(open) = masked[i..end].find(['"', '`']).map(|at| at + i) {
            let Some(spelling) = literal_at(text, masked, open) else {
                break;
            };
            push(out, spelling.to_owned(), ImportKind::Import, false);
            i = open + spelling.len() + 2;
            if i >= end {
                break;
            }
        }
    }
}

fn include_imports(text: &str, masked: &str, out: &mut Vec<ImportSpec>) {
    let mut offset = 0;
    for line in masked.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let Some(target) = rest.trim_start().strip_prefix("include") else {
            continue;
        };
        let target = target.trim();
        let spelling = if target.starts_with('"') {
            line.find('"')
                .and_then(|quote| literal_at(text, masked, start + quote))
        } else {
            target.strip_prefix('<').and_then(|t| t.split('>').next())
        };
        if let Some(spelling) = spelling {
            push(out, spelling.to_owned(), ImportKind::Import, false);
        }
    }
}

fn keyword_lines(masked: &str, keyword: &str, out: &mut Vec<ImportSpec>) {
    for line in masked.lines() {
        let Some(rest) = line.trim_start().strip_prefix(keyword) else {
            continue;
        };
        let rest = rest.trim().trim_end_matches(';').trim();
        let rest = rest.strip_prefix("static ").unwrap_or(rest).trim();
        let path = rest.split(" as ").next().unwrap_or(rest).trim();
        let simple = path
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '*'));
        if simple && !path.contains("..") {
            push(out, path.to_owned(), ImportKind::Import, false);
        }
    }
}

fn zig_imports(text: &str, masked: &str, out: &mut Vec<ImportSpec>) {
    for (at, _) in masked.match_indices("@import(") {
        let open = at + 8;
        if masked.as_bytes().get(open) == Some(&b'"')
            && let Some(spelling) = literal_at(text, masked, open)
        {
            push(out, spelling.to_owned(), ImportKind::Import, false);
        }
    }
}

/// Resolves import spellings to files that exist in the indexed set.
#[derive(Default)]
pub struct Resolver {
    files: HashSet<String>,
    dirs: HashMap<String, Vec<String>>,
    crates: HashMap<String, String>,
    classes: HashMap<String, String>,
}

impl Resolver {
    pub fn new<'a>(paths: impl IntoIterator<Item = &'a str>) -> Self {
        let mut resolver = Self::default();
        for path in paths {
            resolver.insert(path);
        }
        resolver
    }

    pub fn insert(&mut self, path: &str) {
        if !self.files.insert(path.to_owned()) {
            return;
        }
        let entries = self.dirs.entry(dir_of(path).to_owned()).or_default();
        let at = entries.partition_point(|entry| entry.as_str() < path);
        entries.insert(at, path.to_owned());
        if let Some(crate_dir) = path.strip_suffix("src/lib.rs") {
            let name = crate_dir
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or("");
            if !name.is_empty() {
                self.crates
                    .insert(name.replace('-', "_"), format!("{crate_dir}src/"));
            }
        }
        if let Some(class) = path
            .strip_suffix(".java")
            .or_else(|| path.strip_suffix(".kt"))
        {
            for (at, _) in class.match_indices('/') {
                self.classes
                    .entry(class[at + 1..].to_owned())
                    .or_insert_with(|| path.to_owned());
            }
            self.classes
                .entry(class.to_owned())
                .or_insert_with(|| path.to_owned());
        }
    }

    pub fn remove(&mut self, path: &str) {
        if self.files.remove(path) {
            if let Some(entries) = self.dirs.get_mut(dir_of(path)) {
                entries.retain(|entry| entry != path);
            }
            self.crates.retain(|_, dir| format!("{dir}lib.rs") != path);
            self.classes.retain(|_, file| file != path);
        }
    }

    pub fn contains(&self, path: &str) -> bool {
        self.files.contains(path)
    }

    /// The indexed file an import names, when it is inside the repository.
    pub fn resolve(&self, from: &str, spec: &ImportSpec) -> Option<String> {
        self.resolve_any(from, spec).filter(|target| target != from)
    }

    fn resolve_any(&self, from: &str, spec: &ImportSpec) -> Option<String> {
        let spelling = spec.spelling.as_str();
        match Grammar::detect(from) {
            Grammar::Rust => self.rust(from, spelling, spec.kind),
            Grammar::TypeScript | Grammar::JavaScript => self.js(from, spelling),
            Grammar::Python => self.python(from, spelling),
            Grammar::Go => self.go(spelling),
            Grammar::C | Grammar::Cpp => self.include(from, spelling),
            Grammar::Java | Grammar::Kotlin => {
                let class = spelling.trim_end_matches(".*").replace('.', "/");
                self.classes.get(&class).cloned()
            }
            Grammar::Zig => {
                normalize(&format!("{}{spelling}", dir_of(from))).filter(|path| self.contains(path))
            }
            _ => None,
        }
    }

    fn first(&self, candidates: impl IntoIterator<Item = String>) -> Option<String> {
        candidates
            .into_iter()
            .find(|path| self.files.contains(path))
    }

    fn rust(&self, from: &str, spelling: &str, kind: ImportKind) -> Option<String> {
        if kind == ImportKind::Module {
            let name = spelling.strip_prefix("mod ")?;
            let dir = module_dir(from);
            return self.first([format!("{dir}{name}.rs"), format!("{dir}{name}/mod.rs")]);
        }
        let segments: Vec<&str> = spelling
            .split("::")
            .filter(|s| !s.is_empty() && *s != "*")
            .collect();
        let (base, rest, explicit) = match *segments.first()? {
            "crate" => (crate_root(from)?, &segments[1..], true),
            "self" => (module_dir(from), &segments[1..], true),
            "super" => {
                let supers = segments.iter().take_while(|s| **s == "super").count();
                let mut dir = module_dir(from);
                for _ in 0..supers {
                    dir = parent_dir(&dir);
                }
                (dir, &segments[supers..], true)
            }
            name => match self.crates.get(name) {
                Some(dir) => (dir.clone(), &segments[1..], true),
                // A bare path may name a child of the current module.
                None => (module_dir(from), &segments[..], false),
            },
        };
        for n in (1..=rest.len()).rev() {
            let path = format!("{base}{}", rest[..n].join("/"));
            if let Some(hit) = self.first([format!("{path}.rs"), format!("{path}/mod.rs")]) {
                return Some(hit);
            }
        }
        if !explicit {
            return None;
        }
        let parent = base.trim_end_matches('/');
        self.first([
            format!("{base}lib.rs"),
            format!("{base}main.rs"),
            format!("{base}mod.rs"),
            format!("{parent}.rs"),
        ])
    }

    fn js(&self, from: &str, spelling: &str) -> Option<String> {
        if !spelling.starts_with('.') {
            return None;
        }
        let base = normalize(&format!("{}{spelling}", dir_of(from)))?;
        const EXTS: [&str; 8] = ["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"];
        let stem = [".js", ".jsx", ".mjs", ".cjs"]
            .iter()
            .find_map(|ext| base.strip_suffix(ext));
        let mut candidates = vec![base.clone()];
        candidates.extend(EXTS.iter().map(|ext| format!("{base}.{ext}")));
        candidates.push(format!("{base}.d.ts"));
        candidates.extend(EXTS.iter().map(|ext| format!("{base}/index.{ext}")));
        if let Some(stem) = stem {
            candidates.extend(
                ["ts", "tsx", "mts", "cts"]
                    .iter()
                    .map(|ext| format!("{stem}.{ext}")),
            );
        }
        self.first(candidates)
    }

    fn python(&self, from: &str, spelling: &str) -> Option<String> {
        let dots = spelling.bytes().take_while(|b| *b == b'.').count();
        let module = spelling[dots..].replace('.', "/");
        let roots: Vec<String> = if dots > 0 {
            let mut dir = dir_of(from).to_owned();
            for _ in 1..dots {
                dir = parent_dir(&dir);
            }
            vec![dir]
        } else {
            vec![String::new(), "src/".to_owned(), dir_of(from).to_owned()]
        };
        roots.iter().find_map(|root| {
            self.first([
                format!("{root}{module}.py"),
                format!("{root}{module}/__init__.py"),
            ])
        })
    }

    fn go(&self, spelling: &str) -> Option<String> {
        let dir = self
            .dirs
            .keys()
            .filter(|dir| {
                let dir = dir.trim_end_matches('/');
                !dir.is_empty() && (spelling == dir || spelling.ends_with(&format!("/{dir}")))
            })
            .max_by_key(|dir| dir.len())?;
        self.dirs
            .get(dir)?
            .iter()
            .find(|file| file.ends_with(".go") && !file.ends_with("_test.go"))
            .cloned()
    }

    fn include(&self, from: &str, spelling: &str) -> Option<String> {
        let local = normalize(&format!("{}{spelling}", dir_of(from)));
        let candidates = local.into_iter().chain([
            spelling.to_owned(),
            format!("include/{spelling}"),
            format!("src/{spelling}"),
        ]);
        self.first(candidates)
    }
}

/// Directory part of a path, with a trailing slash, or empty at the root.
fn dir_of(path: &str) -> &str {
    path.rfind('/').map_or("", |at| &path[..=at])
}

fn parent_dir(dir: &str) -> String {
    let trimmed = dir.trim_end_matches('/');
    trimmed
        .rfind('/')
        .map_or(String::new(), |at| trimmed[..=at].to_owned())
}

/// The directory holding a Rust file's child modules.
fn module_dir(from: &str) -> String {
    let dir = dir_of(from);
    let name = &from[dir.len()..];
    let stem = name.strip_suffix(".rs").unwrap_or(name);
    if matches!(stem, "lib" | "main" | "mod") {
        dir.to_owned()
    } else {
        format!("{dir}{stem}/")
    }
}

fn crate_root(from: &str) -> Option<String> {
    if from.starts_with("src/") {
        return Some("src/".to_owned());
    }
    from.rfind("/src/").map(|at| from[..at + 5].to_owned())
}

/// Resolve `.` and `..` segments; `None` when the path leaves the root.
fn normalize(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}
