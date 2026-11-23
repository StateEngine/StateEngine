//! Pure-Rust extraction: one shared lexical and delimiter-depth scanner feeds
//! per-language outline rules, dual tokenization and import discovery.
//!
//! Extraction never fails a file: binary, minified and oversized inputs keep
//! their path and leading tokens with an explicit flag, and a panic in any rule
//! is contained to that file and reported as `EXTRACT_FAILED`.
mod c_family;
pub mod covers;
mod declared;
mod go;
pub mod imports;
mod js_ts;
mod lex;
mod markup;
mod outline;
mod python;
mod rust;
pub mod tokens;

pub use declared::display_name;
pub(crate) use outline::parents_first;
pub use outline::{Accuracy, Symbol, SymbolKind, find_word};
use std::{borrow::Cow, collections::HashMap, fmt};

/// File flag bits stored in `files.flags`.
pub mod flags {
    pub const BINARY: u32 = 1;
    pub const MINIFIED: u32 = 1 << 1;
    pub const TRUNCATED: u32 = 1 << 2;
    pub const TEST: u32 = 1 << 3;
    pub const GENERATED: u32 = 1 << 4;
    pub const EXTRACT_FAILED: u32 = 1 << 5;
    /// The file carries inline unit tests (Rust `#[cfg(test)]`).
    pub const INLINE_TESTS: u32 = 1 << 6;
}

/// Raised whenever extraction changes its output, so stored indexes rebuild.
pub const EXTRACTOR_VERSION: i64 = 2;
const BINARY_SNIFF: usize = 8 * 1024;
const MAX_LINE: usize = 4 * 1024;
const MINIFIED_AVERAGE_LINE: usize = 300;
const MINIFIED_MIN_BYTES: usize = 8 * 1024;
const MINIFIED_PREFIX: usize = 64 * 1024;
/// Symbols beyond this many per file are dropped and the file is truncated.
pub const MAX_SYMBOLS: usize = 20_000;

/// An open, lowercase language name. Known names select outline rules; any
/// other well-formed name is kept and indexed as text.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LanguageTag(Cow<'static, str>);

impl LanguageTag {
    pub const TEXT: Self = Self(Cow::Borrowed("text"));

    /// Accept a user-supplied tag: 1 to 32 ASCII letters, digits, `+`, `#`,
    /// `-` or `_`, compared lowercase.
    pub fn new(tag: &str) -> Option<Self> {
        let valid = (1..=32).contains(&tag.len())
            && tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+#-_".contains(&b));
        valid.then(|| Self(Cow::Owned(tag.to_ascii_lowercase())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The language a root-relative path most likely holds.
    pub fn detect(path: &str) -> Self {
        Self(Cow::Borrowed(Grammar::detect(path).tag()))
    }
}

impl fmt::Display for LanguageTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Outline rules selected for one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Grammar {
    Rust,
    TypeScript,
    JavaScript,
    Python,
    Go,
    C,
    Cpp,
    Java,
    CSharp,
    Kotlin,
    Zig,
    Shell,
    Markdown,
    Toml,
    Yaml,
    Json,
    Sql,
    Makefile,
    Dockerfile,
    Text,
}

impl Grammar {
    pub(crate) fn detect(path: &str) -> Self {
        let name = path.rsplit('/').next().unwrap_or(path);
        if let Some(grammar) = Self::by_name(name) {
            return grammar;
        }
        let Some((_, ext)) = name.rsplit_once('.') else {
            return Self::Text;
        };
        Self::by_extension(&ext.to_ascii_lowercase())
    }

    fn by_name(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        if matches!(lower.as_str(), "makefile" | "gnumakefile") {
            return Some(Self::Makefile);
        }
        if lower == "dockerfile" || lower.starts_with("dockerfile.") {
            return Some(Self::Dockerfile);
        }
        (lower == "cargo.lock").then_some(Self::Toml)
    }

    fn by_extension(ext: &str) -> Self {
        match ext {
            "rs" => Self::Rust,
            "ts" | "tsx" | "mts" | "cts" => Self::TypeScript,
            "js" | "jsx" | "mjs" | "cjs" => Self::JavaScript,
            "py" | "pyi" => Self::Python,
            "go" => Self::Go,
            "c" | "h" => Self::C,
            "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" | "ipp" => Self::Cpp,
            "java" => Self::Java,
            "cs" => Self::CSharp,
            "kt" | "kts" => Self::Kotlin,
            "zig" => Self::Zig,
            "sh" | "bash" | "zsh" | "ksh" => Self::Shell,
            "md" | "markdown" => Self::Markdown,
            "toml" => Self::Toml,
            "yaml" | "yml" => Self::Yaml,
            "json" | "jsonc" => Self::Json,
            "sql" => Self::Sql,
            "mk" => Self::Makefile,
            "dockerfile" => Self::Dockerfile,
            _ => Self::Text,
        }
    }

    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::TypeScript => "typescript",
            Self::JavaScript => "javascript",
            Self::Python => "python",
            Self::Go => "go",
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::Java => "java",
            Self::CSharp => "csharp",
            Self::Kotlin => "kotlin",
            Self::Zig => "zig",
            Self::Shell => "shell",
            Self::Markdown => "markdown",
            Self::Toml => "toml",
            Self::Yaml => "yaml",
            Self::Json => "json",
            Self::Sql => "sql",
            Self::Makefile => "makefile",
            Self::Dockerfile => "dockerfile",
            Self::Text => "text",
        }
    }
}

/// One import spelling as written, before resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportSpec {
    pub spelling: String,
    pub kind: ImportKind,
    pub reexport: bool,
}

/// How an import was written; stored as `imp.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportKind {
    /// `use`, `import`, `from ... import`, `#include` and similar.
    Import = 1,
    /// A child module declaration such as Rust `mod foo;`.
    Module = 2,
    /// A runtime load such as `require()` or `import()`.
    Dynamic = 3,
}

/// Everything extracted from one file.
#[derive(Debug)]
pub struct Extracted {
    pub lang: LanguageTag,
    pub flags: u32,
    /// BLAKE3 of the bytes read.
    pub hash: [u8; 32],
    /// Lowercase tokens with their term frequency, sorted by token.
    pub tokens: Vec<(String, u32)>,
    pub accuracy: Accuracy,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<ImportSpec>,
}

/// The 16-byte stable key of a root-relative path.
pub fn file_key(path: &str) -> [u8; 16] {
    let digest = blake3::hash(path.as_bytes());
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest.as_bytes()[..16]);
    key
}

/// Extract one file. `prefix_only` reports that the reader kept only the
/// leading bytes of a larger file. A panic anywhere in extraction is
/// contained: the file keeps its path tokens and is flagged `EXTRACT_FAILED`.
pub fn extract(path: &str, bytes: &[u8], prefix_only: bool) -> Extracted {
    std::panic::catch_unwind(|| extract_guarded(path, bytes, prefix_only))
        .unwrap_or_else(|_| failed(path, bytes))
}

fn failed(path: &str, bytes: &[u8]) -> Extracted {
    let grammar = Grammar::detect(path);
    let mut counts = HashMap::new();
    tokens::tokenize(path, &mut counts);
    Extracted {
        lang: LanguageTag(Cow::Borrowed(grammar.tag())),
        flags: flags::EXTRACT_FAILED,
        hash: *blake3::hash(bytes).as_bytes(),
        tokens: tokens::sorted(counts),
        accuracy: outline::accuracy_of(grammar),
        symbols: Vec::new(),
        imports: Vec::new(),
    }
}

fn extract_guarded(path: &str, bytes: &[u8], prefix_only: bool) -> Extracted {
    let grammar = Grammar::detect(path);
    let mut out = Extracted {
        lang: LanguageTag(Cow::Borrowed(grammar.tag())),
        flags: 0,
        hash: *blake3::hash(bytes).as_bytes(),
        tokens: Vec::new(),
        accuracy: outline::accuracy_of(grammar),
        symbols: Vec::new(),
        imports: Vec::new(),
    };
    let mut counts = HashMap::new();
    tokens::tokenize(path, &mut counts);
    if bytes[..bytes.len().min(BINARY_SNIFF)].contains(&0) {
        out.flags |= flags::BINARY;
        out.tokens = tokens::sorted(counts);
        return out;
    }
    let bytes = bytes.strip_prefix("\u{feff}".as_bytes()).unwrap_or(bytes);
    let text = String::from_utf8_lossy(bytes);
    if prefix_only || minified(&text) {
        out.flags |= flags::TRUNCATED | flags::MINIFIED;
        tokens::tokenize(char_prefix(&text, MINIFIED_PREFIX), &mut counts);
        out.tokens = tokens::sorted(counts);
        return out;
    }
    if lock_file(path) {
        // Generated dependency pins: searchable, but an outline is noise.
        out.flags |= flags::GENERATED;
        tokens::tokenize(&text, &mut counts);
        out.tokens = tokens::sorted(counts);
        return out;
    }
    let full = std::panic::catch_unwind(|| extract_text(path, &text, grammar));
    match full {
        Ok(full) => {
            for (token, tf) in full.tokens.into_iter().chain(full.name_tokens) {
                *counts.entry(token).or_insert(0) += tf;
            }
            out.flags |= full.flags;
            out.symbols = full.symbols;
            out.imports = full.imports;
        }
        Err(_) => out.flags |= flags::EXTRACT_FAILED,
    }
    out.tokens = tokens::sorted(counts);
    out
}

struct FullText {
    tokens: HashMap<String, u32>,
    name_tokens: Vec<(String, u32)>,
    flags: u32,
    symbols: Vec<Symbol>,
    imports: Vec<ImportSpec>,
}

fn extract_text(path: &str, text: &str, grammar: Grammar) -> FullText {
    let mut tokens = HashMap::new();
    tokens::tokenize(text, &mut tokens);
    let masked = lex::mask_for(grammar, text);
    let (mut symbols, truncated) = outline::outline(grammar, text, &masked);
    outline::assign_keys(path, &mut symbols);
    let imports = imports::extract_imports(grammar, text, &masked);
    let name_tokens = symbols
        .iter()
        .filter(|symbol| !symbol.name.is_empty())
        .map(|symbol| (symbol.name.to_lowercase(), 1))
        .collect();
    let mut flags = covers::test_flags(path, &masked);
    if truncated {
        flags |= self::flags::TRUNCATED;
    }
    if generated(path, text) {
        flags |= self::flags::GENERATED;
    }
    FullText {
        tokens,
        name_tokens,
        flags,
        symbols,
        imports,
    }
}

fn minified(text: &str) -> bool {
    let mut lines = 0usize;
    let mut longest = 0usize;
    for line in text.split('\n') {
        lines += 1;
        longest = longest.max(line.len());
    }
    longest > MAX_LINE
        || (text.len() >= MINIFIED_MIN_BYTES && text.len() / lines.max(1) > MINIFIED_AVERAGE_LINE)
}

const LOCK_FILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "Gemfile.lock",
    "composer.lock",
    "go.sum",
    "flake.lock",
];

fn lock_file(path: &str) -> bool {
    LOCK_FILES.contains(&path.rsplit('/').next().unwrap_or(path))
}

fn generated(path: &str, text: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let head = char_prefix(text, 1024);
    name.ends_with(".min.js")
        || name.ends_with(".pb.go")
        || name.contains("_generated.")
        || name == "package-lock.json"
        || head.contains("@generated")
        || head.contains("DO NOT EDIT")
}

/// The longest prefix of at most `limit` bytes that ends on a char boundary.
pub fn char_prefix(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}
