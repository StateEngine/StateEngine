//! Outline building: symbol records, the delimiter-depth scanner shared by
//! every brace language, and the per-grammar dispatch.
//!
//! The scanner walks masked text tracking brace and paren depth. The text
//! since the last statement boundary is the header; at `{` the grammar names
//! the block (or leaves it anonymous), at `;` (and, for newline-terminated
//! languages, at a completed line) it may name a bodyless declaration.
//! Headers are capped at 32 lines and 4 KiB.
use super::{Grammar, MAX_SYMBOLS, c_family, go, js_ts, markup, python, rust};
use std::collections::HashMap;

/// What a symbol declares; stored as `sym.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    Module = 1,
    Function = 2,
    Method = 3,
    Struct = 4,
    Enum = 5,
    Interface = 6,
    Impl = 7,
    Class = 8,
    Type = 9,
    Const = 10,
    Variable = 11,
    Macro = 12,
    Namespace = 13,
    Section = 14,
    Table = 15,
    Key = 16,
    Item = 17,
    Target = 18,
    Stage = 19,
    Test = 20,
}

impl SymbolKind {
    pub fn code(self) -> i64 {
        self as i64
    }

    /// The kind stored as `code`, if this version knows it.
    pub fn from_code(code: i64) -> Option<Self> {
        const ALL: [SymbolKind; 20] = [
            SymbolKind::Module,
            SymbolKind::Function,
            SymbolKind::Method,
            SymbolKind::Struct,
            SymbolKind::Enum,
            SymbolKind::Interface,
            SymbolKind::Impl,
            SymbolKind::Class,
            SymbolKind::Type,
            SymbolKind::Const,
            SymbolKind::Variable,
            SymbolKind::Macro,
            SymbolKind::Namespace,
            SymbolKind::Section,
            SymbolKind::Table,
            SymbolKind::Key,
            SymbolKind::Item,
            SymbolKind::Target,
            SymbolKind::Stage,
            SymbolKind::Test,
        ];
        ALL.into_iter().find(|kind| kind.code() == code)
    }

    /// The lowercase name shown to users.
    pub fn name(self) -> &'static str {
        match self {
            Self::Module => "module",
            Self::Function => "function",
            Self::Method => "method",
            Self::Struct => "struct",
            Self::Enum => "enum",
            Self::Interface => "interface",
            Self::Impl => "impl",
            Self::Class => "class",
            Self::Type => "type",
            Self::Const => "const",
            Self::Variable => "variable",
            Self::Macro => "macro",
            Self::Namespace => "namespace",
            Self::Section => "section",
            Self::Table => "table",
            Self::Key => "key",
            Self::Item => "item",
            Self::Target => "target",
            Self::Stage => "stage",
            Self::Test => "test",
        }
    }

    fn holds_methods(self) -> bool {
        matches!(
            self,
            Self::Class | Self::Struct | Self::Interface | Self::Impl | Self::Enum
        )
    }
}

/// How far an outline can be trusted; stored as `sym.accuracy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accuracy {
    /// Keyword-led recognition of code; macros and metaprogramming are missed.
    Heuristic = 1,
    /// Exact for the format's own structure (headings, tables, keys).
    Syntactic = 2,
}

/// One outline entry.
#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    /// 1-based first and last line.
    pub line: u32,
    pub end_line: u32,
    /// Index of the enclosing symbol in the same file's list.
    pub parent: Option<usize>,
    pub exported: bool,
    /// The declaration header, whitespace-collapsed, at most 120 bytes.
    pub sig: String,
    pub sig_hash: i64,
    pub body_hash: i64,
    /// Stable identity: path, enclosing chain, kind, name and ordinal.
    pub key: [u8; 32],
}

/// A grammar's verdict on one header.
pub(crate) struct Decl {
    pub name: String,
    pub kind: SymbolKind,
    pub exported: bool,
    /// Owning type named outside the block, such as a Go method receiver.
    pub owner: Option<String>,
}

impl Decl {
    pub fn new(name: &str, kind: SymbolKind, exported: bool) -> Option<Self> {
        (!name.is_empty()).then(|| Self {
            name: name.to_owned(),
            kind,
            exported,
            owner: None,
        })
    }
}

/// Where a header sits.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Scope {
    /// Kind of the immediately enclosing named block, if any.
    pub parent: Option<SymbolKind>,
    /// No block of any kind encloses the header.
    pub top_level: bool,
    /// The header ended at a statement boundary rather than at `{`.
    pub statement: bool,
}

impl Scope {
    pub fn in_type(&self) -> bool {
        self.parent.is_some_and(SymbolKind::holds_methods)
    }
}

pub(crate) type Classify = fn(&str, &str, Scope) -> Option<Decl>;

pub(crate) fn accuracy_of(grammar: Grammar) -> Accuracy {
    match grammar {
        Grammar::Markdown
        | Grammar::Toml
        | Grammar::Yaml
        | Grammar::Json
        | Grammar::Sql
        | Grammar::Makefile
        | Grammar::Dockerfile
        | Grammar::Shell => Accuracy::Syntactic,
        _ => Accuracy::Heuristic,
    }
}

/// Outline one file; the flag reports the symbol cap was reached.
pub(crate) fn outline(grammar: Grammar, text: &str, masked: &str) -> (Vec<Symbol>, bool) {
    let mut builder = Builder::new(text, masked);
    let brace = |classify: Classify, newline_ends: bool| (classify, newline_ends);
    let rules = match grammar {
        Grammar::Rust => Some(brace(rust::classify, false)),
        Grammar::TypeScript | Grammar::JavaScript => Some(brace(js_ts::classify, true)),
        Grammar::Go => Some(brace(go::classify, true)),
        Grammar::C | Grammar::Cpp => Some(brace(c_family::classify_c, false)),
        Grammar::Java | Grammar::CSharp => Some(brace(c_family::classify_managed, false)),
        Grammar::Kotlin => Some(brace(c_family::classify_kotlin, true)),
        Grammar::Zig => Some(brace(c_family::classify_zig, false)),
        Grammar::Shell => Some(brace(markup::classify_shell, true)),
        _ => None,
    };
    match (rules, grammar) {
        (Some((classify, newline_ends)), _) => {
            let mut scan = BraceScan::new(text, masked, classify, newline_ends, &mut builder);
            scan.preprocessor = matches!(grammar, Grammar::C | Grammar::Cpp | Grammar::CSharp);
            scan.run();
        }
        (None, Grammar::Python) => python::outline(text, masked, &mut builder),
        (None, _) => markup::outline(grammar, text, masked, &mut builder),
    }
    builder.link_owners();
    (builder.symbols, builder.truncated)
}

/// Line lookup over byte offsets.
pub(crate) struct Lines {
    starts: Vec<usize>,
}

impl Lines {
    pub fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
        Self { starts }
    }

    /// 1-based line of a byte offset.
    pub fn line_of(&self, offset: usize) -> u32 {
        let index = self.starts.partition_point(|start| *start <= offset);
        u32::try_from(index.max(1)).unwrap_or(u32::MAX)
    }
}

/// Accumulates symbols with hashes, parents and the per-file cap.
pub(crate) struct Builder<'t> {
    raw: &'t str,
    masked: &'t str,
    pub lines: Lines,
    pub symbols: Vec<Symbol>,
    owners: Vec<(usize, String)>,
    pub truncated: bool,
}

impl<'t> Builder<'t> {
    pub fn new(raw: &'t str, masked: &'t str) -> Self {
        Self {
            raw,
            masked,
            lines: Lines::new(masked),
            symbols: Vec::new(),
            owners: Vec::new(),
            truncated: false,
        }
    }

    /// Record a declaration whose header spans `header` and whose name sits at
    /// or after `start`. Returns its index, or `None` once the cap is reached.
    pub fn open(
        &mut self,
        decl: Decl,
        header: (usize, usize),
        parent: Option<usize>,
    ) -> Option<usize> {
        if self.symbols.len() >= MAX_SYMBOLS {
            self.truncated = true;
            return None;
        }
        let name_at = find_word(
            self.masked.get(header.0..header.1).unwrap_or(""),
            &decl.name,
        )
        .map_or(header.0, |at| header.0 + at);
        let line = self.lines.line_of(name_at);
        let collapsed = collapse(self.raw.get(header.0..header.1).unwrap_or(""));
        let index = self.symbols.len();
        if let Some(owner) = decl.owner {
            self.owners.push((index, owner));
        }
        self.symbols.push(Symbol {
            name: decl.name,
            kind: decl.kind,
            line,
            end_line: line,
            parent,
            exported: decl.exported,
            sig: super::char_prefix(display_signature(&collapsed), 120).to_owned(),
            sig_hash: hash64(collapsed.as_bytes()),
            body_hash: 0,
            key: [0; 32],
        });
        Some(index)
    }

    /// Close a symbol whose full text spans `body`.
    pub fn close(&mut self, index: usize, body: (usize, usize)) {
        let end = body.1.min(self.raw.len());
        let start = body.0.min(end);
        let end_line = self.lines.line_of(end.saturating_sub(1).max(start));
        let body_hash = hash64(collapse(self.raw.get(start..end).unwrap_or("")).as_bytes());
        if let Some(symbol) = self.symbols.get_mut(index) {
            symbol.end_line = end_line.max(symbol.line);
            symbol.body_hash = body_hash;
        }
    }

    /// Attach receiver-declared methods to their type when it is in this file.
    fn link_owners(&mut self) {
        for (index, owner) in std::mem::take(&mut self.owners) {
            let found = self.symbols.iter().position(|symbol| {
                symbol.parent.is_none()
                    && symbol.name == owner
                    && matches!(
                        symbol.kind,
                        SymbolKind::Struct | SymbolKind::Type | SymbolKind::Interface
                    )
            });
            if let (Some(found), Some(symbol)) = (found, self.symbols.get_mut(index))
                && symbol.parent.is_none()
                && found != index
            {
                symbol.parent = Some(found);
            }
        }
    }
}

/// Fill every symbol's stable key. A key hashes its parent's key, so parents
/// are keyed first even when declared later (a Go method may precede its
/// receiver type); ordinals count same-named siblings in declaration order.
pub(crate) fn assign_keys(path: &str, symbols: &mut [Symbol]) {
    let mut counts: HashMap<(Option<usize>, SymbolKind, &str), u32> = HashMap::new();
    let ordinals: Vec<u32> = symbols
        .iter()
        .map(|symbol| {
            let count = counts
                .entry((symbol.parent, symbol.kind, symbol.name.as_str()))
                .or_insert(0);
            *count += 1;
            *count - 1
        })
        .collect();
    let mut keyed = vec![false; symbols.len()];
    for index in parents_first(symbols) {
        let symbol = &symbols[index];
        let mut hasher = blake3::Hasher::new();
        match symbol
            .parent
            .filter(|parent| keyed.get(*parent) == Some(&true))
        {
            Some(parent) => hasher.update(&symbols[parent].key),
            None => hasher.update(path.as_bytes()),
        };
        hasher.update(&[0, symbol.kind as u8]);
        hasher.update(symbol.name.as_bytes());
        hasher.update(&ordinals[index].to_le_bytes());
        symbols[index].key = *hasher.finalize().as_bytes();
        keyed[index] = true;
    }
}

/// Symbol indexes ordered so every parent precedes its children. A parent
/// chain that loops or leaves the list is cut where it does.
pub(crate) fn parents_first(symbols: &[Symbol]) -> Vec<usize> {
    const NEW: u8 = 0;
    const OPEN: u8 = 1;
    const PLACED: u8 = 2;
    let mut state = vec![NEW; symbols.len()];
    let mut order = Vec::with_capacity(symbols.len());
    let mut chain = Vec::new();
    for start in 0..symbols.len() {
        let mut at = Some(start);
        while let Some(index) = at.filter(|index| state.get(*index) == Some(&NEW)) {
            state[index] = OPEN;
            chain.push(index);
            at = symbols[index].parent;
        }
        while let Some(index) = chain.pop() {
            state[index] = PLACED;
            order.push(index);
        }
    }
    order
}

/// First 8 bytes of BLAKE3, as SQLite's signed integer.
pub(crate) fn hash64(bytes: &[u8]) -> i64 {
    let digest = blake3::hash(bytes);
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest.as_bytes()[..8]);
    i64::from_le_bytes(head)
}

/// The header without leading attributes, annotations or decorators, which
/// still count toward `sig_hash`.
fn display_signature(collapsed: &str) -> &str {
    let mut text = collapsed;
    loop {
        let rest = if let Some(rest) = text.strip_prefix("#!").or_else(|| text.strip_prefix('#')) {
            if !rest.starts_with('[') {
                return text;
            }
            skip_group(rest, b'[', b']')
        } else if text.starts_with('[') {
            skip_group(text, b'[', b']')
        } else if let Some(rest) = ["public:", "private:", "protected:"]
            .iter()
            .find_map(|label| text.strip_prefix(label))
        {
            rest
        } else if let Some(rest) = text.strip_prefix('@') {
            let after =
                rest.trim_start_matches(|c: char| c.is_alphanumeric() || c == '_' || c == '.');
            if after.starts_with('(') {
                skip_group(after, b'(', b')')
            } else {
                after
            }
        } else {
            return text;
        };
        let rest = rest.trim_start();
        if rest.is_empty() {
            return text;
        }
        text = rest;
    }
}

/// Trim and collapse every whitespace run to one space.
pub(crate) fn collapse(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(4096));
    for word in text.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out
}

/// Byte offset of `word` as a whole identifier inside `text`.
pub fn find_word(text: &str, word: &str) -> Option<usize> {
    if word.is_empty() {
        return None;
    }
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';
    let bytes = text.as_bytes();
    text.match_indices(word).map(|(at, _)| at).find(|at| {
        let before = at.checked_sub(1).map(|p| bytes[p]);
        let after = bytes.get(at + word.len()).copied();
        !before.is_some_and(ident) && !after.is_some_and(ident)
    })
}

struct Frame {
    symbol: Option<usize>,
    kind: Option<SymbolKind>,
    saved_paren: u32,
    start: usize,
    /// The header in progress when a block opens inside parentheses, such
    /// as a `= {}` default parameter or a callback body. It resumes when the
    /// block closes, so the enclosing declaration keeps its name.
    outer: Option<usize>,
}

const MAX_HEADER_BYTES: usize = 4096;
const MAX_HEADER_LINES: u32 = 32;

/// The delimiter-depth scanner for brace languages.
struct BraceScan<'a, 'b> {
    text: &'a str,
    masked: &'a str,
    classify: Classify,
    newline_ends: bool,
    /// Lines starting with `#` are directives, never part of a header.
    preprocessor: bool,
    builder: &'b mut Builder<'a>,
    stack: Vec<Frame>,
    header_start: usize,
    header_lines: u32,
    paren: u32,
}

impl<'a, 'b> BraceScan<'a, 'b> {
    fn new(
        text: &'a str,
        masked: &'a str,
        classify: Classify,
        newline_ends: bool,
        builder: &'b mut Builder<'a>,
    ) -> Self {
        Self {
            text,
            masked,
            classify,
            newline_ends,
            preprocessor: false,
            builder,
            stack: Vec::new(),
            header_start: 0,
            header_lines: 0,
            paren: 0,
        }
    }

    fn run(mut self) {
        let bytes = self.masked.as_bytes();
        for (i, byte) in bytes.iter().enumerate() {
            match byte {
                b'(' | b'[' => self.paren += 1,
                b')' | b']' => self.paren = self.paren.saturating_sub(1),
                b'{' => self.open_block(i),
                b'}' => self.close_block(i),
                b';' if self.paren == 0 => self.statement(i),
                b'\n' => self.newline(i),
                _ => {}
            }
        }
        while let Some(frame) = self.stack.pop() {
            if let Some(index) = frame.symbol {
                self.builder.close(index, (frame.start, bytes.len()));
            }
        }
    }

    /// The trimmed header ending at `end`, as a byte range.
    fn header(&self, end: usize) -> (usize, usize) {
        let slice = &self.masked[self.header_start..end];
        let start = self.header_start + (slice.len() - slice.trim_start().len());
        (start, start.max(self.header_start + slice.trim_end().len()))
    }

    fn scope(&self, statement: bool) -> Scope {
        Scope {
            parent: self.stack.last().and_then(|frame| frame.kind),
            top_level: self.stack.is_empty(),
            statement,
        }
    }

    fn enclosing_symbol(&self) -> Option<usize> {
        self.stack.iter().rev().find_map(|frame| frame.symbol)
    }

    fn classify_header(&mut self, range: (usize, usize), statement: bool) -> Option<usize> {
        if range.0 >= range.1 {
            return None;
        }
        let masked = self.masked.get(range.0..range.1).unwrap_or("");
        let raw = self.text.get(range.0..range.1).unwrap_or("");
        let decl = (self.classify)(masked, raw, self.scope(statement))?;
        let parent = self.enclosing_symbol();
        self.builder.open(decl, range, parent)
    }

    fn open_block(&mut self, i: usize) {
        let range = self.header(i);
        let symbol = if self.paren == 0 {
            self.classify_header(range, false)
        } else {
            None
        };
        let kind = symbol.and_then(|index| self.builder.symbols.get(index).map(|s| s.kind));
        let outer = (self.paren > 0).then_some(self.header_start);
        self.stack.push(Frame {
            symbol,
            kind,
            saved_paren: self.paren,
            start: range.0,
            outer,
        });
        self.reset(i + 1);
    }

    fn close_block(&mut self, i: usize) {
        let Some(frame) = self.stack.pop() else {
            self.reset(i + 1);
            return;
        };
        if let Some(index) = frame.symbol {
            self.builder.close(index, (frame.start, i + 1));
        }
        self.paren = frame.saved_paren;
        // A resumed header still honours both header caps.
        let resumed = frame
            .outer
            .filter(|start| i + 1 - start <= MAX_HEADER_BYTES)
            .and_then(|start| {
                let lines = self.masked[start..=i].bytes().filter(|b| *b == b'\n');
                Some((start, u32::try_from(lines.count()).ok()?))
            })
            .filter(|(_, lines)| *lines <= MAX_HEADER_LINES);
        match resumed {
            Some((start, lines)) => {
                self.header_start = start;
                self.header_lines = lines;
            }
            None => self.reset(i + 1),
        }
    }

    fn statement(&mut self, i: usize) {
        let range = self.header(i);
        if let Some(index) = self.classify_header(range, true) {
            self.builder.close(index, (range.0, i + 1));
        }
        self.reset(i + 1);
    }

    fn newline(&mut self, i: usize) {
        self.header_lines += 1;
        let header = self.masked[self.header_start..i].trim();
        let directive = header.starts_with('#') && !header.ends_with('\\');
        if self.preprocessor && self.paren == 0 && directive {
            self.reset(i + 1);
            return;
        }
        if self.newline_ends && self.paren == 0 && !self.continues(i) {
            self.statement(i);
            return;
        }
        if self.header_lines > MAX_HEADER_LINES || i - self.header_start > MAX_HEADER_BYTES {
            self.reset(i + 1);
        }
    }

    /// Whether a newline-terminated statement continues on the next line.
    fn continues(&self, i: usize) -> bool {
        let header = self.masked[self.header_start..i].trim_end();
        let Some(last) = header.bytes().last() else {
            return false;
        };
        let next = self.masked[i..]
            .bytes()
            .find(|b| !b.is_ascii_whitespace())
            .unwrap_or(b';');
        b",([{=+-*/%|&.<>:?!^~\\".contains(&last) || b"{.)]?:=,|&".contains(&next)
    }

    fn reset(&mut self, at: usize) {
        self.header_start = at;
        self.header_lines = 0;
    }
}

/// The leading identifier of `text` (letters, digits, `_`, `$`).
pub(crate) fn ident(text: &str) -> &str {
    let end = text
        .char_indices()
        .find(|(_, c)| !(c.is_alphanumeric() || *c == '_' || *c == '$'))
        .map_or(text.len(), |(at, _)| at);
    &text[..end]
}

/// `text` after a leading keyword, only when the keyword ends at an
/// identifier boundary (`fun` but not `function`, `enum` but not
/// `enumerable`).
pub(crate) fn keyword<'t>(text: &'t str, word: &str) -> Option<&'t str> {
    let rest = text.strip_prefix(word)?;
    let continues = rest
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '$');
    (!continues).then_some(rest)
}

/// Strip a leading balanced group such as `#[...]`, `@Name(...)` or `[Attr]`
/// starting at `open`; returns the rest after it.
pub(crate) fn skip_group(text: &str, open: u8, close: u8) -> &str {
    let bytes = text.as_bytes();
    if bytes.first() != Some(&open) {
        return text;
    }
    let mut depth = 0u32;
    for (i, b) in bytes.iter().enumerate() {
        if *b == open {
            depth += 1;
        } else if *b == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return &text[i + 1..];
            }
        }
    }
    ""
}

/// Text before the first top-level `(`, if any.
pub(crate) fn before_paren(text: &str) -> Option<&str> {
    let mut angle = 0i32;
    for (i, b) in text.bytes().enumerate() {
        match b {
            b'<' => angle += 1,
            b'>' => angle -= 1,
            b'(' if angle <= 0 => return Some(&text[..i]),
            _ => {}
        }
    }
    None
}
