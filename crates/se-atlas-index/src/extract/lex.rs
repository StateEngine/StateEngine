//! The shared lexical pass. It returns a copy of the text of identical byte
//! length in which comments and string contents are blanked to spaces, so the
//! delimiter scanner and outline rules never mistake a quoted brace for code.
//! Newlines survive, so offsets and line numbers stay aligned with the source.
use super::Grammar;

/// Lexical features a grammar enables.
mod feature {
    /// Block comments nest.
    pub const NESTED: u8 = 1;
    /// Simple strings may span lines; otherwise a newline ends them.
    pub const MULTILINE: u8 = 1 << 1;
    /// `"""` and `'''` strings.
    pub const TRIPLE: u8 = 1 << 2;
    /// Raw backtick strings that may span lines, with no escapes (Go).
    pub const BACKTICK: u8 = 1 << 3;
    /// Raw strings `r#"..."#`, `br"..."`, `cr"..."` and the
    /// character-literal/lifetime split.
    pub const RUST: u8 = 1 << 4;
    /// Regular-expression literals after an operator.
    pub const REGEX: u8 = 1 << 5;
    /// `#` starts a comment only at line start or after whitespace.
    pub const HASH_AFTER_SPACE: u8 = 1 << 6;
    /// Template literals: escapes, and `${...}` code that may nest strings
    /// and templates of its own.
    pub const TEMPLATE: u8 = 1 << 7;
}

/// Interpolations nested deeper than this blank the rest of the file.
const MAX_TEMPLATE_DEPTH: usize = 32;
use feature::*;

#[derive(Clone, Copy)]
pub(crate) struct LexSpec {
    line: &'static [&'static str],
    block: Option<(&'static str, &'static str)>,
    quotes: &'static [u8],
    features: u8,
}

impl LexSpec {
    fn has(&self, feature: u8) -> bool {
        self.features & feature != 0
    }
}

const C_LIKE: LexSpec = LexSpec {
    line: &["//"],
    block: Some(("/*", "*/")),
    quotes: b"\"'",
    features: TRIPLE,
};

const HASH_LIKE: LexSpec = LexSpec {
    line: &["#"],
    block: None,
    quotes: b"\"'",
    features: HASH_AFTER_SPACE,
};

fn spec_for(grammar: Grammar) -> Option<LexSpec> {
    Some(match grammar {
        Grammar::Rust => LexSpec {
            quotes: b"\"",
            features: NESTED | MULTILINE | RUST,
            ..C_LIKE
        },
        Grammar::TypeScript | Grammar::JavaScript => LexSpec {
            features: TEMPLATE | REGEX,
            ..C_LIKE
        },
        Grammar::Go => LexSpec {
            features: BACKTICK,
            ..C_LIKE
        },
        Grammar::C | Grammar::Cpp | Grammar::Java | Grammar::CSharp | Grammar::Kotlin => C_LIKE,
        Grammar::Zig => LexSpec {
            block: None,
            features: 0,
            ..C_LIKE
        },
        Grammar::Python => LexSpec {
            features: TRIPLE,
            ..HASH_LIKE
        },
        Grammar::Shell => LexSpec {
            features: HASH_AFTER_SPACE | MULTILINE,
            ..HASH_LIKE
        },
        Grammar::Toml => LexSpec {
            features: HASH_AFTER_SPACE | TRIPLE,
            ..HASH_LIKE
        },
        Grammar::Yaml | Grammar::Makefile | Grammar::Dockerfile => HASH_LIKE,
        Grammar::Sql => LexSpec {
            line: &["--"],
            block: Some(("/*", "*/")),
            quotes: b"'\"",
            features: 0,
        },
        Grammar::Json => LexSpec {
            quotes: b"\"",
            features: 0,
            ..C_LIKE
        },
        Grammar::Markdown | Grammar::Text => return None,
    })
}

/// Mask comments and string contents for the grammar; prose formats are
/// returned unchanged.
pub(crate) fn mask_for(grammar: Grammar, text: &str) -> String {
    match spec_for(grammar) {
        Some(spec) => mask(text, &spec),
        None => text.to_owned(),
    }
}

pub(crate) fn mask(text: &str, spec: &LexSpec) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    let mut previous = b'\n';
    while i < bytes.len() {
        if let Some(end) = comment_end(bytes, i, spec) {
            blank(&mut out, i, end);
            i = end;
            continue;
        }
        if let Some((inner, end)) = string_span(bytes, i, spec, previous) {
            blank(&mut out, inner.0, inner.1);
            previous = b'"';
            i = end;
            continue;
        }
        if !bytes[i].is_ascii_whitespace() {
            previous = bytes[i];
        }
        i += 1;
    }
    // Every blanked span starts and ends at ASCII delimiters, so the bytes
    // stay valid UTF-8; the lossy path only guards that invariant.
    String::from_utf8(out)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
}

fn blank(out: &mut [u8], start: usize, end: usize) {
    let end = end.min(out.len());
    for byte in &mut out[start.min(end)..end] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn comment_end(bytes: &[u8], i: usize, spec: &LexSpec) -> Option<usize> {
    let rest = &bytes[i..];
    for marker in spec.line {
        if !rest.starts_with(marker.as_bytes()) {
            continue;
        }
        if spec.has(HASH_AFTER_SPACE)
            && *marker == "#"
            && i > 0
            && !bytes[i - 1].is_ascii_whitespace()
        {
            continue;
        }
        return Some(find_from(bytes, i, b"\n").unwrap_or(bytes.len()));
    }
    let (open, close) = spec.block?;
    if !rest.starts_with(open.as_bytes()) {
        return None;
    }
    Some(block_end(
        bytes,
        i + open.len(),
        open,
        close,
        spec.has(NESTED),
    ))
}

fn block_end(bytes: &[u8], mut i: usize, open: &str, close: &str, nested: bool) -> usize {
    let mut depth = 1;
    while i < bytes.len() {
        if bytes[i..].starts_with(close.as_bytes()) {
            depth -= 1;
            i += close.len();
            if depth == 0 {
                return i;
            }
        } else if nested && bytes[i..].starts_with(open.as_bytes()) {
            depth += 1;
            i += open.len();
        } else {
            i += 1;
        }
    }
    bytes.len()
}

type Span = ((usize, usize), usize);

/// The blanked interior and the resume offset of a string starting at `i`.
fn string_span(bytes: &[u8], i: usize, spec: &LexSpec, previous: u8) -> Option<Span> {
    let b = bytes[i];
    if spec.has(RUST) {
        if let Some(span) = rust_raw(bytes, i) {
            return Some(span);
        }
        if b == b'\'' {
            return rust_char(bytes, i);
        }
    }
    if spec.has(TRIPLE) && spec.quotes.contains(&b) && bytes[i..].starts_with(&[b, b, b]) {
        // The delimiters are blanked too, so a closing quote line never
        // reads as code at column zero.
        let close = find_escaped(bytes, i + 3, &[b, b, b], true).unwrap_or(bytes.len());
        let end = (close + 3).min(bytes.len());
        return Some(((i, end), end));
    }
    if spec.has(TEMPLATE) && b == b'`' {
        let close = template_close(bytes, i + 1, 0).unwrap_or(bytes.len());
        return Some(((i + 1, close), (close + 1).min(bytes.len())));
    }
    if spec.has(BACKTICK) && b == b'`' {
        let close = find_from(bytes, i + 1, b"`").unwrap_or(bytes.len());
        return Some(((i + 1, close), (close + 1).min(bytes.len())));
    }
    if spec.quotes.contains(&b) {
        return Some(quoted(bytes, i, b, spec.has(MULTILINE)));
    }
    if spec.has(REGEX) && b == b'/' && regex_may_start(previous) {
        return regex(bytes, i);
    }
    None
}

fn quoted(bytes: &[u8], i: usize, quote: u8, multiline: bool) -> Span {
    let mut j = i + 1;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => j += 2,
            b'\n' if !multiline => return ((i + 1, j), j),
            c if c == quote => return ((i + 1, j), j + 1),
            _ => j += 1,
        }
    }
    ((i + 1, bytes.len()), bytes.len())
}

/// Offset of the backtick closing a template whose body starts at `j`.
fn template_close(bytes: &[u8], mut j: usize, depth: usize) -> Option<usize> {
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => j += 2,
            b'`' => return Some(j),
            b'$' if bytes.get(j + 1) == Some(&b'{') => {
                j = interpolation_end(bytes, j + 2, depth)?;
            }
            _ => j += 1,
        }
    }
    None
}

/// Offset just past the `}` that closes an interpolation starting at `j`.
fn interpolation_end(bytes: &[u8], mut j: usize, depth: usize) -> Option<usize> {
    if depth >= MAX_TEMPLATE_DEPTH {
        return None;
    }
    let mut braces = 0usize;
    while j < bytes.len() {
        match bytes[j] {
            b'{' => braces += 1,
            b'}' if braces == 0 => return Some(j + 1),
            b'}' => braces -= 1,
            b'`' => {
                j = template_close(bytes, j + 1, depth + 1)? + 1;
                continue;
            }
            quote @ (b'"' | b'\'') => {
                j = quoted(bytes, j, quote, false).1;
                continue;
            }
            _ => {}
        }
        j += 1;
    }
    None
}

fn find_escaped(bytes: &[u8], mut i: usize, needle: &[u8], escapes: bool) -> Option<usize> {
    while i < bytes.len() {
        if escapes && bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i..].starts_with(needle) {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_from(bytes: &[u8], i: usize, needle: &[u8]) -> Option<usize> {
    find_escaped(bytes, i, needle, false)
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `r"..."`, `r#"..."#`, `br"..."` and `cr"..."`, with no escapes inside.
fn rust_raw(bytes: &[u8], i: usize) -> Option<Span> {
    if bytes[i] != b'r' {
        return None;
    }
    let before = i.checked_sub(1).map(|p| bytes[p]);
    let prefix_ok = match before {
        None => true,
        Some(b'b' | b'c') => i < 2 || !is_ident(bytes[i - 2]),
        Some(c) => !is_ident(c),
    };
    if !prefix_ok {
        return None;
    }
    let hashes = bytes[i + 1..].iter().take_while(|b| **b == b'#').count();
    let open = i + 1 + hashes;
    if bytes.get(open) != Some(&b'"') {
        return None;
    }
    let mut close = vec![b'"'];
    close.extend(std::iter::repeat_n(b'#', hashes));
    let end = find_from(bytes, open + 1, &close).unwrap_or(bytes.len());
    Some(((open + 1, end), (end + close.len()).min(bytes.len())))
}

/// A character literal such as `'a'`, `'\n'` or `'\u{1F600}'`; a lifetime
/// such as `'a` is code and is left alone.
fn rust_char(bytes: &[u8], i: usize) -> Option<Span> {
    let next = *bytes.get(i + 1)?;
    if next == b'\\' {
        // The escaped character itself may be a quote, as in `'\''`.
        let close = bytes
            .get(i + 3..)?
            .iter()
            .take(12)
            .position(|b| *b == b'\'')?;
        let end = i + 3 + close;
        return Some(((i + 1, end), end + 1));
    }
    let width = match next {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    };
    (bytes.get(i + 1 + width) == Some(&b'\'')).then_some(((i + 1, i + 1 + width), i + 2 + width))
}

fn regex_may_start(previous: u8) -> bool {
    b"(,=:[!&|?{};+-*%<>~^\n".contains(&previous)
}

fn regex(bytes: &[u8], i: usize) -> Option<Span> {
    let next = *bytes.get(i + 1)?;
    if next == b'/' || next == b'*' {
        return None;
    }
    let mut j = i + 1;
    let mut class = false;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => j += 2,
            b'\n' => return None,
            b'[' => {
                class = true;
                j += 1;
            }
            b']' => {
                class = false;
                j += 1;
            }
            b'/' if !class => return Some(((i + 1, j), j + 1)),
            _ => j += 1,
        }
    }
    None
}
