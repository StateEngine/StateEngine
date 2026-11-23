//! The declared spelling of a symbol name. Names are indexed lowercase; the
//! signature still shows the name as written, so its spelling is read back
//! from the identifier at the declaration site.
use super::outline::find_word;

/// Lowercase words that may follow a declared name: `class A extends B`,
/// `type A struct`, `impl A for B`.
const FOLLOWERS: &[&str] = &[
    "extends",
    "implements",
    "for",
    "where",
    "with",
    "struct",
    "interface",
    "as",
];

/// The spelling of `lower` as declared in `sig`: the first identifier equal
/// to it, ignoring ASCII case, that stands outside brackets and does not
/// lead another identifier. Keywords, modifiers, Go receivers and return
/// types are skipped that way: `type` in `pub type Type`, `Store` in
/// `func (s *Store) store()`, `Widget` in `Widget widget()`. Otherwise the
/// first whole-word occurrence anywhere, then `lower` itself.
pub fn display_name(sig: Option<&str>, lower: &str) -> String {
    let Some(sig) = sig else {
        return lower.to_owned();
    };
    let folded = sig.to_ascii_lowercase();
    let simple = !lower.is_empty() && lower.bytes().all(ident_byte);
    let at = simple
        .then(|| declared_at(sig, &folded, lower))
        .flatten()
        .or_else(|| find_word(&folded, lower));
    at.and_then(|at| sig.get(at..at + lower.len()))
        .map_or_else(|| lower.to_owned(), str::to_owned)
}

fn ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80
}

fn declared_at(sig: &str, folded: &str, lower: &str) -> Option<usize> {
    let bytes = folded.as_bytes();
    let (mut depth, mut angle, mut at) = (0u32, 0u32, 0usize);
    while at < bytes.len() {
        let b = bytes[at];
        if ident_byte(b) {
            let end = word_end(bytes, at);
            if depth + angle == 0 && &folded[at..end] == lower && !leads(sig, end) {
                return Some(at);
            }
            at = end;
            continue;
        }
        let after_ident = at > 0 && ident_byte(bytes[at - 1]);
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b'<' if after_ident => angle += 1,
            b'>' if angle > 0 && !matches!(bytes[at - 1], b'-' | b'=') => angle -= 1,
            _ => {}
        }
        at += 1;
    }
    None
}

fn word_end(bytes: &[u8], from: usize) -> usize {
    bytes[from..]
        .iter()
        .position(|b| !ident_byte(*b))
        .map_or(bytes.len(), |n| from + n)
}

/// Whether the identifier ending at `end` leads another one, past pointer
/// marks, generic or array brackets, or an adjacent `::`/`.` qualifier.
fn leads(sig: &str, end: usize) -> bool {
    let bytes = sig.as_bytes();
    if matches!(sig.get(end..end + 2), Some("::")) || bytes.get(end) == Some(&b'.') {
        return bytes
            .get(end + 1 + usize::from(bytes[end] == b':'))
            .is_some_and(|b| ident_byte(*b));
    }
    let mut at = end;
    loop {
        match bytes.get(at) {
            Some(b' ' | b'\t' | b'*' | b'&' | b'?' | b'!') => at += 1,
            Some(b'<') => at = close_of(bytes, at, b'<', b'>'),
            Some(b'[') => at = close_of(bytes, at, b'[', b']'),
            Some(b) if ident_byte(*b) => {
                let word = &sig[at..word_end(bytes, at)];
                return !FOLLOWERS.contains(&word);
            }
            _ => return false,
        }
    }
}

/// The index past the bracket that closes the one opening at `open`.
fn close_of(bytes: &[u8], open: usize, left: u8, right: u8) -> usize {
    let mut depth = 0u32;
    for (at, b) in bytes.iter().enumerate().skip(open) {
        if *b == left {
            depth += 1;
        } else if *b == right {
            depth -= 1;
            if depth == 0 {
                return at + 1;
            }
        }
    }
    bytes.len()
}
