//! Dual tokenization. Whole tokens keep internal name punctuation
//! (`app-server`, `crate::cache::connection`, `0xc0000142`, `1.2.3`) so
//! punctuated searches hit the index; their identifier parts (split on `_`,
//! `-`, `.`, `::`, camelCase and digit transitions) are indexed beside them
//! for partial and typo matches.
use std::collections::HashMap;

/// Longer whole tokens (hashes, base64) are not indexed.
pub const MAX_TOKEN_BYTES: usize = 128;
/// Identifier tokens up to this length enter the trigram index.
pub const MAX_GRAM_TOKEN: usize = 48;
/// Tokens up to this length are listed in `short` instead of `gram`.
pub const MAX_SHORT_TOKEN: usize = 2;

/// Add every token of `text` with its count to `counts`.
pub fn tokenize(text: &str, counts: &mut HashMap<String, u32>) {
    let mut i = 0;
    while i < text.len() {
        let Some(width) = word_width(text, i) else {
            i += text[i..].chars().next().map_or(1, char::len_utf8);
            continue;
        };
        let end = token_end(text, i + width);
        add_token(&text[i..end], counts);
        i = end;
    }
}

/// Sorted `(token, tf)` pairs.
pub fn sorted(counts: HashMap<String, u32>) -> Vec<(String, u32)> {
    let mut tokens: Vec<_> = counts.into_iter().collect();
    tokens.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    tokens
}

/// The separator-stripped form used for near-miss lookup.
pub fn compact(token: &str) -> String {
    token
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | '.' | ':'))
        .collect()
}

/// Whether a token belongs in the trigram index.
/// Digit-only tokens are left out: a typo match on a number is noise.
pub fn is_gram_token(token: &str) -> bool {
    (3..=MAX_GRAM_TOKEN).contains(&token.len())
        && token.bytes().any(|b| b.is_ascii_lowercase())
        && token
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The trigram ids of a gram token: three bytes packed big-endian.
pub fn trigrams(token: &str) -> impl Iterator<Item = u32> + '_ {
    token
        .as_bytes()
        .windows(3)
        .map(|w| (u32::from(w[0]) << 16) | (u32::from(w[1]) << 8) | u32::from(w[2]))
}

/// Identifier parts of a whole token, split on punctuation, camelCase and
/// letter/digit transitions. Slices of the original spelling.
pub fn split_parts(token: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    for piece in token.split(|c: char| !c.is_alphanumeric()) {
        let mut start = 0;
        let chars: Vec<(usize, char)> = piece.char_indices().collect();
        for k in 1..chars.len() {
            if boundary(chars[k - 1].1, chars[k].1, chars.get(k + 1).map(|c| c.1)) {
                parts.push(&piece[start..chars[k].0]);
                start = chars[k].0;
            }
        }
        if start < piece.len() {
            parts.push(&piece[start..]);
        }
    }
    parts
}

/// Whether an identifier splits between `previous` and `current`.
pub fn boundary(previous: char, current: char, next: Option<char>) -> bool {
    let camel = previous.is_lowercase() && current.is_uppercase();
    let acronym_end =
        previous.is_uppercase() && current.is_uppercase() && next.is_some_and(char::is_lowercase);
    let digit = previous.is_ascii_digit() != current.is_ascii_digit();
    camel || acronym_end || digit
}

/// Count a token and its identifier parts. A whole token over the byte cap
/// is not stored, but its parts that fit still are, so a long joined name
/// stays findable by its pieces.
fn add_token(raw: &str, counts: &mut HashMap<String, u32>) {
    let whole = (raw.len() <= MAX_TOKEN_BYTES).then(|| raw.to_lowercase());
    // A long hex run is a hash or id: its digit/letter splits are noise.
    let hex = raw.len() >= 16 && raw.bytes().all(|b| b.is_ascii_hexdigit());
    for part in split_parts(raw).into_iter().filter(|_| !hex) {
        if part.len() > MAX_TOKEN_BYTES {
            continue;
        }
        let part = part.to_lowercase();
        if whole.as_ref() != Some(&part) {
            bump(counts, part);
        }
    }
    if let Some(whole) = whole {
        bump(counts, whole);
    }
}

fn bump(counts: &mut HashMap<String, u32>, token: String) {
    let tf = counts.entry(token).or_insert(0);
    *tf = tf.saturating_add(1);
}

fn word_width(text: &str, i: usize) -> Option<usize> {
    let b = text.as_bytes()[i];
    if b.is_ascii() {
        return (b.is_ascii_alphanumeric() || b == b'_').then_some(1);
    }
    let c = text[i..].chars().next()?;
    c.is_alphanumeric().then(|| c.len_utf8())
}

/// Extend a token over word characters and over the joiners that keep a
/// name whole: a single `-` (`app-server`), `::` (`crate::cache`), and `.`
/// between digits (`1.2.3`). Dotted member chains such as `self.conn.run`
/// stay separate tokens; phrase search confirms them from their parts.
fn token_end(text: &str, mut i: usize) -> usize {
    let bytes = text.as_bytes();
    loop {
        if let Some(width) = (i < text.len()).then(|| word_width(text, i)).flatten() {
            i += width;
            continue;
        }
        let rest = &bytes[i.min(bytes.len())..];
        let dash = rest.starts_with(b"-") && rest.get(1) != Some(&b'-');
        let decimal = rest.starts_with(b".")
            && i > 0
            && bytes[i - 1].is_ascii_digit()
            && rest.get(1).is_some_and(u8::is_ascii_digit);
        let joiner = if rest.starts_with(b"::") {
            2
        } else {
            usize::from(dash || decimal)
        };
        if joiner > 0 && i + joiner < text.len() && word_width(text, i + joiner).is_some() {
            i += joiner;
            continue;
        }
        return i;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(text: &str) -> HashMap<String, u32> {
        let mut counts = HashMap::new();
        tokenize(text, &mut counts);
        counts
    }

    #[test]
    fn whole_tokens_keep_internal_punctuation_and_parts_split() {
        let counts = tokens(
            "use crate::cache::connection; 0xC0000142 app-server QueryReader. self.conn v1.2.3",
        );
        for token in [
            "crate::cache::connection",
            "connection",
            "0xc0000142",
            "app-server",
            "server",
            "queryreader",
            "query",
            "reader",
        ] {
            assert!(counts.contains_key(token), "missing {token}");
        }
        assert!(!counts.contains_key("queryreader."));
        assert!(!counts.contains_key("self.conn") && counts.contains_key("conn"));
        assert!(counts.contains_key("v1.2.3"));
        assert_eq!(split_parts("HTTPServer2go"), ["HTTP", "Server", "2", "go"]);
        assert_eq!(compact("app-server_x"), "appserverx");
        assert!(is_gram_token("query_reader") && !is_gram_token("app-server"));
    }
}
