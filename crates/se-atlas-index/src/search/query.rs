//! Query parsing: plain words, punctuated literals, quoted phrases, and the
//! literal anchors of a regex.
//!
//! A plain word (letters, digits and `_`) is looked up as a term, with typo
//! tolerance. Anything punctuated (`self.conn.run`, `0x1f-ab`, `a::b`) or
//! quoted is a literal: the index narrows the files by the literal's
//! identifier parts, then each candidate line must contain it. A literal is
//! never split into OR'd fragments.
use super::QueryMode;
use crate::{IndexError, Result, extract::tokens};
use regex_syntax::hir::{Hir, HirKind};

/// One plain word.
#[derive(Debug)]
pub(crate) struct Word {
    /// Lowercase spelling.
    pub text: String,
    /// Lowercase identifier parts when the word has more than one
    /// (`QueryReader` gives `query`, `reader`).
    pub parts: Vec<String>,
}

/// A punctuated word or quoted phrase, matched as a case-insensitive
/// substring that starts and ends where the tokenizer would split.
#[derive(Debug)]
pub(crate) struct Literal {
    /// Lowercase, whitespace runs collapsed to one space.
    pub text: String,
    /// Alternative token sets; a file holding the literal indexes every
    /// token of at least one set. The sets differ because the tokenizer's
    /// splits depend on case and joiners the query may not share: the
    /// literal's identifier parts as written (`QueryReader.run` gives
    /// `query`, `reader`, `run`), its whole words (`queryreader`, `run`),
    /// and the literal itself when it is one joined token
    /// (`queryreader::new`). Empty for pure operators such as `->`.
    ///
    /// Not covered: a literal edge that continues a 16-digit hex run in the
    /// text, whose parts the tokenizer never indexes.
    pub anchor_sets: Vec<Vec<String>>,
}

#[derive(Debug)]
pub(crate) enum Parsed {
    Text {
        words: Vec<Word>,
        literals: Vec<Literal>,
    },
    Regex {
        pattern: String,
        /// Lowercase identifier pieces some indexed token must contain in
        /// every file the expression matches.
        pieces: Vec<String>,
    },
}

impl Parsed {
    /// Whether the index can narrow this query at all.
    pub fn indexable(&self) -> bool {
        match self {
            Self::Text { words, literals } => {
                !words.is_empty() || literals.iter().any(|lit| !lit.anchor_sets.is_empty())
            }
            Self::Regex { pieces, .. } => !pieces.is_empty(),
        }
    }
}

pub(crate) fn parse(query: &str, mode: QueryMode) -> Result<Parsed> {
    if query.trim().is_empty() {
        return Err(IndexError::Invalid("search query is empty"));
    }
    match mode {
        QueryMode::Text => Ok(parse_text(query)),
        QueryMode::Regex => Ok(Parsed::Regex {
            pattern: query.to_owned(),
            pieces: regex_pieces(query)?,
        }),
    }
}

fn parse_text(query: &str) -> Parsed {
    let mut words: Vec<Word> = Vec::new();
    let mut literals: Vec<Literal> = Vec::new();
    // Odd segments between double quotes are phrases.
    for (index, segment) in query.split('"').enumerate() {
        if index % 2 == 1 {
            if !segment.trim().is_empty() {
                literals.push(Literal::new(segment));
            }
            continue;
        }
        for raw in segment.split_whitespace() {
            if raw.chars().all(|c| c.is_alphanumeric() || c == '_') {
                let parts: Vec<String> = tokens::split_parts(raw)
                    .into_iter()
                    .map(str::to_lowercase)
                    .collect();
                let text = raw.to_lowercase();
                if !words.iter().any(|word| word.text == text) {
                    words.push(Word {
                        text,
                        parts: if parts.len() > 1 { parts } else { Vec::new() },
                    });
                }
            } else {
                literals.push(Literal::new(raw));
            }
        }
    }
    Parsed::Text { words, literals }
}

impl Literal {
    fn new(raw: &str) -> Self {
        let text = raw
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        let mut parts: Vec<String> = Vec::new();
        for segment in raw.split(|c: char| !c.is_alphanumeric()) {
            // A long hex run is indexed whole, never by parts.
            if segment.len() >= 16 && segment.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            for part in tokens::split_parts(segment) {
                push_unique(&mut parts, part.to_lowercase());
            }
        }
        let mut words: Vec<String> = Vec::new();
        for word in raw.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            if !word.is_empty() {
                push_unique(&mut words, word.to_lowercase());
            }
        }
        let mut joined = std::collections::HashMap::new();
        tokens::tokenize(raw, &mut joined);
        let mut anchor_sets: Vec<Vec<String>> = Vec::new();
        let whole = joined.contains_key(&text).then(|| vec![text.clone()]);
        for set in [Some(parts), Some(words), whole].into_iter().flatten() {
            let set: Vec<String> = set
                .into_iter()
                .filter(|token| token.len() <= tokens::MAX_TOKEN_BYTES)
                .collect();
            if !set.is_empty() && !anchor_sets.contains(&set) {
                anchor_sets.push(set);
            }
        }
        Self { text, anchor_sets }
    }
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if !list.contains(&item) {
        list.push(item);
    }
}

/// Identifier pieces of the literals every match of `pattern` contains.
///
/// A piece is cut at the same places the tokenizer splits identifiers, so it
/// lies inside one indexed part. The last piece is dropped when it ends in two
/// capitals, because a following lowercase letter would move that split.
pub(crate) fn regex_pieces(pattern: &str) -> Result<Vec<String>> {
    let hir = regex_syntax::ParserBuilder::new()
        .build()
        .parse(pattern)
        .map_err(|_| IndexError::Invalid("regex query does not parse"))?;
    let mut literals = Vec::new();
    let mut run = Vec::new();
    required_literals(&hir, &mut run, &mut literals);
    flush(&mut run, &mut literals);
    let mut pieces: Vec<String> = Vec::new();
    for literal in literals {
        for piece in literal_pieces(&literal) {
            if !pieces.contains(&piece) {
                pieces.push(piece);
            }
        }
    }
    Ok(pieces)
}

fn required_literals(hir: &Hir, run: &mut Vec<u8>, out: &mut Vec<String>) {
    match hir.kind() {
        HirKind::Literal(literal) => run.extend_from_slice(&literal.0),
        HirKind::Concat(children) => {
            for child in children {
                required_literals(child, run, out);
            }
        }
        HirKind::Capture(capture) => required_literals(&capture.sub, run, out),
        // Zero-width assertions keep their neighbours adjacent.
        HirKind::Look(_) | HirKind::Empty => {}
        HirKind::Repetition(repetition) if repetition.min >= 1 => {
            flush(run, out);
            let mut inner = Vec::new();
            required_literals(&repetition.sub, &mut inner, out);
            flush(&mut inner, out);
        }
        _ => flush(run, out),
    }
}

fn flush(run: &mut Vec<u8>, out: &mut Vec<String>) {
    if !run.is_empty() {
        out.push(String::from_utf8_lossy(run).into_owned());
        run.clear();
    }
}

fn literal_pieces(literal: &str) -> Vec<String> {
    let segments: Vec<&str> = literal.split(|c: char| !c.is_alphanumeric()).collect();
    let ends_in_word = literal.chars().last().is_some_and(char::is_alphanumeric);
    let mut out = Vec::new();
    for (index, segment) in segments.iter().enumerate() {
        // Parts holding other letters never enter the trigram index.
        if segment.is_empty() || !segment.is_ascii() {
            continue;
        }
        let mut parts = tokens::split_parts(segment);
        let open_end = ends_in_word && index + 1 == segments.len();
        let bytes = segment.as_bytes();
        if open_end
            && bytes.len() >= 2
            && bytes[bytes.len() - 2..].iter().all(u8::is_ascii_uppercase)
        {
            parts.pop();
        }
        out.extend(
            parts
                .into_iter()
                .map(str::to_ascii_lowercase)
                .filter(|part| tokens::is_gram_token(part)),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pieces(pattern: &str) -> Vec<String> {
        regex_pieces(pattern).unwrap_or_default()
    }

    #[test]
    fn regex_anchors_are_required_identifier_pieces() {
        assert_eq!(pieces(r"fn\s+scan_worktree\("), ["scan", "worktree"]);
        assert_eq!(pieces(r"QueryRead(er)?::new"), ["query", "read", "new"]);
        assert_eq!(pieces(r"foo|bar"), Vec::<String>::new());
        assert_eq!(pieces(r"(?i)reader"), Vec::<String>::new());
        assert_eq!(pieces(r"\w+->\w+"), Vec::<String>::new());
        // A trailing acronym may split differently in the text.
        assert_eq!(pieces(r"loadHTTPS"), ["load"]);
        assert_eq!(pieces(r"x+abc"), ["abc"]);
        assert!(regex_pieces("(unclosed").is_err());
    }

    #[test]
    fn punctuation_makes_a_literal_and_quotes_make_a_phrase() -> Result<()> {
        let Parsed::Text { words, literals } = parse(
            "QueryReader self.conn.run \"open  the Door\" ->",
            QueryMode::Text,
        )?
        else {
            return Err(IndexError::Invalid("text query parsed as regex"));
        };
        assert_eq!(words.len(), 1);
        assert_eq!(words[0].text, "queryreader");
        assert_eq!(words[0].parts, ["query", "reader"]);
        let texts: Vec<&str> = literals.iter().map(|lit| lit.text.as_str()).collect();
        assert_eq!(texts, ["self.conn.run", "open the door", "->"]);
        assert_eq!(literals[0].anchor_sets, [["self", "conn", "run"]]);
        assert!(literals[2].anchor_sets.is_empty());
        let Parsed::Text { literals, .. } = parse("QueryReader::new", QueryMode::Text)? else {
            return Err(IndexError::Invalid("text query parsed as regex"));
        };
        let sets: Vec<Vec<&str>> = literals[0]
            .anchor_sets
            .iter()
            .map(|set| set.iter().map(String::as_str).collect())
            .collect();
        assert_eq!(
            sets,
            [
                vec!["query", "reader", "new"],
                vec!["queryreader", "new"],
                vec!["queryreader::new"]
            ]
        );
        assert!(parse("  ", QueryMode::Text).is_err());
        Ok(())
    }
}
