//! Term resolution: the vocabulary tokens one query word may stand for.
//!
//! In order: an exact token (evidence 100; words of one or two characters
//! go through `short` and stop there), separator-stripped spellings through
//! the `vocab_compact` index (95), and only when both find nothing, typo
//! candidates. Typo candidates come from the trigram index (the 256 tokens
//! sharing the most trigrams) plus, for words of up to five letters, every
//! one-edit spelling looked up directly, since a short word shares too few
//! trigrams to retrieve reliably. A candidate is kept when the Dice score of
//! boundary-padded trigrams is at least 0.45 and a banded Damerau-Levenshtein
//! distance is within the word's band (70 - 5 per edit), or when it extends
//! the word as a prefix or subsequence (60). Near misses outside those bounds
//! are kept apart, only for labelled guesses.
use super::MatchKind;
use crate::{Result, extract::tokens, store::ReadSnapshot};
use rusqlite::{OptionalExtension, params};
use std::collections::HashMap;

/// Candidates read from the trigram index per word.
const RETRIEVE: usize = 256;
pub(crate) const MIN_DICE: f64 = 0.45;
const GUESS_DICE: f64 = 0.30;
/// Tokens kept per word.
const MAX_TERM_TOKENS: usize = 16;
const COMPACT_LIMIT: i64 = 32;
const PREFIX_LIMIT: i64 = 32;
/// Words up to this many bytes also try every one-edit spelling.
const EDIT_LOOKUP_MAX: usize = 5;
const EDIT_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";

#[derive(Clone, Debug)]
pub(crate) struct TokenMatch {
    pub id: i64,
    pub text: String,
    pub kind: MatchKind,
    pub evidence: u8,
}

#[derive(Debug, Default)]
pub(crate) struct Resolution {
    pub matches: Vec<TokenMatch>,
    /// Close spellings outside the typo bounds, best first.
    pub near: Vec<TokenMatch>,
}

impl Resolution {
    pub fn has_exact(&self) -> bool {
        self.matches
            .iter()
            .any(|found| found.kind == MatchKind::Exact)
    }
}

/// The maximum edit distance for a word of `len` separator-stripped bytes.
pub(crate) fn max_distance(len: usize) -> usize {
    match len {
        0..=2 => 0,
        3..=5 => 1,
        6..=10 => 2,
        _ => 3,
    }
}

pub(crate) fn resolve(snapshot: &ReadSnapshot<'_>, word: &str) -> Result<Resolution> {
    let conn = snapshot.connection();
    let mut out = Resolution::default();
    if word.len() <= tokens::MAX_SHORT_TOKEN {
        let mut select = conn.prepare_cached("SELECT vocab_id FROM short WHERE tok=?1")?;
        for id in select.query_map([word], |row| row.get::<_, i64>(0))? {
            out.matches.push(found(id?, word, MatchKind::Exact));
        }
        return Ok(out);
    }
    if let Some(id) = snapshot.token_id(word)? {
        out.matches.push(found(id, word, MatchKind::Exact));
    }
    let compact = tokens::compact(word);
    let mut select =
        conn.prepare_cached("SELECT id, tok FROM vocab WHERE compact=?1 ORDER BY id LIMIT ?2")?;
    let rows = select.query_map(params![compact, COMPACT_LIMIT], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (id, text) = row?;
        if !out.matches.iter().any(|known| known.id == id) {
            out.matches.push(found(id, &text, MatchKind::Compact));
        }
    }
    if out.matches.is_empty() && typo_eligible(word) {
        typo_candidates(snapshot, word, &compact, &mut out)?;
    }
    Ok(out)
}

fn found(id: i64, text: &str, kind: MatchKind) -> TokenMatch {
    TokenMatch {
        id,
        text: text.to_owned(),
        kind,
        evidence: kind.evidence(),
    }
}

/// Typo matching covers identifier words with at least one letter.
fn typo_eligible(word: &str) -> bool {
    word.len() >= 3
        && word.bytes().any(|b| b.is_ascii_lowercase())
        && word
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn typo_candidates(
    snapshot: &ReadSnapshot<'_>,
    word: &str,
    compact: &str,
    out: &mut Resolution,
) -> Result<()> {
    let conn = snapshot.connection();
    let band = max_distance(compact.len());
    let query_grams = padded_trigrams(compact);
    let mut text_of = conn.prepare_cached("SELECT tok, compact FROM vocab WHERE id=?1")?;
    let mut near = Vec::new();
    for id in retrieve(snapshot, word, compact)? {
        let Some((text, token_compact)) = text_of
            .query_row([id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .optional()?
        else {
            continue;
        };
        let dice = dice(&query_grams, &padded_trigrams(&token_compact));
        let distance = osa_distance(compact, &token_compact, band + 1);
        match judge(compact, &token_compact, dice, distance, band) {
            Some(kind) => out.matches.push(found(id, &text, kind)),
            None if dice >= GUESS_DICE && distance.is_some() => {
                let distance = distance.unwrap_or(band + 1);
                near.push((distance, found(id, &text, fuzzy(distance))));
            }
            None => {}
        }
    }
    let mut prefix = conn.prepare_cached(
        "SELECT id, tok FROM vocab WHERE tok > ?1 AND tok < ?2 ORDER BY tok LIMIT ?3",
    )?;
    let upper = format!("{word}{}", char::MAX);
    let rows = prefix.query_map(params![word, upper, PREFIX_LIMIT], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (id, text) = row?;
        if !out.matches.iter().any(|known| known.id == id) {
            out.matches.push(found(id, &text, MatchKind::Partial));
        }
    }
    out.matches.sort_by(|a, b| {
        b.evidence
            .cmp(&a.evidence)
            .then(a.text.len().cmp(&b.text.len()))
            .then(a.id.cmp(&b.id))
    });
    out.matches.dedup_by_key(|found| found.id);
    out.matches.truncate(MAX_TERM_TOKENS);
    near.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.text.cmp(&b.1.text)));
    out.near = near.into_iter().map(|(_, found)| found).take(3).collect();
    Ok(())
}

fn fuzzy(distance: usize) -> MatchKind {
    MatchKind::Fuzzy {
        distance: u8::try_from(distance).unwrap_or(u8::MAX),
    }
}

/// Classify one retrieved token against the word, both separator-stripped.
fn judge(
    word: &str,
    token: &str,
    dice: f64,
    distance: Option<usize>,
    band: usize,
) -> Option<MatchKind> {
    match distance {
        Some(0) => return Some(MatchKind::Compact),
        Some(d) if d <= band && dice >= MIN_DICE => return Some(fuzzy(d)),
        _ => {}
    }
    let extends = token.starts_with(word)
        || (dice >= MIN_DICE
            && token.len() <= word.len() * 2
            && word.chars().next() == token.chars().next()
            && subsequence(word, token));
    extends.then_some(MatchKind::Partial)
}

/// Vocab ids worth scoring: trigram overlap leaders, plus one-edit
/// spellings of a short word.
fn retrieve(snapshot: &ReadSnapshot<'_>, word: &str, compact: &str) -> Result<Vec<i64>> {
    let mut grams: Vec<u32> = tokens::trigrams(word)
        .chain(tokens::trigrams(compact))
        .collect();
    grams.sort_unstable();
    grams.dedup();
    let mut overlap: HashMap<i64, u32> = HashMap::new();
    for gram in grams {
        for id in snapshot.gram_tokens(gram)? {
            *overlap.entry(id).or_insert(0) += 1;
        }
    }
    let mut ranked: Vec<(i64, u32)> = overlap.into_iter().collect();
    ranked.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    ranked.truncate(RETRIEVE);
    let mut ids: Vec<i64> = ranked.into_iter().map(|(id, _)| id).collect();
    if compact.len() <= EDIT_LOOKUP_MAX {
        let mut select = snapshot
            .connection()
            .prepare_cached("SELECT id FROM vocab WHERE compact=?1 ORDER BY id LIMIT 4")?;
        for spelling in one_edit_spellings(compact) {
            for id in select.query_map([spelling], |row| row.get::<_, i64>(0))? {
                let id = id?;
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
    }
    Ok(ids)
}

/// Every spelling one deletion, insertion, substitution or transposition
/// away, over the identifier alphabet.
pub(crate) fn one_edit_spellings(word: &str) -> Vec<String> {
    let bytes = word.as_bytes();
    let mut out = Vec::new();
    let mut push = |candidate: Vec<u8>| {
        if let Ok(text) = String::from_utf8(candidate)
            && !text.is_empty()
            && text != word
        {
            out.push(text);
        }
    };
    for at in 0..=bytes.len() {
        if at < bytes.len() {
            push([&bytes[..at], &bytes[at + 1..]].concat());
            if at + 1 < bytes.len() {
                let mut swapped = bytes.to_vec();
                swapped.swap(at, at + 1);
                push(swapped);
            }
        }
        for &letter in EDIT_ALPHABET {
            push([&bytes[..at], &[letter], &bytes[at..]].concat());
            if at < bytes.len() {
                push([&bytes[..at], &[letter], &bytes[at + 1..]].concat());
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Sorted distinct trigrams of `text` padded with one boundary mark each
/// side, so short words still share their first and last letters.
pub(crate) fn padded_trigrams(text: &str) -> Vec<[char; 3]> {
    let chars: Vec<char> = std::iter::once('\u{2}')
        .chain(text.chars())
        .chain(std::iter::once('\u{3}'))
        .collect();
    let mut grams: Vec<[char; 3]> = chars.windows(3).map(|w| [w[0], w[1], w[2]]).collect();
    grams.sort_unstable();
    grams.dedup();
    grams
}

/// Dice coefficient of two sorted distinct trigram lists.
pub(crate) fn dice(a: &[[char; 3]], b: &[[char; 3]]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let (mut i, mut j, mut shared) = (0, 0, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                shared += 1;
                i += 1;
                j += 1;
            }
        }
    }
    (2 * shared) as f64 / (a.len() + b.len()) as f64
}

/// Optimal-string-alignment (restricted Damerau-Levenshtein) distance,
/// computed only inside a diagonal band of width `max`; `None` past it.
pub(crate) fn osa_distance(a: &str, b: &str, max: usize) -> Option<usize> {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > max {
        return None;
    }
    if a.is_empty() || b.is_empty() {
        return Some(a.len().max(b.len()));
    }
    let over = max + 1;
    let width = b.len() + 1;
    let mut before: Vec<usize> = vec![over; width];
    let mut previous: Vec<usize> = (0..width).map(|j| j.min(over)).collect();
    let mut current: Vec<usize> = vec![over; width];
    for i in 1..=a.len() {
        current.fill(over);
        current[0] = i.min(over);
        let mut row_min = current[0];
        let low = i.saturating_sub(max).max(1);
        let high = (i + max).min(b.len());
        for j in low..=high {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut value = (previous[j - 1] + cost)
                .min(previous[j] + 1)
                .min(current[j - 1] + 1);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                value = value.min(before[j - 2] + 1);
            }
            current[j] = value.min(over);
            row_min = row_min.min(current[j]);
        }
        if row_min > max {
            return None;
        }
        std::mem::swap(&mut before, &mut previous);
        std::mem::swap(&mut previous, &mut current);
    }
    let distance = previous[b.len()];
    (distance <= max).then_some(distance)
}

/// Whether every char of `needle` appears in `haystack` in order.
fn subsequence(needle: &str, haystack: &str) -> bool {
    let mut rest = haystack.chars();
    needle.chars().all(|c| rest.any(|h| h == c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banded_osa_counts_transpositions_and_stops_past_the_band() {
        assert_eq!(osa_distance("queryreder", "queryreader", 2), Some(1));
        assert_eq!(osa_distance("reciever", "receiver", 2), Some(1));
        assert_eq!(osa_distance("memry", "memory", 1), Some(1));
        assert_eq!(
            osa_distance("scanworktreforlnks", "scanworktreeforlinks", 3),
            Some(2)
        );
        assert_eq!(osa_distance("abc", "abc", 0), Some(0));
        assert_eq!(osa_distance("abcdef", "badcfe", 2), None);
        assert_eq!(osa_distance("abc", "abcdefg", 3), None);
        assert_eq!(osa_distance("", "ab", 2), Some(2));
    }

    #[test]
    fn padded_dice_keeps_short_typos_and_rejects_strangers() {
        let score = |a: &str, b: &str| dice(&padded_trigrams(a), &padded_trigrams(b));
        assert!(score("memry", "memory") >= MIN_DICE);
        assert!(score("statemnt", "statement") >= MIN_DICE);
        assert!(score("literlbst", "literalbst") >= MIN_DICE);
        assert!(score("worktre", "worktree") >= MIN_DICE);
        assert!(score("memry", "merry_go") < MIN_DICE);
        assert!((score("same", "same") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn bands_and_verdicts_follow_word_length() {
        assert_eq!(max_distance(2), 0);
        assert_eq!(max_distance(5), 1);
        assert_eq!(max_distance(10), 2);
        assert_eq!(max_distance(11), 3);
        let verdict = |word: &str, token: &str| {
            let d = dice(&padded_trigrams(word), &padded_trigrams(token));
            let band = max_distance(word.len());
            judge(word, token, d, osa_distance(word, token, band + 1), band)
        };
        assert_eq!(
            verdict("queryreder", "queryreader"),
            Some(MatchKind::Fuzzy { distance: 1 })
        );
        assert_eq!(verdict("atlas", "atlasindex"), Some(MatchKind::Partial));
        assert_eq!(verdict("door", "floor"), None);
        let spellings = one_edit_spellings("memry");
        assert!(spellings.iter().any(|s| s == "memory"));
        assert!(spellings.iter().any(|s| s == "mery") && !spellings.contains(&"memry".into()));
    }
}
