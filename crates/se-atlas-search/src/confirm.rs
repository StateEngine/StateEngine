//! Reading candidate files and confirming matches line by line.
//!
//! Files open only through [`IndexSourceRoot::open_guarded_file`], so the
//! private-file policy and the no-follow custody apply to every byte read.
//! A grep prefilter finds lines holding any pattern; each such line is then
//! checked pattern by pattern with [`LineText::contains`], which requires the
//! match to start and end where the tokenizer would split an identifier, so
//! `id` matches `user_id` and `userId` but not `valid`.
use crate::{SearchOutcome, rank::TermHit};
use grep_regex::{RegexMatcher, RegexMatcherBuilder};
use grep_searcher::{BinaryDetection, Searcher, SearcherBuilder, sinks::Lossy};
use se_atlas_index::{
    IndexError, Result,
    custody::{FULL_READ_LIMIT, GuardedOpen, IndexSourceRoot},
    extract::{char_prefix, tokens::boundary},
};
use std::io::Read;

/// Confirmed lines kept per file.
const LINES_PER_FILE: usize = 200;
/// Prefilter lines examined per file, confirmed or not.
const SCANNED_LINES_PER_FILE: usize = 20_000;
/// Bytes of a line kept as hit text.
pub(crate) const TEXT_BYTES: usize = 240;
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// What a pattern stands for in the query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Covers {
    /// One query term, by index.
    Term(usize),
    /// Every plain word at once: the words written as one identifier.
    Words,
}

/// One spelling a query term may take in text.
#[derive(Clone, Debug)]
pub(crate) struct Pattern {
    /// Lowercase; a space stands for any run of whitespace.
    pub text: String,
    chars: Vec<char>,
    pub covers: Covers,
    pub hit: TermHit,
    /// The spelling equals the whole query once separators are removed.
    pub full: bool,
}

impl Pattern {
    pub fn new(text: &str, covers: Covers, hit: TermHit, full: bool) -> Self {
        let text = text.to_lowercase();
        Self {
            chars: lower_chars(&text),
            text,
            covers,
            hit,
            full,
        }
    }

    /// The regex alternative that finds lines that may hold this pattern.
    fn prefilter(&self) -> String {
        self.text
            .split(' ')
            .map(regex_syntax::escape)
            .collect::<Vec<_>>()
            .join(r"\s+")
    }
}

/// A line's chars as written and lowercased, position for position.
pub(crate) struct LineText {
    original: Vec<char>,
    lower: Vec<char>,
}

impl LineText {
    pub fn new(line: &str) -> Self {
        let original: Vec<char> = line.chars().collect();
        let lower = lower_chars(line);
        Self { original, lower }
    }

    /// Whether `pattern` occurs case-insensitively with token-split edges.
    pub fn contains(&self, pattern: &Pattern) -> bool {
        let needle = &pattern.chars;
        if needle.is_empty() {
            return false;
        }
        (0..self.lower.len()).any(|start| {
            self.match_at(start, needle)
                .is_some_and(|end| self.edges_split(start, end))
        })
    }

    fn match_at(&self, start: usize, needle: &[char]) -> Option<usize> {
        let mut at = start;
        for &want in needle {
            if want == ' ' {
                let run = self.lower[at.min(self.lower.len())..]
                    .iter()
                    .take_while(|c| c.is_whitespace())
                    .count();
                if run == 0 {
                    return None;
                }
                at += run;
            } else if self.lower.get(at) == Some(&want) {
                at += 1;
            } else {
                return None;
            }
        }
        Some(at)
    }

    fn edges_split(&self, start: usize, end: usize) -> bool {
        let text = &self.original;
        let splits = |left: usize| {
            let (previous, current) = (text[left], text[left + 1]);
            !(previous.is_alphanumeric() && current.is_alphanumeric())
                || boundary(previous, current, text.get(left + 2).copied())
        };
        (start == 0 || splits(start - 1)) && (end >= text.len() || splits(end - 1))
    }
}

fn lower_chars(text: &str) -> Vec<char> {
    text.chars()
        .map(|c| c.to_lowercase().next().unwrap_or(c))
        .collect()
}

/// A case-insensitive matcher for lines holding any of `patterns`.
pub(crate) fn prefilter(patterns: &[Pattern]) -> Result<RegexMatcher> {
    let mut alternatives: Vec<String> = patterns.iter().map(Pattern::prefilter).collect();
    alternatives.sort_unstable();
    alternatives.dedup();
    RegexMatcherBuilder::new()
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build(&alternatives.join("|"))
        .map_err(|_| IndexError::Invalid("search patterns do not compile"))
}

/// A matcher for a regex query as written.
pub(crate) fn regex(pattern: &str) -> Result<RegexMatcher> {
    RegexMatcherBuilder::new()
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build(pattern)
        .map_err(|_| IndexError::Invalid("regex query does not compile"))
}

pub(crate) fn searcher() -> Searcher {
    SearcherBuilder::new()
        .line_number(true)
        .binary_detection(BinaryDetection::quit(0))
        .build()
}

/// How one file read ended.
pub(crate) enum FileRead {
    /// Bytes read; `partial` when a line cap or the full-read limit stopped
    /// the read before the end of the file.
    Done {
        bytes: u64,
        partial: bool,
    },
    Absent,
    Refused,
    Failed,
}

impl FileRead {
    /// Count this read in the outcome's per-reason file counts.
    pub fn tally(&self, outcome: &mut SearchOutcome) {
        match self {
            Self::Done { partial, .. } => {
                outcome.files_read += 1;
                outcome.files_partly_read += usize::from(*partial);
            }
            Self::Absent => outcome.files_absent += 1,
            Self::Refused => outcome.files_refused += 1,
            Self::Failed => outcome.files_read_failed += 1,
        }
    }
}

/// Feed every line of `path` the matcher finds to `on_line` as
/// `(line number, text)`; it answers whether it kept the line. Reading stops
/// after [`LINES_PER_FILE`] kept or [`SCANNED_LINES_PER_FILE`] offered lines.
pub(crate) fn read_lines(
    root: &IndexSourceRoot,
    path: &str,
    matcher: &RegexMatcher,
    searcher: &mut Searcher,
    mut on_line: impl FnMut(u32, &str) -> bool,
) -> FileRead {
    let mut file = match root.open_guarded_file(path) {
        Ok(GuardedOpen::File(file)) => file,
        Ok(GuardedOpen::Absent) => return FileRead::Absent,
        Ok(GuardedOpen::Denied | GuardedOpen::Refused) => return FileRead::Refused,
        Err(_) => return FileRead::Failed,
    };
    let size = file.opened_revision().size;
    let (mut kept, mut offered) = (0usize, 0usize);
    let sink = Lossy(|number, line: &str| {
        let line = line.trim_end_matches(['\r', '\n']);
        let line = if number == 1 {
            line.trim_start_matches('\u{feff}')
        } else {
            line
        };
        offered += 1;
        kept += usize::from(on_line(u32::try_from(number).unwrap_or(u32::MAX), line));
        Ok(kept < LINES_PER_FILE && offered < SCANNED_LINES_PER_FILE)
    });
    match searcher.search_reader(matcher, (&mut file).take(FULL_READ_LIMIT), sink) {
        Ok(()) => FileRead::Done {
            bytes: size.min(FULL_READ_LIMIT),
            partial: size > FULL_READ_LIMIT
                || kept >= LINES_PER_FILE
                || offered >= SCANNED_LINES_PER_FILE,
        },
        Err(_) => FileRead::Failed,
    }
}

/// The trimmed text of a line as shown in a hit.
pub(crate) fn hit_text(line: &str) -> String {
    char_prefix(line.trim(), TEXT_BYTES).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MatchKind;

    fn pattern(text: &str) -> Pattern {
        let hit = TermHit {
            kind: MatchKind::Exact,
            evidence: 100,
            idf: 0,
        };
        Pattern::new(text, Covers::Term(0), hit, false)
    }

    #[test]
    fn matches_need_identifier_split_edges() {
        let id = pattern("id");
        for line in ["let user_id = 1;", "userId", "ID", "fn id()", "x.id"] {
            assert!(LineText::new(line).contains(&id), "{line}");
        }
        for line in ["valid", "idx", "IDs", "userid"] {
            assert!(!LineText::new(line).contains(&id), "{line}");
        }
        let run = pattern("self.conn.run");
        assert!(LineText::new("    Self.conn.runQuery()").contains(&run));
        assert!(!LineText::new("self.conn.running").contains(&run));
        let phrase = pattern("open the door");
        assert!(LineText::new("// Open   the\tdoor now").contains(&phrase));
        assert!(!LineText::new("open thedoor").contains(&phrase));
        let arrow = pattern("->");
        assert!(LineText::new("fn f() -> u8").contains(&arrow));
    }
}
