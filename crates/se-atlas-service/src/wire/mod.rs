//! v5 answers in the shared `se_types::code` wire: pointers, spans, kinds,
//! pages and cursors. Every page states why it stopped; an incomplete source
//! outranks a page limit, so a cursor never hides a gap.
pub(crate) mod find;
pub(crate) mod history;
pub(crate) mod nav;
pub(crate) mod outline;
pub(crate) mod records;

use se_atlas_index::extract::{LanguageTag, SymbolKind as V5Kind, file_key};
use se_types::code::AtlasText as _;
use se_types::{
    Cursor, Omission, OmissionReason, Page, Read, Result, SeError, Sequence, Source, StopReason,
    Window, WindowFields,
    code::{
        Answer, AtlasCursor, CodePointer, ContentHash, FileId, IndexSummary, Language, Position,
        QueryBudget, RelativePath, SnapshotFreshness, Span, SymbolKind,
    },
};
use std::num::NonZeroU32;

pub(crate) fn answer<T>(index: &IndexSummary, data: Read<T>) -> Answer<Read<T>> {
    Answer {
        index: index.clone(),
        snapshot_advanced: false,
        epoch_retired: false,
        data,
    }
}

pub(crate) fn unknown<T>(index: &IndexSummary, what: &str) -> Answer<Read<T>> {
    answer(index, Read::Unknown { what: what.into() })
}

pub(crate) fn file_id(path: &str) -> FileId {
    FileId(file_key(path))
}

/// A one-or-more line span; byte offsets are not tracked by the v5 index.
pub(crate) fn span(line: u32, end_line: u32) -> Span {
    let line = line.max(1);
    Span {
        start: Position {
            line,
            byte_column: 0,
        },
        end: Position {
            line: end_line.max(line),
            byte_column: 0,
        },
        start_byte: 0,
        end_byte: 0,
    }
}

pub(crate) fn pointer(
    path: &str,
    lines: Option<(u32, u32)>,
    hash: Option<[u8; 32]>,
    freshness: SnapshotFreshness,
) -> Result<CodePointer> {
    Ok(CodePointer {
        file: file_id(path),
        path: RelativePath::new(path)?,
        span: lines.map(|(line, end)| span(line, end)),
        content_hash: hash.map(ContentHash),
        freshness,
    })
}

pub(crate) fn hash(blob: Option<Vec<u8>>) -> Option<[u8; 32]> {
    blob.and_then(|bytes| bytes.try_into().ok())
}

pub(crate) fn kind(kind: V5Kind) -> SymbolKind {
    match kind {
        V5Kind::Module | V5Kind::Section | V5Kind::Table | V5Kind::Stage => SymbolKind::Module,
        V5Kind::Function | V5Kind::Target | V5Kind::Test => SymbolKind::Function,
        V5Kind::Method => SymbolKind::Method,
        V5Kind::Struct => SymbolKind::Struct,
        V5Kind::Enum => SymbolKind::Enum,
        V5Kind::Interface => SymbolKind::Interface,
        V5Kind::Impl | V5Kind::Namespace => SymbolKind::Namespace,
        V5Kind::Class => SymbolKind::Class,
        V5Kind::Type => SymbolKind::TypeAlias,
        V5Kind::Const => SymbolKind::Constant,
        V5Kind::Variable => SymbolKind::Variable,
        V5Kind::Macro => SymbolKind::Macro,
        V5Kind::Key | V5Kind::Item => SymbolKind::Field,
    }
}

/// The closed wire language for an open v5 tag, when it has one.
pub(crate) fn language(tag: &str, path: &str) -> Option<Language> {
    let jsx = path.ends_with(".jsx");
    let tsx = path.ends_with(".tsx");
    match tag {
        "rust" => Some(Language::Rust),
        "python" => Some(Language::Python),
        "javascript" if jsx => Some(Language::Jsx),
        "javascript" => Some(Language::JavaScript),
        "typescript" if tsx => Some(Language::Tsx),
        "typescript" => Some(Language::TypeScript),
        _ => None,
    }
}

pub(crate) fn language_tags(languages: &[Language]) -> Vec<LanguageTag> {
    let mut tags: Vec<LanguageTag> = Vec::new();
    for language in languages {
        let name = match language {
            Language::JavaScript | Language::Jsx => "javascript",
            Language::TypeScript | Language::Tsx => "typescript",
            Language::Rust => "rust",
            Language::Python => "python",
        };
        if let Some(tag) = LanguageTag::new(name)
            && !tags.contains(&tag)
        {
            tags.push(tag);
        }
    }
    tags
}

/// Serialized bytes of a value, the measure every byte budget uses.
pub(crate) fn size(value: &impl serde::Serialize) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// Opaque page cursors: a tag letter and a payload in the cursor alphabet.
pub(crate) mod cursor {
    use se_types::{
        Result, SeError,
        code::{AtlasCursor, AtlasText as _},
    };

    pub fn wrap(tag: char, payload: &str) -> Result<AtlasCursor> {
        let mut text = format!("{tag}{}", payload.replace('.', "_"));
        // Unpadded base64url lengths are never 1 mod 4.
        if text.len() % 4 == 1 {
            text.push('-');
        }
        AtlasCursor::new(text)
    }

    pub fn unwrap(tag: char, cursor: &AtlasCursor) -> Result<String> {
        cursor
            .as_str()
            .strip_prefix(tag)
            .map(|payload| payload.trim_end_matches('-').replace('_', "."))
            .ok_or_else(|| {
                SeError::invalid(
                    "Atlas cursor",
                    "a cursor this query returned; repeat the query without it",
                )
            })
    }

    pub fn number(tag: char, cursor: &AtlasCursor) -> Result<u64> {
        unwrap(tag, cursor)?.parse().map_err(|_| {
            SeError::invalid(
                "Atlas cursor",
                "a cursor this query returned; repeat the query without it",
            )
        })
    }
}

/// One page and the window that accounts for it.
pub(crate) struct PageFacts<'a> {
    pub index: &'a IndexSummary,
    pub budget: QueryBudget,
    pub after: Option<&'a AtlasCursor>,
    pub next: Option<AtlasCursor>,
    pub examined: Examined,
    pub bytes: usize,
}

/// How much of its sources a page examined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Examined {
    All,
    /// The sources left something unexamined.
    Partly,
    /// The work deadline stopped the reading, leaving the rest unexamined.
    Deadline,
}

impl Examined {
    pub fn of(partial: bool, deadline: bool) -> Self {
        if deadline {
            Self::Deadline
        } else if partial {
            Self::Partly
        } else {
            Self::All
        }
    }
}

pub(crate) fn page<T>(items: Vec<T>, facts: PageFacts<'_>) -> Result<Page<T>> {
    let PageFacts {
        index,
        budget,
        after,
        next,
        examined,
        bytes,
    } = facts;
    let omission = if examined != Examined::All {
        Omission::Unknown {
            reason: OmissionReason::SourceIncomplete,
        }
    } else if next.is_some() {
        Omission::Unknown {
            reason: OmissionReason::Limit,
        }
    } else {
        Omission::None
    };
    let wire = |cursor: &AtlasCursor| Cursor::new(cursor.as_str());
    let limit = u32::from(budget.max_results).max(items.len() as u32);
    let window = Window::new(WindowFields {
        source: Source::Atlas {
            project: index.project.clone(),
            root: index.root.clone(),
            epoch: index.epoch.clone(),
        },
        from: Sequence::ZERO,
        to: Sequence::new(index.generation.map_or(1, |g| g.0.max(1)))?,
        start_cursor: after.map(wire).transpose()?,
        end_cursor: next.as_ref().map(wire).transpose()?,
        returned: items.len() as u64,
        limit: NonZeroU32::new(limit.max(1))
            .ok_or_else(|| SeError::invalid("Atlas page", "a positive limit"))?,
        bytes: bytes.min(budget.max_bytes as usize) as u64,
        max_bytes: NonZeroU32::new(budget.max_bytes)
            .ok_or_else(|| SeError::invalid("Atlas page", "a positive byte limit"))?,
        omitted_before: Omission::None,
        omitted_after: omission,
        unreadable: 0,
        stop_reason: if examined == Examined::Deadline {
            StopReason::Deadline
        } else if next.is_some() {
            StopReason::ItemLimit
        } else if examined == Examined::Partly {
            StopReason::Unsupported
        } else {
            StopReason::Exhausted
        },
    })?;
    Page::new(items, window, next.as_ref().map(wire).transpose()?)
}

/// Bytes of the answer for `facts`' page before any item is listed. The
/// page's cursor is taken as given, so pass the widest one it may carry;
/// each listed item then costs its own bytes plus one separator.
pub(crate) fn envelope<T: serde::Serialize>(facts: PageFacts<'_>) -> Result<usize> {
    let index = facts.index;
    let value = page(Vec::<T>::new(), facts)?;
    Ok(size(&answer(index, Read::Present { value })))
}

/// Refuse an answer past its byte budget instead of truncating it silently.
pub(crate) fn checked<T: serde::Serialize>(value: T, budget: QueryBudget) -> Result<T> {
    let bytes = size(&value);
    if bytes > budget.max_bytes as usize {
        return Err(SeError::new(se_types::Detail::AtlasResourceBudget(
            se_types::details::AtlasResourceBudget {
                resource: "Atlas response bytes".into(),
                requested: bytes as u64,
                available: u64::from(budget.max_bytes),
            },
        )));
    }
    Ok(value)
}
