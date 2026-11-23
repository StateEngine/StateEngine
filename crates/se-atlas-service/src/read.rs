//! Queries against one root. Each answer carries the root's summary as it
//! stood when the query began; the host decides beforehand whether the root
//! can answer at all.
use crate::{
    error::{index_error, sqlite},
    reconcile,
    root::Root,
    wire::{find, history, nav},
};
use rusqlite::OptionalExtension;
use se_atlas_query::{Answer as Found, Target, outline::OutlineRequest};
use se_types::{
    EventId, Page, Read, Result,
    code::{
        Answer, ChangesQuery, CodeChange, FindQuery, Impact, ImpactQuery, Outline, OutlineQuery,
        QueryText, RecordHit, RecordPointer, ReferenceHit, RefsQuery, ResumeCode, ResumeRequest,
        SearchResults,
    },
};

/// The refusal while a root has no store to read yet.
pub const STARTING: &str = "Atlas indexing is queued or starting; retry this query in 1 second, or use se status to watch progress";

/// Smallest file an edit hook outlines; smaller files are read whole anyway.
const HOOK_OUTLINE_BYTES: i64 = 32 * 1024;
/// Outline entries a hook lists.
const HOOK_OUTLINE_ENTRIES: usize = 40;

/// Core's check of one record for the admitted viewer. The store only holds
/// candidates; a record becomes a hit only through this check.
pub trait RecordCheck {
    fn hit(&self, pointer: &RecordPointer, query: Option<&QueryText>) -> Result<Read<RecordHit>>;
}

/// Index-only context for an edit hook naming a symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookSymbol {
    pub name: String,
    pub path: String,
    pub line: u32,
    /// Files importing the defining file and holding the name.
    pub callers: Vec<String>,
    /// Project-visible records mentioning the symbol or its file.
    pub mentions: usize,
}

/// Index-only outline of a large file for an edit hook.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookOutline {
    pub path: String,
    pub symbols: Vec<(String, u32)>,
    pub mentions: usize,
}

impl Root {
    pub fn find(
        &self,
        query: &FindQuery,
        records: &dyn RecordCheck,
    ) -> Result<Answer<Read<SearchResults>>> {
        find::find(&self.shared, &self.summary()?, query, records)
    }

    pub fn refs(&self, query: &RefsQuery) -> Result<Answer<Read<Page<ReferenceHit>>>> {
        nav::refs(&self.shared, &self.summary()?, query)
    }

    pub fn impact(
        &self,
        query: &ImpactQuery,
        records: &dyn RecordCheck,
    ) -> Result<Answer<Read<Impact>>> {
        nav::impact(&self.shared, &self.summary()?, query, records)
    }

    pub fn outline(
        &self,
        query: &OutlineQuery,
        records: &dyn RecordCheck,
    ) -> Result<Answer<Read<Outline>>> {
        nav::outline(&self.shared, &self.summary()?, query, records)
    }

    pub fn changes(&self, query: &ChangesQuery) -> Result<Answer<Read<Page<CodeChange>>>> {
        history::changes(&self.shared, &self.summary()?, query)
    }

    /// The resume digest; building it never moves the viewer's cursor.
    pub fn resume(&self, request: &ResumeRequest) -> Result<ResumeCode> {
        history::resume(&self.shared, &self.summary()?, request)
    }

    /// The last core event folded into the store's records.
    pub fn feed_cursor(&self) -> Result<Option<EventId>> {
        crate::engine::feed_cursor(&self.shared)
    }

    /// Whether `path` names a regular file in this worktree now, checked
    /// through custody without reading it.
    pub fn has_file(&self, path: &str) -> Result<bool> {
        let Some(source) = self.shared.source() else {
            return Ok(false);
        };
        Ok(reconcile::stat(source, path)
            .map_err(|e| index_error(&e))?
            .is_some())
    }

    /// A unique definition of `name`, with its importers, from SQL alone.
    pub fn hook_symbol(&self, name: &str) -> Result<Option<HookSymbol>> {
        let reader = self.shared.reader()?;
        let result = (|| {
            let found = se_atlas_query::hooks::hooks(&reader, &Target::Symbol(name.to_owned()))
                .map_err(|e| index_error(&e))?;
            let Found::Found(hooks) = found else {
                return Ok(None);
            };
            // One defining file; a type and its impl blocks are one target.
            let (Some(symbol), [file]) = (hooks.symbols.first(), hooks.files.as_slice()) else {
                return Ok(None);
            };
            let line: Option<u32> = reader
                .connection()
                .prepare_cached(
                    "SELECT s.line FROM sym s JOIN vocab v ON v.id = s.name
                     WHERE s.file=?1 AND v.tok=?2 ORDER BY s.line LIMIT 1",
                )
                .and_then(|mut select| {
                    select
                        .query_row(rusqlite::params![file.id, name.to_lowercase()], |row| {
                            row.get(0)
                        })
                        .optional()
                })
                .map_err(|e| sqlite(&e))?;
            Ok(Some(HookSymbol {
                name: symbol.clone(),
                path: file.path.clone(),
                line: line.unwrap_or(1),
                callers: hooks.importers.items.clone(),
                mentions: hooks.mentions,
            }))
        })();
        self.shared.give_back(reader);
        result
    }

    /// The outline of a large indexed file, or `None` for a small one.
    pub fn hook_outline(&self, path: &str) -> Result<Option<HookOutline>> {
        let Some(source) = self.shared.source() else {
            return Ok(None);
        };
        match reconcile::stat(source, path).map_err(|e| index_error(&e))? {
            Some((size, _)) if size >= HOOK_OUTLINE_BYTES => {}
            _ => return Ok(None),
        }
        let reader = self.shared.reader()?;
        let result = (|| {
            let request = OutlineRequest {
                target: Target::File(path.to_owned()),
                limit: HOOK_OUTLINE_ENTRIES,
            };
            let Found::Found(outline) =
                se_atlas_query::outline::outline(&reader, &request).map_err(|e| index_error(&e))?
            else {
                return Ok(None);
            };
            let mentions =
                match se_atlas_query::hooks::hooks(&reader, &Target::File(path.to_owned()))
                    .map_err(|e| index_error(&e))?
                {
                    Found::Found(hooks) => hooks.mentions,
                    _ => 0,
                };
            Ok(Some(HookOutline {
                path: outline.file.path.clone(),
                symbols: outline
                    .entries
                    .iter()
                    .map(|entry| (entry.name.clone(), entry.line))
                    .collect(),
                mentions,
            }))
        })();
        self.shared.give_back(reader);
        result
    }
}
