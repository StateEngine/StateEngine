//! Queries against one root. Each answer carries the root's summary as it
//! stood when the query began, taken together with the dirty paths the
//! answer overlays; the host decides beforehand whether the root can answer.
use crate::{
    error::{index_error, sqlite},
    reconcile,
    root::Root,
    wire::{find, history, nav, outline},
};
use rusqlite::OptionalExtension;
use se_atlas_query::{Answer as Found, Resolved, Target, outline::OutlineRequest};
use se_types::{
    EventId, Page, Read, Result,
    code::{
        Answer, AtlasPrincipal, AtlasTarget, ChangesQuery, CodeChange, FindQuery, Impact,
        ImpactQuery, IndexState, Outline, OutlineQuery, QueryText, RecordHit, RecordPointer,
        ReferenceHit, RefsQuery, RepoHub, RepoMap, ResumeCode, ResumeRequest, SearchResults,
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
        let (index, dirty) = self.shared.snapshot()?;
        find::find(&self.shared, &index, &dirty, query, records)
    }

    pub fn refs(&self, query: &RefsQuery) -> Result<Answer<Read<Page<ReferenceHit>>>> {
        let (index, dirty) = self.shared.snapshot()?;
        nav::refs(&self.shared, &index, &dirty, query)
    }

    pub fn impact(
        &self,
        query: &ImpactQuery,
        records: &dyn RecordCheck,
    ) -> Result<Answer<Read<Impact>>> {
        let (index, dirty) = self.shared.snapshot()?;
        nav::impact(&self.shared, &index, &dirty, query, records)
    }

    pub fn outline(
        &self,
        query: &OutlineQuery,
        records: &dyn RecordCheck,
    ) -> Result<Answer<Read<Outline>>> {
        let (index, dirty) = self.shared.snapshot()?;
        outline::outline(&self.shared, &index, &dirty, query, records)
    }

    /// Changes for `viewer`; a resume range cursor is bound to its viewer.
    pub fn changes(
        &self,
        query: &ChangesQuery,
        viewer: &AtlasPrincipal,
    ) -> Result<Answer<Read<Page<CodeChange>>>> {
        history::changes(&self.shared, &self.summary()?, query, viewer)
    }

    /// The resume digest; building it never moves the viewer's cursor.
    pub fn resume(&self, request: &ResumeRequest) -> Result<ResumeCode> {
        history::resume(&self.shared, &self.summary()?, request)
    }

    /// The last core event folded into the store's records.
    pub fn feed_cursor(&self) -> Result<Option<EventId>> {
        Ok(crate::engine::feed_state(&self.shared)?.0)
    }

    /// Whether any unreadable record event was skipped in this store.
    pub fn feed_degraded(&self) -> Result<bool> {
        Ok(crate::engine::feed_state(&self.shared)?.1)
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

    /// The files that define `target`, in index order: one for a file or a
    /// symbol declared once, several for a name declared in many places,
    /// none for a refused or unknown target. `true` when the name has more
    /// definitions than the index lists, so more files may define it.
    pub fn defining_files(&self, target: &AtlasTarget) -> Result<(Vec<String>, bool)> {
        let target = nav::target(target)?;
        self.shared.with_reader(|reader| {
            Ok(
                match se_atlas_query::resolve(reader, &target).map_err(|e| index_error(&e))? {
                    Resolved::File(file) => (vec![file.path], false),
                    Resolved::Symbols { symbols, capped } => {
                        let mut paths: Vec<String> = Vec::new();
                        for symbol in symbols {
                            if !paths.contains(&symbol.file.path) {
                                paths.push(symbol.file.path);
                            }
                        }
                        (paths, capped)
                    }
                    Resolved::Refused { .. } | Resolved::NotFound { .. } => (Vec::new(), false),
                },
            )
        })
    }

    /// The orientation map of this root, from SQL alone. `current` is false
    /// while the index builds, catches up or holds files changed since.
    /// `None` when the map could not be read before `deadline`.
    pub fn repo_map(&self, deadline: std::time::Instant) -> Result<Option<RepoMap>> {
        let (index, dirty) = self.shared.snapshot()?;
        let Some(map) = self.shared.with_reader(|reader| {
            se_atlas_query::map::map(reader, deadline).map_err(|e| index_error(&e))
        })?
        else {
            return Ok(None);
        };
        let coverage = &index.coverage;
        Ok(Some(RepoMap {
            files: map.files,
            current: index.state == IndexState::Current
                && dirty.paths.is_empty()
                && !dirty.overflowed
                && coverage.stale_files == 0,
            areas: map.areas,
            hubs: map
                .hubs
                .into_iter()
                .map(|hub| RepoHub {
                    path: hub.path,
                    importers: hub.importers,
                    declarations: hub.declarations,
                })
                .collect(),
            complete: map.more_areas == 0 && !map.more_hubs,
        }))
    }

    /// A unique definition of `name`, with its importers, from SQL alone.
    pub fn hook_symbol(&self, name: &str) -> Result<Option<HookSymbol>> {
        self.shared.with_reader(|reader| {
            let found = se_atlas_query::hooks::hooks(reader, &Target::Symbol(name.to_owned()))
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
        })
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
        self.shared.with_reader(|reader| {
            let request = OutlineRequest {
                target: Target::File(path.to_owned()),
                limit: HOOK_OUTLINE_ENTRIES,
            };
            let Found::Found(outline) =
                se_atlas_query::outline::outline(reader, &request).map_err(|e| index_error(&e))?
            else {
                return Ok(None);
            };
            let mentions =
                match se_atlas_query::hooks::hooks(reader, &Target::File(path.to_owned()))
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
        })
    }
}
