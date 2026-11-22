//! Bounded query inputs shared by the CLI, MCP and native host read port.
use super::inputs::Validate;
use schemars::JsonSchema;
use se_types::{Page, Read, Result, SeError, code::*};
use serde::{Deserialize, Serialize};
fn bytes() -> u32 {
    16384
}
fn all() -> SearchKind {
    SearchKind::All
}
fn depth() -> u8 {
    2
}
fn yes() -> bool {
    true
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AtlasOptions {
    /// Select one registered worktree when the admitted project has several.
    #[serde(default)]
    pub root: Option<RootId>,
    #[serde(default)]
    pub cursor: Option<AtlasCursor>,
    /// Page size; defaults: find 20, refs/impact/changes 50, outline 300.
    #[serde(default)]
    pub limit: Option<u16>,
    #[serde(default = "bytes")]
    pub byte_budget: u32,
    #[serde(default)]
    pub format: AtlasFormat,
    #[serde(default)]
    pub explain: bool,
    /// Exit 2 whenever the answer is incomplete or stale, even with hits.
    #[serde(default)]
    pub require_complete: bool,
}
impl AtlasOptions {
    /// `(default, max)` is the family's page size, one of the `ATLAS_*_PAGE` pairs.
    pub fn budget(&self, (default, max): (u16, u16)) -> Result<QueryBudget> {
        let limit = self.limit.unwrap_or(default);
        if !(1024..=ATLAS_MAX_BYTES).contains(&self.byte_budget) || !(1..=max).contains(&limit) {
            return Err(SeError::invalid(
                "Atlas limit or byte_budget",
                &format!("limit 1..{max}; budget 1024..262144 UTF-8 bytes including the envelope"),
            ));
        }
        // The reader measures Answer<Read<T>>; reserve the family's envelope.
        se_types::code::Validate.query_budget(limit, self.byte_budget - 192)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AtlasFind {
    pub query: QueryText,
    #[serde(default = "all")]
    pub kind: SearchKind,
    #[serde(default)]
    pub paths: Vec<RelativePath>,
    #[serde(default)]
    pub languages: Vec<Language>,
    #[serde(default)]
    pub mode: Option<SearchMode>,
    #[serde(default)]
    pub order: SearchOrder,
    #[serde(default)]
    pub full: bool,
    /// Match a case-sensitive regular expression in live source; use (?i) to ignore case.
    #[serde(default)]
    pub regex: bool,
    #[serde(flatten)]
    pub options: AtlasOptions,
}
impl AtlasFind {
    pub fn query(&self) -> Result<FindQuery> {
        Ok(FindQuery {
            query: self.query.clone(),
            kind: self.kind,
            scope: scope(&self.paths, &self.languages)?,
            mode: self.mode,
            order: self.order,
            full: self.full,
            regex: self.regex,
            next: self.options.cursor.clone(),
            budget: {
                let mut budget = self.options.budget(ATLAS_FIND_PAGE)?;
                if self.options.format == AtlasFormat::Compact
                    && matches!(
                        self.kind,
                        SearchKind::All | SearchKind::Code | SearchKind::Text
                    )
                {
                    // Compact source hits need room for typed pointer metadata;
                    // the reader separately fits the exact rendered byte budget.
                    budget.max_bytes = budget.max_bytes.saturating_mul(4).min(ATLAS_MAX_BYTES);
                }
                budget
            },
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AtlasRefs {
    pub target: AtlasTarget,
    #[serde(default)]
    pub kinds: Vec<ReferenceKind>,
    #[serde(default = "yes")]
    pub include_name_only: bool,
    #[serde(flatten)]
    pub options: AtlasOptions,
}
impl AtlasRefs {
    pub fn query(&self) -> Result<RefsQuery> {
        if !matches!(
            self.target,
            AtlasTarget::Symbol(_) | AtlasTarget::File(_) | AtlasTarget::Auto(_)
        ) || self.kinds.len() > 5
        {
            return Err(SeError::invalid(
                "Atlas refs target",
                "a symbol, file or positional target and at most five reference kinds",
            ));
        }
        target(&self.target)?;
        Ok(RefsQuery {
            target: self.target.clone(),
            kinds: self.kinds.clone(),
            include_name_only: self.include_name_only,
            next: self.options.cursor.clone(),
            budget: self.options.budget(ATLAS_LIST_PAGE)?,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AtlasImpact {
    pub target: AtlasTarget,
    #[serde(default = "depth")]
    pub depth: u8,
    #[serde(default)]
    pub include_name_only: bool,
    #[serde(flatten)]
    pub options: AtlasOptions,
}
impl AtlasImpact {
    pub fn query(&self) -> Result<ImpactQuery> {
        if !(1..=3).contains(&self.depth) {
            return Err(SeError::invalid("impact depth", "1..3"));
        }
        target(&self.target)?;
        Ok(ImpactQuery {
            target: self.target.clone(),
            depth: self.depth,
            include_name_only: self.include_name_only,
            next: self.options.cursor.clone(),
            budget: self.options.budget(ATLAS_LIST_PAGE)?,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AtlasChanges {
    pub since: ChangeBaseline,
    #[serde(default)]
    pub paths: Vec<RelativePath>,
    #[serde(default)]
    pub languages: Vec<Language>,
    #[serde(flatten)]
    pub options: AtlasOptions,
}
impl AtlasChanges {
    pub fn query(&self) -> Result<ChangesQuery> {
        Ok(ChangesQuery {
            since: self.since.clone(),
            scope: scope(&self.paths, &self.languages)?,
            next: self.options.cursor.clone(),
            budget: self.options.budget(ATLAS_LIST_PAGE)?,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AtlasOutline {
    pub path: RelativePath,
    #[serde(flatten)]
    pub options: AtlasOptions,
}
impl AtlasOutline {
    pub fn query(&self) -> Result<OutlineQuery> {
        Ok(OutlineQuery {
            path: self.path.clone(),
            next: self.options.cursor.clone(),
            budget: self.options.budget(ATLAS_OUTLINE_PAGE)?,
        })
    }
}
/// Each Atlas input is valid exactly when it builds its bounded query.
macro_rules! validate_by_query {
    ($($op:ty),+) => {$(
        impl Validate for $op {
            fn validate(&self) -> Result<()> {
                self.query().map(|_| ())
            }
        }
    )+};
}
validate_by_query!(
    AtlasFind,
    AtlasRefs,
    AtlasImpact,
    AtlasChanges,
    AtlasOutline
);
fn scope(paths: &[RelativePath], languages: &[Language]) -> Result<SearchScope> {
    if paths.len() > 32 || languages.len() > 32 {
        return Err(SeError::invalid(
            "Atlas scope",
            "at most 32 registered relative paths and languages",
        ));
    }
    Ok(SearchScope {
        paths: paths.to_vec(),
        languages: languages.to_vec(),
    })
}
fn target(target: &AtlasTarget) -> Result<()> {
    if let AtlasTarget::Symbol(selector) = target {
        se_types::code::Validate.selector(selector.clone())?;
    }
    Ok(())
}
#[derive(Clone, Debug)]
pub enum AtlasRead {
    Find(AtlasFind),
    Refs(AtlasRefs),
    Impact(AtlasImpact),
    Changes(AtlasChanges),
    Outline(AtlasOutline),
}
impl AtlasRead {
    pub fn options(&self) -> &AtlasOptions {
        match self {
            Self::Find(v) => &v.options,
            Self::Refs(v) => &v.options,
            Self::Impact(v) => &v.options,
            Self::Changes(v) => &v.options,
            Self::Outline(v) => &v.options,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AtlasFindOutput {
    #[serde(flatten)]
    pub answer: Answer<Read<SearchResults>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AtlasRefsOutput {
    #[serde(flatten)]
    pub answer: Answer<Read<Page<ReferenceHit>>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AtlasImpactOutput {
    #[serde(flatten)]
    pub answer: Answer<Read<Impact>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AtlasChangesOutput {
    #[serde(flatten)]
    pub answer: Answer<Read<Page<CodeChange>>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AtlasOutlineOutput {
    #[serde(flatten)]
    pub answer: Answer<Read<Outline>>,
}

impl super::AnyOp {
    pub fn atlas_options(&self) -> Option<&AtlasOptions> {
        match self {
            Self::AtlasFind(v) => Some(&v.options),
            Self::AtlasRefs(v) => Some(&v.options),
            Self::AtlasImpact(v) => Some(&v.options),
            Self::AtlasChanges(v) => Some(&v.options),
            Self::AtlasOutline(v) => Some(&v.options),
            _ => None,
        }
    }
}
impl super::AnyOutput {
    /// Atlas exits: any real hit is 0 in every index state, and an empty answer
    /// is 0 only when complete. `require_complete` makes any gap 2, even with
    /// hits. Pagination is never a gap: a page or byte limit leaves a cursor,
    /// not missing results. Loose fallback guesses are never real hits.
    pub fn atlas_exit(&self, require_complete: bool) -> Option<u8> {
        Some(match self {
            Self::AtlasFind(v) => exit(&v.value.answer, require_complete, |s| {
                let (hits, gap) = page_facts(&s.page);
                let loose = matches!(s.mode, SearchMode::Broad | SearchMode::Related);
                let guess = loose && s.fallback_from.is_some();
                (if guess { 0 } else { hits }, gap)
            }),
            Self::AtlasRefs(v) => exit(&v.value.answer, require_complete, page_facts),
            Self::AtlasChanges(v) => exit(&v.value.answer, require_complete, page_facts),
            Self::AtlasImpact(v) => exit(&v.value.answer, require_complete, |i| {
                let hits = i.dependents.len() + i.tests.len() + i.records.len();
                (hits, !i.frontier_count_complete)
            }),
            Self::AtlasOutline(v) => exit(&v.value.answer, require_complete, |o| {
                (o.symbols.len() + o.records.len(), false)
            }),
            _ => return None,
        })
    }
}
/// Hits, and whether the page misses results its sources hold (unreadable or
/// incomplete), as opposed to one a page or byte limit cut short.
fn page_facts<T>(page: &Page<T>) -> (usize, bool) {
    (page.items().len(), page.window().exit_code(false) != 0)
}
/// `facts` gives the hit count and whether the family itself left a gap.
fn exit<T>(answer: &Answer<Read<T>>, required: bool, facts: impl Fn(&T) -> (usize, bool)) -> u8 {
    let index = &answer.index;
    let value = match &answer.data {
        Read::Present { value } => value,
        // An unknown target may still appear while the index builds: incomplete.
        // On a complete index it stays a refusal (unavailable or policy-denied).
        Read::Unknown { .. } if !index.negative_complete() => return 2,
        other => return other.exit_code(),
    };
    let (hits, gap) = facts(value);
    let complete = !gap
        && !answer.snapshot_advanced
        && index.negative_complete()
        && !index.coverage.reasons.contains(&CoverageReason::TimeLimit);
    if complete || (hits > 0 && !required) {
        0
    } else {
        2
    }
}
