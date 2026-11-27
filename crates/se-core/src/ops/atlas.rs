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
    /// Inspect applies it as every section's cap (defaults 100, 20, 20, 10).
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
// Inspect: one pre-edit call over the outline, refs, impact and changes
// answers for one target, each keeping its own coverage and cursor.
/// How far back inspect lists observed edits to the target's file.
pub const INSPECT_RECENT_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Smallest whole budget: every section keeps at least the per-family minimum.
pub const INSPECT_MIN_BYTES: u32 = 8192;
/// Shares of the byte budget, in sixteenths, and default page sizes.
const OUTLINE: (u32, u16) = (4, 60);
const REFS: (u32, u16) = (4, 20);
const IMPACT: (u32, u16) = (5, 20);
const CHANGES: (u32, u16) = (3, 10);

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AtlasInspect {
    pub target: AtlasTarget,
    #[serde(flatten)]
    pub options: AtlasOptions,
}

/// The bounded queries one inspect runs, each built for a page size so a
/// compact answer can shrink a section until it fits its share. Outline and
/// changes need the target's defining file, which only the index can name.
pub struct InspectQueries {
    target: AtlasTarget,
    /// Outline, refs, impact and changes, in output order.
    budgets: [QueryBudget; 4],
}

impl InspectQueries {
    /// Each section's requested page size, in output order.
    pub fn limits(&self) -> [u16; 4] {
        self.budgets.map(|budget| budget.max_results)
    }
    fn budget(&self, section: usize, limit: u16) -> QueryBudget {
        QueryBudget {
            max_results: limit,
            ..self.budgets[section]
        }
    }
    pub fn outline(&self, path: RelativePath, limit: u16) -> OutlineQuery {
        OutlineQuery {
            path,
            next: None,
            budget: self.budget(0, limit),
        }
    }
    pub fn refs(&self, limit: u16) -> RefsQuery {
        RefsQuery {
            target: self.target.clone(),
            kinds: Vec::new(),
            include_name_only: true,
            next: None,
            budget: self.budget(1, limit),
        }
    }
    pub fn impact(&self, limit: u16) -> ImpactQuery {
        ImpactQuery {
            target: self.target.clone(),
            depth: 2,
            include_name_only: false,
            next: None,
            budget: self.budget(2, limit),
        }
    }
    pub fn changes(&self, path: RelativePath, limit: u16) -> ChangesQuery {
        ChangesQuery {
            since: ChangeBaseline::RelativeMillis(INSPECT_RECENT_MS),
            scope: SearchScope {
                paths: vec![path],
                languages: Vec::new(),
            },
            next: None,
            budget: self.budget(3, limit),
        }
    }
}

impl AtlasInspect {
    pub fn query(&self) -> Result<InspectQueries> {
        if self.options.cursor.is_some() {
            return Err(SeError::invalid(
                "Atlas inspect cursor",
                "no cursor; continue one section with se atlas outline, refs, impact or changes --cursor",
            ));
        }
        if self.options.byte_budget < INSPECT_MIN_BYTES {
            return Err(SeError::invalid(
                "Atlas inspect byte_budget",
                "8192..262144 UTF-8 bytes, shared by its four sections",
            ));
        }
        if let AtlasTarget::Symbol(selector) = &self.target {
            se_types::code::Validate.selector(selector.clone())?;
        }
        let compact = self.options.format == AtlasFormat::Compact;
        let section = |(share, limit): (u32, u16), max: (u16, u16)| -> Result<QueryBudget> {
            let mut budget = AtlasOptions {
                byte_budget: self.options.byte_budget / 16 * share,
                limit: Some(self.options.limit.unwrap_or(limit).min(max.1)),
                ..self.options.clone()
            }
            .budget(max)?;
            if compact {
                // Typed JSON is several times its compact rendering; the
                // compact share is fitted separately, as find does.
                budget.max_bytes = budget.max_bytes.saturating_mul(4).min(ATLAS_MAX_BYTES);
            }
            Ok(budget)
        };
        Ok(InspectQueries {
            target: self.target.clone(),
            budgets: [
                section(OUTLINE, ATLAS_OUTLINE_PAGE)?,
                section(REFS, ATLAS_LIST_PAGE)?,
                section(IMPACT, ATLAS_LIST_PAGE)?,
                section(CHANGES, ATLAS_LIST_PAGE)?,
            ],
        })
    }
    /// The byte share each section renders into, in output order.
    pub fn shares(max: usize) -> [usize; 4] {
        [OUTLINE.0, REFS.0, IMPACT.0, CHANGES.0].map(|share| max / 16 * share as usize)
    }
    /// The shares a compact answer is fitted to: the smallest text budget any
    /// surface renders it into. `None` for JSON, which the query budget bounds.
    pub fn compact_shares(&self) -> Option<[usize; 4]> {
        (self.options.format == AtlasFormat::Compact)
            .then(|| Self::shares(self.options.byte_budget.saturating_sub(256) as usize))
    }
}

impl Validate for AtlasInspect {
    fn validate(&self) -> Result<()> {
        self.query().map(|_| ())
    }
}

/// Each section is the matching single-family answer. Outline and changes
/// are `Unknown`, with the reason, when the target has no single defining file.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AtlasInspectOutput {
    /// Declarations and linked records of the defining file.
    pub outline: Answer<Read<Outline>>,
    /// Callers and other references, including labelled name-only candidates.
    pub refs: Answer<Read<Page<ReferenceHit>>>,
    /// Dependents up to two hops, possible covering tests and linked records.
    pub impact: Answer<Read<Impact>>,
    /// Edits Atlas observed to the defining file in the last seven days, with
    /// the captured agent when one is known.
    pub changes: Answer<Read<Page<CodeChange>>>,
}
#[derive(Clone, Debug)]
pub enum AtlasRead {
    Find(AtlasFind),
    Inspect(AtlasInspect),
    Refs(AtlasRefs),
    Impact(AtlasImpact),
    Changes(AtlasChanges),
    Outline(AtlasOutline),
}
impl AtlasRead {
    pub fn options(&self) -> &AtlasOptions {
        match self {
            Self::Find(v) => &v.options,
            Self::Inspect(v) => &v.options,
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
            Self::AtlasInspect(v) => Some(&v.options),
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
            Self::AtlasImpact(v) => exit(&v.value.answer, require_complete, impact_facts),
            Self::AtlasOutline(v) => exit(&v.value.answer, require_complete, outline_facts),
            // Refs and impact always apply; outline and changes count only
            // when the target has one defining file to read them from.
            Self::AtlasInspect(v) => {
                let v = &v.value;
                let mut codes = vec![
                    exit(&v.refs, require_complete, page_facts),
                    exit(&v.impact, require_complete, impact_facts),
                ];
                if matches!(v.outline.data, Read::Present { .. }) {
                    codes.push(exit(&v.outline, require_complete, outline_facts));
                }
                if matches!(v.changes.data, Read::Present { .. }) {
                    codes.push(exit(&v.changes, require_complete, page_facts));
                }
                let worst = codes.iter().copied().max().unwrap_or(0);
                if require_complete || !codes.contains(&0) {
                    worst
                } else {
                    0
                }
            }
            _ => return None,
        })
    }
}
fn impact_facts(impact: &Impact) -> (usize, bool) {
    let hits = impact.dependents.len() + impact.tests.len() + impact.records.len();
    (hits, !impact.frontier_count_complete)
}
fn outline_facts(outline: &Outline) -> (usize, bool) {
    (outline.symbols.len() + outline.records.len(), false)
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
