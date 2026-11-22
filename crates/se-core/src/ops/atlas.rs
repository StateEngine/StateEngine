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
    /// `(default, max)` is the family's page size.
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
const PAGE: (u16, u16) = (50, 500);
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
                let mut budget = self.options.budget((20, 200))?;
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
impl Validate for AtlasFind {
    fn validate(&self) -> Result<()> {
        self.query().map(|_| ())
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
            budget: self.options.budget(PAGE)?,
        })
    }
}
impl Validate for AtlasRefs {
    fn validate(&self) -> Result<()> {
        self.query().map(|_| ())
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
            budget: self.options.budget(PAGE)?,
        })
    }
}
impl Validate for AtlasImpact {
    fn validate(&self) -> Result<()> {
        self.query().map(|_| ())
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
            budget: self.options.budget(PAGE)?,
        })
    }
}
impl Validate for AtlasChanges {
    fn validate(&self) -> Result<()> {
        self.query().map(|_| ())
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
            budget: self.options.budget((300, 2000))?,
        })
    }
}
impl Validate for AtlasOutline {
    fn validate(&self) -> Result<()> {
        self.query().map(|_| ())
    }
}
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
    /// Atlas exits, scoped to Atlas: any real hit is 0 in every index state; an
    /// empty answer is 0 only when complete and current, else 2. Loose fallback
    /// guesses are never real hits; `require_complete` turns any gap into 2.
    pub fn atlas_exit(&self, require_complete: bool) -> Option<u8> {
        let r = require_complete;
        Some(match self {
            Self::AtlasFind(v) => exit(&v.value.answer, r, |s| {
                let guess = matches!(s.mode, SearchMode::Broad | SearchMode::Related);
                let hits = if guess && s.fallback_from.is_some() {
                    0
                } else {
                    s.page.items().len()
                };
                (hits, s.page.window().complete())
            }),
            Self::AtlasRefs(v) => exit(&v.value.answer, r, page_hits),
            Self::AtlasChanges(v) => exit(&v.value.answer, r, page_hits),
            Self::AtlasImpact(v) => exit(&v.value.answer, r, |i| {
                let hits = i.dependents.len() + i.tests.len() + i.records.len();
                (hits, i.complete)
            }),
            Self::AtlasOutline(v) => exit(&v.value.answer, r, |o| {
                (o.symbols.len() + o.records.len(), o.complete)
            }),
            _ => return None,
        })
    }
}
fn page_hits<T>(page: &Page<T>) -> (usize, bool) {
    (page.items().len(), page.window().complete())
}
fn exit<T>(answer: &Answer<Read<T>>, require: bool, facts: impl Fn(&T) -> (usize, bool)) -> u8 {
    let Read::Present { value } = &answer.data else {
        return answer.data.exit_code();
    };
    let (hits, complete) = facts(value);
    let gaps = &answer.index.coverage.reasons;
    let complete = complete
        && matches!(answer.index.state, IndexState::Current)
        && !gaps.contains(&CoverageReason::TimeLimit);
    2 * u8::from(!complete && (hits == 0 || require))
}
