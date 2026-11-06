//! Bounded query inputs shared by the CLI, MCP and native host read port.
use super::inputs::Validate;
use schemars::JsonSchema;
use se_types::{Page, Read, Result, SeError, code::*};
use serde::{Deserialize, Serialize};
fn limit() -> u16 {
    10
}
fn bytes() -> u32 {
    4096
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
    #[serde(default = "limit")]
    pub limit: u16,
    #[serde(default = "bytes")]
    pub byte_budget: u32,
    #[serde(default)]
    pub format: AtlasFormat,
    #[serde(default)]
    pub explain: bool,
}
impl AtlasOptions {
    pub fn budget(&self) -> Result<QueryBudget> {
        if !(1024..=32768).contains(&self.byte_budget) {
            return Err(SeError::invalid(
                "Atlas byte_budget",
                "1024..32768 UTF-8 bytes including the response envelope",
            ));
        }
        // The reader measures Answer<Read<T>>; reserve the family's envelope.
        se_types::code::Validate.query_budget(self.limit, self.byte_budget - 192)
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
                let mut budget = self.options.budget()?;
                if self.options.format == AtlasFormat::Compact
                    && matches!(
                        self.kind,
                        SearchKind::All | SearchKind::Code | SearchKind::Text
                    )
                {
                    // Compact source hits need room for typed pointer metadata;
                    // the reader separately fits the exact rendered byte budget.
                    budget.max_bytes = budget.max_bytes.saturating_mul(4).min(32768);
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
        if !matches!(self.target, AtlasTarget::Symbol(_) | AtlasTarget::File(_))
            || self.kinds.len() > 5
        {
            return Err(SeError::invalid(
                "Atlas refs target",
                "a symbol or file and at most five reference kinds",
            ));
        }
        target(&self.target)?;
        Ok(RefsQuery {
            target: self.target.clone(),
            kinds: self.kinds.clone(),
            include_name_only: self.include_name_only,
            next: self.options.cursor.clone(),
            budget: self.options.budget()?,
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
            budget: self.options.budget()?,
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
            budget: self.options.budget()?,
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
            budget: self.options.budget()?,
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
pub(super) fn page_exit<T>(data: &Read<Page<T>>) -> u8 {
    match data {
        Read::Present { value } => value.window().exit_code(false),
        _ => data.exit_code(),
    }
}
pub(super) fn complete_exit<T>(data: &Read<T>, complete: impl FnOnce(&T) -> bool) -> u8 {
    match data {
        Read::Present { value } => {
            if complete(value) {
                0
            } else {
                2
            }
        }
        _ => data.exit_code(),
    }
}
