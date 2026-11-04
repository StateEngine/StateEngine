//! Shared bounded Atlas query values; execution ports stay in se-atlas.
use super::*;
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(try_from = "BudgetWire")]
pub struct QueryBudget {
    pub max_results: u16,
    pub max_bytes: u32,
    pub work: Duration,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(try_from = "ScopeWire")]
pub struct SearchScope {
    pub paths: Vec<RelativePath>,
    pub languages: Vec<Language>,
}
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum SymbolSelector {
    Id(SymbolId),
    At {
        path: RelativePath,
        position: Position,
    },
    Name {
        name: QueryText,
        path: Option<RelativePath>,
        container: Option<QueryText>,
    },
}
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum SearchKind {
    Symbol,
    Text,
    Path,
}
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindQuery {
    pub kind: SearchKind,
    pub query: QueryText,
    pub scope: SearchScope,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RefsQuery {
    pub symbol: SymbolSelector,
    pub kinds: Vec<ReferenceKind>,
    pub include_name_only: bool,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImpactQuery {
    pub symbol: SymbolSelector,
    pub depth: u8,
    pub include_name_only: bool,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub enum GitObjectId {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub enum ChangeBaseline {
    Cursor(AtlasCursor),
    ObservedCommit(GitObjectId),
    ObservedUnixMillis(i64),
}
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangesQuery {
    pub since: ChangeBaseline,
    pub scope: SearchScope,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutlineQuery {
    pub path: RelativePath,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct BudgetWire {
    max_results: u16,
    max_bytes: u32,
    work: Duration,
}
impl TryFrom<BudgetWire> for QueryBudget {
    type Error = crate::SeError;
    fn try_from(v: BudgetWire) -> crate::Result<Self> {
        if !(1..=50).contains(&v.max_results)
            || !(1..=32768).contains(&v.max_bytes)
            || v.work.is_zero()
            || v.work > Duration::from_millis(40)
        {
            return Err(crate::SeError::invalid(
                "Atlas query budget",
                "1..50 results, 1..32768 bytes and at most 40 ms finite index work",
            ));
        }
        Ok(Self {
            max_results: v.max_results,
            max_bytes: v.max_bytes,
            work: v.work,
        })
    }
}
#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ScopeWire {
    paths: Vec<RelativePath>,
    languages: Vec<Language>,
}
impl TryFrom<ScopeWire> for SearchScope {
    type Error = crate::SeError;
    fn try_from(v: ScopeWire) -> crate::Result<Self> {
        if v.paths.len() > 32 || v.languages.len() > 32 {
            return Err(crate::SeError::invalid(
                "Atlas scope",
                "at most 32 paths/languages",
            ));
        }
        Ok(Self {
            paths: v.paths,
            languages: v.languages,
        })
    }
}
