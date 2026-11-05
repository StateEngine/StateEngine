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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(try_from = "ScopeWire")]
pub struct SearchScope {
    /// Exact files or directories, including their descendants at path boundaries.
    pub paths: Vec<RelativePath>,
    pub languages: Vec<Language>,
}
impl SearchScope {
    pub fn validate(&self) -> crate::Result<()> {
        if self.paths.len() > 32
            || self.languages.len() > 32
            || self
                .paths
                .iter()
                .map(|p| p.as_str().len() + 1)
                .sum::<usize>()
                > 8192
        {
            return Err(crate::SeError::invalid(
                "Atlas scope",
                "at most 32 paths/languages and 8192 path bytes",
            ));
        }
        Ok(())
    }
    pub fn includes_path(&self, path: &RelativePath) -> bool {
        self.paths.is_empty()
            || self.paths.iter().any(|prefix| {
                path == prefix
                    || path
                        .as_str()
                        .strip_prefix(prefix.as_str())
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
    }
    pub fn packed_languages(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for language in &self.languages {
            let name = match language {
                Language::JavaScript => "JavaScript",
                Language::Jsx => "Jsx",
                Language::TypeScript => "TypeScript",
                Language::Tsx => "Tsx",
                Language::Rust => "Rust",
                Language::Python => "Python",
            };
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
        }
        bytes
    }
    pub fn packed_paths(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for path in &self.paths {
            bytes.extend_from_slice(path.as_str().as_bytes());
            bytes.push(0);
        }
        bytes
    }
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
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
#[serde(rename_all = "snake_case")]
pub enum SearchKind {
    All,
    Code,
    Symbol,
    Text,
    Path,
    Decision,
    Message,
    Working,
    Edit,
    Commit,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindQuery {
    pub kind: SearchKind,
    pub query: QueryText,
    pub scope: SearchScope,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
    /// None selects the documented automatic mode/fallback sequence.
    #[serde(default)]
    pub mode: Option<SearchMode>,
    #[serde(default)]
    pub order: SearchOrder,
    #[serde(default)]
    pub full: bool,
    #[serde(default)]
    pub regex: bool,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RefsQuery {
    pub target: AtlasTarget,
    pub kinds: Vec<ReferenceKind>,
    pub include_name_only: bool,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImpactQuery {
    pub target: AtlasTarget,
    pub depth: u8,
    pub include_name_only: bool,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum GitObjectId {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub enum ChangeBaseline {
    Cursor(AtlasCursor),
    ObservedCommit(GitObjectId),
    ObservedUnixMillis(i64),
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangesQuery {
    pub since: ChangeBaseline,
    pub scope: SearchScope,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
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
        let scope = Self {
            paths: v.paths,
            languages: v.languages,
        };
        scope.validate()?;
        Ok(scope)
    }
}
