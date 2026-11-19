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
        /// Optional kind filter; a lone type declaration wins over
        /// same-named non-declaration symbols when no kind or line is set.
        /// Absent filters omit from the wire so old cursors keep matching.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<SymbolKind>,
        /// Optional 1-based start line of the symbol definition.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        line: Option<u32>,
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
    Message,
    Working,
    Edit,
    Commit,
}
impl SearchKind {
    /// Symbol plans may use the full bounded query work allowance.
    pub fn query_budget(self, mut budget: QueryBudget) -> QueryBudget {
        if matches!(self, Self::All | Self::Code | Self::Symbol) {
            budget.work = Duration::from_millis(40);
        }
        budget
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_selector_filters_keep_the_pre_change_wire_shape()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let selector = SymbolSelector::Name {
            name: QueryText::new("Foo")?,
            path: None,
            container: None,
            kind: None,
            line: None,
        };
        // The exact bytes the pre-change selector emitted for the same query.
        let old_shape = br#"{"Name":{"name":"Foo","path":null,"container":null}}"#;
        let wire = serde_json::to_vec(&selector)?;
        assert_eq!(
            &wire[..],
            old_shape,
            "absent filters must omit from the wire so old refs and impact cursor digests keep matching"
        );
        let decoded: SymbolSelector = serde_json::from_slice(old_shape)?;
        assert_eq!(selector, decoded, "an old cursor's query must still decode");
        Ok(())
    }
    #[test]
    fn set_selector_filters_round_trip() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let selector = SymbolSelector::Name {
            name: QueryText::new("Foo")?,
            path: Some(RelativePath::new("foo.rs")?),
            container: None,
            kind: Some(SymbolKind::Struct),
            line: Some(12),
        };
        let wire = serde_json::to_value(&selector)?;
        assert_eq!(wire["Name"]["kind"], "Struct");
        assert_eq!(wire["Name"]["line"], 12);
        assert_eq!(wire["Name"]["container"], serde_json::Value::Null);
        let decoded: SymbolSelector = serde_json::from_value(wire)?;
        assert_eq!(decoded, selector);
        Ok(())
    }
}
