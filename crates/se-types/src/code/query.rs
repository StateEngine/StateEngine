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
/// Atlas page ceilings: results, response bytes and the soft work budget after
/// which a query returns what it has collected instead of failing.
pub const ATLAS_MAX_RESULTS: u16 = 2000;
pub const ATLAS_MAX_BYTES: u32 = 262_144;
pub const ATLAS_SOFT_WORK: Duration = Duration::from_millis(250);
/// `(default, max)` page sizes: find, the refs/impact/changes lists, outline.
pub const ATLAS_FIND_PAGE: (u16, u16) = (20, 200);
pub const ATLAS_LIST_PAGE: (u16, u16) = (50, 500);
pub const ATLAS_OUTLINE_PAGE: (u16, u16) = (300, ATLAS_MAX_RESULTS);
/// The longest inline record excerpt line an Atlas hit carries.
pub const RECORD_LINE_BYTES: usize = 280;

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
#[serde(try_from = "BaselineWire")]
pub enum ChangeBaseline {
    Cursor(AtlasCursor),
    ObservedCommit(GitObjectId),
    /// A short lowercase hexadecimal commit prefix, resolved against observed commits.
    ObservedCommitPrefix(String),
    ObservedUnixMillis(i64),
}
/// A typed baseline, or the text a person types: `10m`, `2026-11-20T09:30Z`, a
/// commit SHA or 7+ hex prefix, an Atlas cursor, or 13+ digit Unix milliseconds.
#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
enum BaselineWire {
    Text(String),
    Typed(#[serde(with = "TypedBaseline")] ChangeBaseline),
}
#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(remote = "ChangeBaseline")]
#[schemars(rename = "TypedChangeBaseline")]
enum TypedBaseline {
    Cursor(AtlasCursor),
    ObservedCommit(GitObjectId),
    ObservedCommitPrefix(String),
    ObservedUnixMillis(i64),
}
impl TryFrom<BaselineWire> for ChangeBaseline {
    type Error = crate::SeError;
    fn try_from(wire: BaselineWire) -> crate::Result<Self> {
        match wire {
            BaselineWire::Typed(typed) => Ok(typed),
            BaselineWire::Text(text) => Self::from_text(&text),
        }
    }
}
impl ChangeBaseline {
    /// [`Self::parse`] against the wall clock, for the CLI and MCP alike.
    pub fn from_text(text: &str) -> crate::Result<Self> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        Self::parse(text, now)
    }
    /// Read a baseline as typed by a person, relative to `now_ms` for durations.
    /// Digit runs of 7..=12 are commit prefixes; Unix milliseconds have 13+ digits.
    pub fn parse(text: &str, now_ms: i64) -> crate::Result<Self> {
        let invalid = || {
            crate::SeError::invalid(
                "since",
                "a duration such as 10m, an ISO UTC time such as 2026-11-20T09:30Z, a commit SHA or 7+ hex prefix, an Atlas cursor or 13+ digit Unix milliseconds",
            )
        };
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if digits(text) && (13..=19).contains(&text.len()) {
            return text
                .parse()
                .map(Self::ObservedUnixMillis)
                .map_err(|_| invalid());
        }
        if (7..=64).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_hexdigit()) {
            let bytes = crate::decode_hex(text).unwrap_or_default();
            let full = match text.len() {
                40 => bytes.try_into().ok().map(GitObjectId::Sha1),
                64 => bytes.try_into().ok().map(GitObjectId::Sha256),
                _ => return Ok(Self::ObservedCommitPrefix(text.to_ascii_lowercase())),
            };
            return full.map(Self::ObservedCommit).ok_or_else(invalid);
        }
        let scale = match text.as_bytes().last() {
            Some(b's') => 1_000,
            Some(b'm') => 60_000,
            Some(b'h') => 3_600_000,
            Some(b'd') => 86_400_000,
            _ => 0,
        };
        let count = &text[..text.len().saturating_sub(1)];
        if scale > 0 && digits(count) {
            let ago = count.parse::<i64>().ok().and_then(|n| n.checked_mul(scale));
            return Ok(Self::ObservedUnixMillis(
                now_ms.saturating_sub(ago.ok_or_else(invalid)?),
            ));
        }
        if let Some(time) = iso_millis(text) {
            return Ok(Self::ObservedUnixMillis(time));
        }
        // Cursors carry a 32-byte digest, so a short word is a typo, not a cursor.
        let cursor = (text.len() >= 43).then(|| AtlasCursor::new(text).ok());
        cursor.flatten().map(Self::Cursor).ok_or_else(invalid)
    }
}
/// `YYYY-MM-DD[THH:MM[:SS]][Z]`, read as UTC.
fn iso_millis(text: &str) -> Option<i64> {
    let text = text.strip_suffix('Z').unwrap_or(text);
    let (date, time) = text.split_once(['T', ' ']).unwrap_or((text, "00:00"));
    let num = |s: &str, len: usize| {
        (s.len() == len && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse::<i64>().ok())?
    };
    let (mut d, mut t) = (date.split('-'), time.split(':'));
    let (y, m, day) = (num(d.next()?, 4)?, num(d.next()?, 2)?, num(d.next()?, 2)?);
    let (h, min) = (num(t.next()?, 2)?, num(t.next()?, 2)?);
    let s = t.next().map_or(Some(0), |s| num(s, 2))?;
    let valid = (1..=12).contains(&m) && (1..=31).contains(&day) && h < 24 && min < 60 && s <= 60;
    if !valid || d.next().is_some() || t.next().is_some() {
        return None;
    }
    // Days from the civil calendar, March-based so leap days fall last.
    let y = if m <= 2 { y - 1 } else { y };
    let (era, yoe) = (y.div_euclid(400), y.rem_euclid(400));
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    Some(((days * 24 + h) * 60 + min) * 60_000 + s * 1_000)
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
impl QueryBudget {
    /// Every Atlas budget meets these ceilings, however it was built.
    pub fn checked(self) -> crate::Result<Self> {
        if !(1..=ATLAS_MAX_RESULTS).contains(&self.max_results)
            || !(1..=ATLAS_MAX_BYTES).contains(&self.max_bytes)
            || self.work.is_zero()
            || self.work > ATLAS_SOFT_WORK
        {
            return Err(crate::SeError::invalid(
                "Atlas query budget",
                "1..2000 results, 1..262144 bytes and at most 250 ms soft index work",
            ));
        }
        Ok(self)
    }
}
impl TryFrom<BudgetWire> for QueryBudget {
    type Error = crate::SeError;
    fn try_from(v: BudgetWire) -> crate::Result<Self> {
        let (max_results, max_bytes, work) = (v.max_results, v.max_bytes, v.work);
        Self {
            max_results,
            max_bytes,
            work,
        }
        .checked()
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
