//! Pure constructors shared by CLI, MCP and Atlas; scope/payload checks follow at query time.
use super::*;
use crate::{Result, SeError};
#[derive(Clone, Copy, Debug, Default)]
pub struct Validate;
impl AtlasValidation for Validate {
    fn relative_path(&self, value: String) -> Result<RelativePath> {
        RelativePath::new(value)
    }
    fn query_text(&self, value: String) -> Result<QueryText> {
        QueryText::new(value)
    }
    fn cursor(&self, value: String) -> Result<AtlasCursor> {
        AtlasCursor::new(value)
    }
    fn query_budget(&self, results: u16, bytes: u32) -> Result<QueryBudget> {
        if !(1..=50).contains(&results) || !(1..=32768).contains(&bytes) {
            return Err(SeError::invalid(
                "Atlas budget",
                "1..50 results and 1..32768 output bytes",
            ));
        }
        Ok(QueryBudget {
            max_results: results,
            max_bytes: bytes,
            work: Duration::from_millis(25),
        })
    }
    fn selector(&self, value: SymbolSelector) -> Result<SymbolSelector> {
        if matches!(&value, SymbolSelector::At {position, ..} if position.line == 0) {
            return Err(SeError::invalid("Atlas position", "a 1-based line"));
        }
        Ok(value)
    }
}
impl RelativePath {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let drive = value.as_bytes().get(1) == Some(&b':');
        if value.is_empty()
            || value.len() > 4096
            || value.contains(['\0', '\\', ':'])
            || drive
            || value
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == ".." || windows_ambiguous(p))
        {
            return Err(SeError::invalid(
                "Atlas path",
                "1..4096 UTF-8 bytes, relative slash-separated portable components without dot, dot-dot, NUL, colon, device names or trailing dot/space",
            ));
        }
        Ok(Self(value))
    }
}
fn windows_ambiguous(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or("");
    let stem = stem.to_ascii_uppercase();
    component.ends_with(['.', ' '])
        || matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        )
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|n| {
                matches!(
                    n,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        })
}
impl QueryText {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > 1024 || value.contains('\0') {
            return Err(SeError::invalid(
                "Atlas query",
                "1..1024 UTF-8 bytes, nonblank and without NUL",
            ));
        }
        Ok(Self(value))
    }
}
impl AtlasCursor {
    /// Bounded base64url envelope only. The query reader checks canonical JSON,
    /// version, mode, root/epoch, viewer digest and retention before using it.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 4096
            || value.len() % 4 == 1
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(SeError::invalid(
                "Atlas cursor",
                "at most 4096 unpadded base64url bytes",
            ));
        }
        Ok(Self(value))
    }
}
macro_rules! text {
    ($($ty:ty),+ $(,)?) => {$ (
        impl AtlasText for $ty { fn as_str(&self) -> &str { &self.0 } }
        impl TryFrom<String> for $ty { type Error = SeError;
            fn try_from(value: String) -> Result<Self> { Self::new(value) }
        }
        impl From<$ty> for String { fn from(value: $ty) -> Self { value.0 } }
    )+};
}
text!(RelativePath, QueryText, AtlasCursor);
