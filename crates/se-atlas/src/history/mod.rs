//! Bounded Git metadata feed. Git authors never imply current-content authorship.
mod apply;
use crate::{
    errors::{AtlasResult, cache_error},
    model::*,
};
pub use apply::{apply, ingest};
use se_types::{ProjectId, code::AtlasText};
/// A source reconciliation does not fill an intentionally bounded Git seed.
/// Both hosted status and query readers retain that independent limitation.
pub fn limitation(
    sql: &crate::cache::connection::SqlView<'_>,
) -> AtlasResult<Option<CoverageReason>> {
    let coverage: String = sql
        .prepare("SELECT coverage_json FROM meta WHERE singleton=1")?
        .query_row([], |row| row.get(0))
        .map_err(cache_error)?;
    let coverage: Coverage = serde_json::from_str(&coverage).map_err(cache_error)?;
    if coverage.history_unavailable.is_some() {
        return Ok(Some(CoverageReason::HistoryUnavailable));
    }
    let saved: Option<String> = sql
        .prepare("SELECT history_bound FROM record_feed WHERE singleton=1")?
        .query_row([], |row| row.get(0))
        .map_err(cache_error)?;
    let Some(saved) = saved else { return Ok(None) };
    let bound: HistoryBound = serde_json::from_str(&saved).map_err(cache_error)?;
    bound.validate()?;
    Ok(bound.next.is_some().then_some(CoverageReason::ResultLimit))
}
pub const FEED_BYTES: usize = 65_536;
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryBound {
    pub head: String,
    pub oldest: Option<String>,
    pub next: Option<String>,
    pub limit: HistoryLimit,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum HistoryLimit {
    Complete,
    CommitCount,
    Bytes,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub oid: String,
    pub parent: Option<String>,
    pub author_unix_ms: i64,
    pub author: String,
    pub subject: String,
    pub paths: Vec<RelativePath>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryFeed {
    pub project: ProjectId,
    pub root: RootId,
    pub expected: Option<HistoryBound>,
    pub bound: HistoryBound,
    pub observed_unix_ms: i64,
    pub commits: Vec<Commit>,
}
#[derive(Debug)]
pub struct HistoryReceipt {
    pub changed: u32,
    pub denied_paths: u32,
    pub generation: Generation,
    pub replay: bool,
}
pub(super) fn object(value: &str) -> AtlasResult<Vec<u8>> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(cache_error(
            "Git history requires complete lowercase SHA-1/SHA-256 object IDs",
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|b| {
            let h = (b[0] as char)
                .to_digit(16)
                .ok_or_else(|| cache_error("invalid Git object ID"))?;
            let l = (b[1] as char)
                .to_digit(16)
                .ok_or_else(|| cache_error("invalid Git object ID"))?;
            Ok((h * 16 + l) as u8)
        })
        .collect()
}
impl HistoryBound {
    fn validate(&self) -> AtlasResult<()> {
        object(&self.head)?;
        for id in [&self.oldest, &self.next].into_iter().flatten() {
            object(id)?;
            if id.len() != self.head.len() {
                return Err(cache_error("Git history object formats differ"));
            }
        }
        if (self.limit == HistoryLimit::Complete) != self.next.is_none() {
            return Err(cache_error(
                "Git history coverage reason must match its explicit continuation",
            ));
        }
        Ok(())
    }
}
impl HistoryFeed {
    pub fn validate(&self) -> AtlasResult<()> {
        self.bound.validate()?;
        if let Some(bound) = &self.expected {
            bound.validate()?;
        }
        if self.commits.is_empty()
            || self.commits.len() > 4
            || self.commits.iter().map(|c| c.paths.len()).sum::<usize>() > 32
        {
            return Err(cache_error(
                "Git writer quantum requires 1..4 complete commits and at most 32 changed paths; request a smaller history window or retain source-only coverage",
            ));
        }
        let mut bytes = self.commits.capacity() * std::mem::size_of::<Commit>();
        for (n, commit) in self.commits.iter().enumerate() {
            object(&commit.oid)?;
            if commit.oid.len() != self.bound.head.len()
                || commit.author.len() > 512
                || commit.subject.len() > 1024
                || commit.author.contains('\0')
                || commit.subject.contains('\0')
                || commit.paths.len() > 256
            {
                return Err(cache_error(
                    "Git commit exceeds its complete bounded metadata contract",
                ));
            }
            if let Some(parent) = &commit.parent {
                object(parent)?;
                if parent.len() != commit.oid.len() {
                    return Err(cache_error("Git parent uses another object format"));
                }
            }
            if n + 1 < self.commits.len()
                && commit.parent.as_deref() != Some(self.commits[n + 1].oid.as_str())
            {
                return Err(cache_error(
                    "Git feed must be a contiguous first-parent window",
                ));
            }
            bytes = bytes.saturating_add(
                commit.oid.capacity()
                    + commit.parent.as_ref().map_or(0, String::capacity)
                    + commit.author.capacity()
                    + commit.subject.capacity()
                    + commit.paths.capacity() * std::mem::size_of::<RelativePath>()
                    + commit.paths.iter().map(|p| p.as_str().len()).sum::<usize>(),
            );
        }
        let first = &self.commits[0];
        let expected_start = self
            .expected
            .as_ref()
            .filter(|b| b.head == self.bound.head)
            .and_then(|b| b.next.as_deref())
            .unwrap_or(&self.bound.head);
        if first.oid != expected_start
            || self.bound.oldest.as_deref() != self.commits.last().map(|c| c.oid.as_str())
            || self.commits.last().and_then(|c| c.parent.as_deref()) != self.bound.next.as_deref()
        {
            return Err(cache_error(
                "Git history bounds do not describe the complete input window",
            ));
        }
        if bytes > FEED_BYTES {
            return Err(crate::errors::capacity(
                "Git history feed bytes",
                bytes as u64,
                FEED_BYTES as u64,
            ));
        }
        Ok(())
    }
}
