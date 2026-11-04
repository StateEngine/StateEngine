//! Read the old ledger's integrity facts without creating a Rust hash chain.
use super::source::SourceFile;
use crate::client::lease::Deadline;
use se_core::scope;
use se_types::{Read, Result};
use std::path::Path;
fn refused(reason: &str) -> se_types::SeError {
    scope::unreadable("Node ledger source integrity", reason)
}
pub(super) fn validate(path: &Path, deadline: &Deadline) -> Result<()> {
    let mut source = match SourceFile::open(path.to_path_buf(), None, deadline)? {
        Read::Absent { .. } => return Ok(()),
        Read::Present { value } => value,
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => return Err(refused(&what)),
    };
    let mut count = 0u64;
    let mut seq = 0u64;
    let mut v2 = false;
    let mut anchored = false;
    let mut previous_line = [0u8; 32];
    use sha2::{Digest, Sha256};
    let mut previous_prefix: [u8; 32] = Sha256::digest([]).into();
    while let Some(row) = source.next(deadline)? {
        let Some(value) = row.value else {
            if source.next(deadline)?.is_none() {
                source.verify(deadline)?;
                return Ok(());
            }
            return Err(refused(
                row.code
                    .unwrap_or("undecodable source row before later history"),
            ));
        };
        let next = value
            .get("seq")
            .and_then(serde_json::Value::as_u64)
            .filter(|n| *n > seq)
            .ok_or_else(|| refused("ledger sequence did not increase"))?;
        match value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
        {
            Some(1) if !v2 => (),
            Some(2) => {
                let events = value
                    .get("events")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| refused("ledger operation has no events array"))?;
                let anchors = events
                    .iter()
                    .filter(|e| {
                        e.get("type").and_then(serde_json::Value::as_str)
                            == Some("ledger.chain_anchor")
                    })
                    .collect::<Vec<_>>();
                if anchors.len() > 1 || anchored && !anchors.is_empty() {
                    return Err(refused("multiple source chain anchors"));
                }
                if let Some(anchor) = anchors.first() {
                    if v2
                        || count == 0
                        || anchor
                            .get("legacy_lines")
                            .and_then(serde_json::Value::as_u64)
                            != Some(count)
                        || anchor
                            .get("legacy_log_hash")
                            .and_then(serde_json::Value::as_str)
                            != Some(se_types::hex_lower(&previous_prefix).as_str())
                    {
                        return Err(refused(
                            "legacy source chain anchor does not seal its exact preceding bytes",
                        ));
                    }
                    anchored = true;
                }
                if !v2 && count > 0 && !anchored {
                    return Err(refused(
                        "first v2 row after legacy history is missing its source anchor",
                    ));
                }
                if value.get("prev_hash").and_then(serde_json::Value::as_str)
                    != Some(se_types::hex_lower(&previous_line).as_str())
                {
                    return Err(refused(
                        "source prev_hash differs from the exact previous raw line",
                    ));
                }
                v2 = true;
            }
            _ => return Err(refused("unsupported source ledger version or v1 after v2")),
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| refused("source row count overflow"))?;
        seq = next;
        previous_line = row.line_hash;
        previous_prefix = row.raw_prefix;
    }
    source.verify(deadline)
}
