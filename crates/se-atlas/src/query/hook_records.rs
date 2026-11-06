//! Current-fence, index-only samples. No record IDs, text or authority reads.
use super::*;
#[derive(Default)]
pub struct LinkedSample {
    pub decisions: u8,
    pub messages: u8,
}
pub(super) fn sample(
    reader: &QueryReader<'_>,
    sql: &SqlView<'_>,
    file: &FileId,
    symbol: Option<&SymbolId>,
) -> AtlasResult<LinkedSample> {
    let mut sample = LinkedSample::default();
    if !reader.record_feed_current {
        return Ok(sample);
    }
    // Cap each covering-index walk before the join/deduplication. A popular
    // file cannot require sorting all its historical links on a hook path.
    let mut statement = sql.prepare("WITH ids AS (SELECT source_id FROM (SELECT source_id FROM mentions WHERE target_kind='file' AND target_key=?1 AND source_kind='record' LIMIT 16) UNION SELECT source_id FROM (SELECT source_id FROM mentions WHERE target_kind='symbol' AND target_key=?2 AND source_kind='record' LIMIT 16)) SELECT r.id,r.kind,r.visibility,r.audience FROM ids JOIN records r ON r.id=ids.source_id WHERE r.kind IN ('decision','message') LIMIT 16")?;
    let mut rows = statement
        .query(params![file.0.as_slice(), symbol.map(|s| s.0.as_slice())])
        .map_err(cache_error)?;
    while let Some(row) = rows.next().map_err(cache_error)? {
        let visibility: String = get(row, 2)?;
        let allowed = match visibility.as_str() {
            "project" => true,
            "restricted" if matches!(reader.viewer, AtlasPrincipal::Human(_)) => true,
            "restricted" => {
                let audience: Option<Vec<u8>> = get(row, 3)?;
                match audience {
                    Some(bytes) if bytes.len() <= 4096 => {
                        let keys: Vec<AtlasPrincipal> =
                            serde_json::from_slice(&bytes).map_err(cache_error)?;
                        if keys.len() > 32 || keys.windows(2).any(|p| p[0] >= p[1]) {
                            return Err(cache_error("invalid hook audience hints"));
                        }
                        keys.binary_search(&reader.viewer).is_ok()
                    }
                    _ => false,
                }
            }
            _ => return Err(cache_error("unknown hook record visibility")),
        };
        if allowed {
            match get::<String>(row, 1)?.as_str() {
                "decision" => sample.decisions += 1,
                "message" => sample.messages += 1,
                _ => return Err(cache_error("unexpected linked record kind")),
            }
        }
    }
    Ok(sample)
}
