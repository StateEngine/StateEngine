//! Linked record ranking rechecks core before any hit or count is retained.
use super::{
    candidates::{Candidate, Kind},
    *,
};
use rusqlite::params;
pub(super) struct RecordRow {
    pub key: Key,
    pub hit: RecordHit,
    cost: usize,
}
pub(super) struct RecordRows {
    pub rows: Vec<RecordRow>,
    pub limited: bool,
}
pub(super) fn collect(
    reader: &QueryReader<'_>,
    sql: &SqlView<'_>,
    snapshot: &Snapshot,
    files: &[i64],
    end: Instant,
) -> AtlasResult<RecordRows> {
    let mut output = RecordRows {
        rows: Vec::new(),
        limited: false,
    };
    let mut seen = Vec::with_capacity(512);
    let mut retained = 0;
    'files: for &file in files {
        let pointer = file_by_id(sql, file)?.pointer;
        for symbol in [false, true] {
            if Instant::now() >= end {
                output.limited = true;
                break 'files;
            }
            let ids = {
                let condition = if symbol {
                    "m.target_kind='symbol' AND m.target_key IN (SELECT key FROM symbols WHERE file=?1)"
                } else {
                    "m.target_kind='file' AND m.target_key=?2"
                };
                let mut stmt=sql.prepare(&format!("SELECT r.id FROM records r LEFT JOIN activity a ON a.target_kind='record' AND a.target_key=CAST(r.record_id AS BLOB) WHERE EXISTS(SELECT 1 FROM mentions m WHERE m.source_kind='record' AND m.source_id=r.id AND {condition}) ORDER BY a.last_touch_unix_ms DESC,r.record_id LIMIT 513"))?;
                let mut rows = if symbol {
                    stmt.query([file])
                } else {
                    stmt.query(params![rusqlite::types::Null, pointer.file.0.as_slice()])
                }
                .map_err(cache_error)?;
                let mut ids = Vec::new();
                while let Some(row) = rows.next().map_err(cache_error)? {
                    ids.push(get::<i64>(row, 0)?);
                }
                ids
            };
            for id in ids {
                if seen.contains(&id) {
                    continue;
                }
                if seen.len() == 512 || Instant::now() >= end {
                    output.limited = true;
                    break 'files;
                }
                seen.push(id);
                let pointer = super::candidates::record_pointer(sql, id)?;
                let hit = match reader.records.read(
                    &snapshot.index.project,
                    &reader.viewer,
                    &pointer,
                    None,
                )? {
                    Read::Present { value } if value.pointer == pointer => value,
                    Read::Absent { .. } => continue,
                    _ => return Err(cache_error("impact record authority unavailable")),
                };
                let activity = crate::rank::activity(
                    sql,
                    "record",
                    pointer.key.as_str().as_bytes(),
                    crate::rank::ActivityQuery {
                        project: &snapshot.index.project,
                        viewer: &reader.viewer,
                        records: reader.records,
                        now: reader.now_unix_ms,
                    },
                )?;
                let candidate = Candidate {
                    kind: Kind::Record,
                    rowid: id,
                    tier: 4,
                    key: pointer.key.as_str().as_bytes().to_vec(),
                    tie: pointer.key.as_str().into(),
                    activity,
                    precomputed_last: None,
                    lexical: 0.0,
                    related: true,
                };
                let mut key = super::find::key(&candidate, SearchOrder::Relevance);
                key.integers = vec![4, 2, key.integers[1]];
                let cost = size(&hit)? + key.bytes.len() + 96;
                retained += cost;
                output.rows.push(RecordRow { key, hit, cost });
                output.rows.sort_by(|a, b| {
                    (a.key.integers[2], &a.key.bytes).cmp(&(b.key.integers[2], &b.key.bytes))
                });
                while retained > 24_576 {
                    let row = output
                        .rows
                        .pop()
                        .ok_or_else(|| cache_error("record impact admission underflow"))?;
                    retained -= row.cost;
                    output.limited = true;
                }
            }
        }
    }
    Ok(output)
}
