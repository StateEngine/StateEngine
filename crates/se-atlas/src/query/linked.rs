//! Record candidates are never output or counted until core rechecks the authority.
use super::*;
use rusqlite::params;
pub(super) struct Linked {
    pub items: Vec<RecordHit>,
    pub last: Option<Key>,
    pub more: bool,
}
pub(super) fn time_key(time: i64) -> u64 {
    (time as u64) ^ (1 << 63)
}
pub(super) fn from_time_key(time: u64) -> i64 {
    (time ^ (1 << 63)) as i64
}
pub(super) struct LinkedRequest<'a> {
    pub file: &'a CodePointer,
    pub limit: usize,
    pub bytes: usize,
    pub after: Option<&'a Key>,
    pub query: Option<&'a QueryText>,
    pub end: Instant,
}
pub(super) fn for_file(
    reader: &QueryReader<'_>,
    sql: &SqlView<'_>,
    snapshot: &Snapshot,
    request: LinkedRequest<'_>,
) -> AtlasResult<Linked> {
    let LinkedRequest {
        file,
        limit,
        bytes,
        after,
        query,
        end,
    } = request;
    let mut stmt = sql.prepare("SELECT r.record_id,r.kind,r.source_event,r.occurred_unix_ms FROM records r WHERE EXISTS (SELECT 1 FROM mentions m WHERE m.source_kind='record' AND m.source_id=r.id AND ((m.target_kind='file' AND m.target_key=?1) OR (m.target_kind='symbol' AND m.target_key IN (SELECT s.key FROM symbols s JOIN files f ON f.id=s.file WHERE f.key=?1)))) AND (?2=0 OR r.occurred_unix_ms<?3 OR (r.occurred_unix_ms=?3 AND r.record_id>?4)) ORDER BY r.occurred_unix_ms DESC,r.record_id LIMIT 513")?;
    let mut rows = stmt
        .query(params![
            file.file.0.as_slice(),
            after.is_some(),
            after.map_or(0, |k| from_time_key(k.integers[1])),
            after
                .map(|k| std::str::from_utf8(&k.bytes).map_err(cursor::invalid))
                .transpose()?
                .unwrap_or("")
        ])
        .map_err(cache_error)?;
    let mut output = Linked {
        items: Vec::new(),
        last: None,
        more: false,
    };
    let mut used = 0;
    let mut scanned = 0;
    while let Some(row) = rows.next().map_err(cache_error)? {
        if scanned == 512 || Instant::now() >= end {
            output.more = true;
            break;
        }
        scanned += 1;
        let pointer = RecordPointer {
            key: RecordKey::new(get::<String>(row, 0)?)?,
            kind: tag(get(row, 1)?)?,
            source_event: get::<String>(row, 2)?.parse()?,
        };
        let key = Key {
            integers: vec![1, time_key(get(row, 3)?)],
            bytes: pointer.key.as_str().as_bytes().to_vec(),
        };
        match reader
            .records
            .read(&snapshot.index.project, &reader.viewer, &pointer, query)?
        {
            Read::Present { value } => {
                if value.pointer != pointer || value.line.len() > 160 || value.mentions.len() > 256
                {
                    return Err(cache_error(
                        "core record read disagrees with its pointer or bounded contract",
                    ));
                }
                let cost = size(&value)?;
                if output.items.len() == limit || used + cost + 1200 > bytes {
                    output.more = true;
                    break;
                }
                used += cost;
                output.items.push(value);
            }
            Read::Absent { .. } => (),
            Read::Unknown { .. } => {
                return Err(cache_error(
                    "record authority could not establish visibility",
                ));
            }
            Read::Unreadable { source, reason, .. } => {
                return Err(cache_error(format!("record authority {source}: {reason}")));
            }
        }
        output.last = Some(key);
    }
    Ok(output)
}
