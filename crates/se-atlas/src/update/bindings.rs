//! Stream export identities and resolved re-export bindings without retaining a
//! second graph. Own import rowids are excluded so replacement converges;
//! interned names and target rowids identify the actual retained SQL bindings.
use super::*;
use rusqlite::types::ValueRef;
pub(super) fn fingerprint(sql: &SqlView<'_>, file: i64) -> AtlasResult<[u8; 32]> {
    let mut hash = blake3::Hasher::new();
    let visible: bool = value(
        sql,
        "SELECT coverage_json='\"Indexed\"' FROM files WHERE id=?1",
        [file],
    )?;
    hash.update(&[u8::from(visible)]);
    if !visible {
        return Ok(*hash.finalize().as_bytes());
    }
    for statement in [
        "SELECT key,name,kind,export_alias FROM symbols WHERE file=?1 AND exported=1 ORDER BY key",
        "SELECT spelling,local_name,imported_name,target_file,target_symbol,kind,lexical_scope,wildcard,target_namespace FROM imports WHERE file=?1 AND reexport=1 ORDER BY start_byte,end_byte,spelling",
    ] {
        hash.update(&[0xff]);
        let mut query = sql.prepare(statement)?;
        let columns = query.column_count();
        let mut rows = query.query([file]).map_err(cache_error)?;
        while let Some(row) = rows.next().map_err(cache_error)? {
            hash.update(&[0xfe]);
            for column in 0..columns {
                match row.get_ref(column).map_err(cache_error)? {
                    ValueRef::Null => {
                        hash.update(&[0]);
                    }
                    ValueRef::Integer(value) => {
                        hash.update(&[1]);
                        hash.update(&value.to_le_bytes());
                    }
                    ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
                        hash.update(&[2]);
                        hash.update(&(bytes.len() as u64).to_le_bytes());
                        hash.update(bytes);
                    }
                    ValueRef::Real(_) => return Err(cache_error("floating-point export identity")),
                }
            }
        }
    }
    Ok(*hash.finalize().as_bytes())
}
