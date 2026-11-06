//! Decoding is fallible: damaged rows never disappear into an empty answer.
use super::*;
use rusqlite::Row;
use serde::de::DeserializeOwned;

pub(super) fn get<T: rusqlite::types::FromSql>(row: &Row<'_>, column: usize) -> AtlasResult<T> {
    match row.get_ref(column).map_err(cache_error)? {
        rusqlite::types::ValueRef::Text(bytes) | rusqlite::types::ValueRef::Blob(bytes)
            if bytes.len() > 8192 =>
        {
            return Err(cache_error("cache query field exceeds 8192 bytes"));
        }
        _ => (),
    }
    row.get(column).map_err(cache_error)
}
pub(super) fn json<T: DeserializeOwned>(text: &str) -> AtlasResult<T> {
    serde_json::from_str(text).map_err(cache_error)
}
pub(super) fn tag<T: DeserializeOwned>(text: String) -> AtlasResult<T> {
    serde_json::from_value(serde_json::Value::String(text)).map_err(cache_error)
}
pub(super) fn blob<const N: usize>(row: &Row<'_>, column: usize) -> AtlasResult<[u8; N]> {
    get::<Vec<u8>>(row, column)?
        .try_into()
        .map_err(|_| cache_error("invalid cache key/hash length"))
}
pub(super) fn optional_blob<const N: usize>(
    row: &Row<'_>,
    column: usize,
) -> AtlasResult<Option<[u8; N]>> {
    get::<Option<Vec<u8>>>(row, column)?
        .map(|v| {
            v.try_into()
                .map_err(|_| cache_error("invalid optional key/hash length"))
        })
        .transpose()
}
pub(super) fn span(row: &Row<'_>, start: usize) -> AtlasResult<Span> {
    let span = Span {
        start_byte: number(row, start)?,
        end_byte: number(row, start + 1)?,
        start: Position {
            line: get(row, start + 2)?,
            byte_column: get(row, start + 3)?,
        },
        end: Position {
            line: get(row, start + 4)?,
            byte_column: get(row, start + 5)?,
        },
    };
    if span.start.line == 0
        || span.end.line == 0
        || span.start_byte > span.end_byte
        || (span.start.line, span.start.byte_column) > (span.end.line, span.end.byte_column)
    {
        return Err(cache_error("invalid source span"));
    }
    Ok(span)
}
pub(super) struct FileRow {
    pub rowid: i64,
    pub pointer: CodePointer,
    pub coverage: FileCoverage,
    pub language: Option<Language>,
}
pub(super) const FILE_COLUMNS: &str = "f.id,f.key,f.path,f.indexed_hash,f.coverage_json,f.language";
pub(super) fn file(row: &Row<'_>, start: usize) -> AtlasResult<FileRow> {
    let coverage: FileCoverage = json(&get::<String>(row, start + 4)?)?;
    let freshness = match &coverage {
        FileCoverage::Indexed => SnapshotFreshness::Current,
        FileCoverage::Stale { .. } => SnapshotFreshness::Stale,
        _ => SnapshotFreshness::Unknown,
    };
    Ok(FileRow {
        rowid: get(row, start)?,
        pointer: CodePointer {
            file: FileId(blob(row, start + 1)?),
            path: RelativePath::new(get::<String>(row, start + 2)?)?,
            content_hash: optional_blob(row, start + 3)?.map(ContentHash),
            span: None,
            freshness,
        },
        coverage,
        language: get::<Option<String>>(row, start + 5)?
            .map(tag)
            .transpose()?,
    })
}
pub(super) fn file_by_path(sql: &SqlView<'_>, path: &RelativePath) -> AtlasResult<Option<FileRow>> {
    let mut stmt = sql.prepare(&format!(
        "SELECT {FILE_COLUMNS} FROM files f WHERE f.path=?1"
    ))?;
    let mut rows = stmt.query([path.as_str()]).map_err(cache_error)?;
    rows.next()
        .map_err(cache_error)?
        .map(|r| file(r, 0))
        .transpose()
}
pub(super) fn file_by_id(sql: &SqlView<'_>, id: i64) -> AtlasResult<FileRow> {
    let mut stmt = sql.prepare(&format!("SELECT {FILE_COLUMNS} FROM files f WHERE f.id=?1"))?;
    let mut rows = stmt.query([id]).map_err(cache_error)?;
    let row = rows
        .next()
        .map_err(cache_error)?
        .ok_or_else(|| cache_error("file disappeared in snapshot"))?;
    file(row, 0)
}
pub(super) fn symbol_by_id(sql: &SqlView<'_>, id: i64) -> AtlasResult<(SymbolRow, i64)> {
    let (parent, name, file, mut result) = {
        let mut stmt=sql.prepare("SELECT id,key,parent,name,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,file FROM symbols WHERE id=?1")?;
        let mut rows = stmt.query([id]).map_err(cache_error)?;
        let row = rows
            .next()
            .map_err(cache_error)?
            .ok_or_else(|| cache_error("symbol disappeared in snapshot"))?;
        (
            get::<Option<i64>>(row, 2)?,
            get::<i64>(row, 3)?,
            get::<i64>(row, 11)?,
            SymbolRow {
                rowid: get(row, 0)?,
                value: OutlineSymbol {
                    id: SymbolId(blob(row, 1)?),
                    parent: None,
                    name: String::new(),
                    kind: tag(get(row, 4)?)?,
                    span: span(row, 5)?,
                },
            },
        )
    };
    result.value.name = {
        let mut stmt = sql.prepare("SELECT text FROM names WHERE id=?1")?;
        stmt.query_row([name], |row| row.get(0))
            .map_err(cache_error)?
    };
    if let Some(parent) = parent {
        let mut stmt = sql.prepare("SELECT key FROM symbols WHERE id=?1")?;
        let key: Vec<u8> = stmt
            .query_row([parent], |row| row.get(0))
            .map_err(cache_error)?;
        result.value.parent = Some(SymbolId(
            key.try_into()
                .map_err(|_| cache_error("invalid parent symbol key"))?,
        ));
    }
    Ok((result, file))
}
pub(super) struct SymbolRow {
    pub rowid: i64,
    pub value: OutlineSymbol,
}

pub(super) fn number(row: &Row<'_>, column: usize) -> AtlasResult<u64> {
    u64::try_from(get::<i64>(row, column)?).map_err(cache_error)
}
pub(super) fn optional_number(row: &Row<'_>, column: usize) -> AtlasResult<Option<u64>> {
    get::<Option<i64>>(row, column)?
        .map(|v| u64::try_from(v).map_err(cache_error))
        .transpose()
}
pub(super) fn signed(value: u64) -> AtlasResult<i64> {
    i64::try_from(value).map_err(|_| cursor::invalid("ordering integer exceeds SQLite range"))
}
