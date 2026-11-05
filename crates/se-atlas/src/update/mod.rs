//! Atomic semantic replacement, bounded publication and provenance repair.
pub mod authors;
pub mod batch;
mod bindings;
pub mod diff;
pub mod file;
pub mod observation;
use crate::{
    cache::connection::SqlView,
    errors::{AtlasResult, cache_error},
};
pub(crate) fn execute<P: rusqlite::Params>(
    sql: &SqlView<'_>,
    statement: &str,
    params: P,
) -> AtlasResult<usize> {
    sql.prepare(statement)?.execute(params).map_err(cache_error)
}
pub(crate) fn value<T: rusqlite::types::FromSql, P: rusqlite::Params>(
    sql: &SqlView<'_>,
    statement: &str,
    params: P,
) -> AtlasResult<T> {
    sql.prepare(statement)?
        .query_row(params, |r| r.get(0))
        .map_err(cache_error)
}
pub(crate) fn json<T: serde::Serialize>(value: &T) -> AtlasResult<String> {
    serde_json::to_string(value).map_err(cache_error)
}

pub(crate) struct U64(u64);
pub(crate) fn n(value: u64) -> U64 {
    U64(value)
}
impl rusqlite::ToSql for U64 {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let value = i64::try_from(self.0)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        Ok(rusqlite::types::ToSqlOutput::Owned(value.into()))
    }
}
pub(crate) fn unsigned(
    sql: &SqlView<'_>,
    statement: &str,
    params: impl rusqlite::Params,
) -> AtlasResult<u64> {
    sql.prepare(statement)?
        .query_row(params, |r| column(r, 0))
        .map_err(cache_error)
}
pub(crate) fn column(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(e),
        )
    })
}
