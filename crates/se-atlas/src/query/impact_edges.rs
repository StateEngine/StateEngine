//! Range only reference identities; close it before loading point metadata.
//! This keeps traversal statements within the 16 KiB SQL reservation.
use super::*;

pub(super) struct Edge {
    pub id: i64,
    pub enclosing: Option<i64>,
    pub file: i64,
    pub start: u64,
}

pub(super) fn read(
    sql: &SqlView<'_>,
    target: i64,
    include_name_only: bool,
    limit: usize,
    end: Instant,
) -> AtlasResult<(Vec<Edge>, bool)> {
    let (name, file) = {
        let mut statement = sql.prepare("SELECT name,file FROM symbols WHERE id=?1")?;
        statement
            .query_row([target], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
            .map_err(cache_error)?
    };
    let target_file = file_by_id(sql, file)?;
    if crate::policy::built_in_denied(&target_file.pointer.path)
        || !matches!(target_file.coverage, FileCoverage::Indexed)
    {
        return Ok((Vec::new(), true));
    }
    let mut output = Vec::with_capacity(limit.min(32));
    let limited = range(sql, false, target, limit, end, &mut output)?;
    if limited || !include_name_only {
        return Ok((output, limited));
    }
    let limited = range(sql, true, name, limit, end, &mut output)?;
    Ok((output, limited))
}

fn range(
    sql: &SqlView<'_>,
    name_only: bool,
    key: i64,
    limit: usize,
    end: Instant,
    output: &mut Vec<Edge>,
) -> AtlasResult<bool> {
    let query = if name_only {
        "SELECT id,enclosing,file,start_byte FROM refs WHERE spelling=?1 AND accuracy='NameOnly' ORDER BY file,start_byte,id LIMIT 1025"
    } else {
        "SELECT id,enclosing,file,start_byte FROM refs WHERE target=?1 AND accuracy<>'NameOnly' ORDER BY file,start_byte,id LIMIT 1025"
    };
    let mut statement = sql.prepare(query)?;
    let mut rows = statement.query([key]).map_err(cache_error)?;
    while let Some(row) = rows.next().map_err(cache_error)? {
        if output.len() == limit || crate::clock::now() >= end {
            return Ok(true);
        }
        output.push(Edge {
            id: get(row, 0)?,
            enclosing: get(row, 1)?,
            file: get(row, 2)?,
            start: number(row, 3)?,
        });
    }
    Ok(false)
}
