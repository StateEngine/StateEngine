//! Keep the existing source-candidate cutoff without a native temporary sort.
use super::{candidate_sql::Plan, candidates::Kind, *};
use std::{cmp::Ordering, collections::BinaryHeap};

type Row = (i64, Option<i64>, f64);
const WINDOW: usize = 512;
pub(super) struct Selected {
    pub rows: Vec<Row>,
    pub truncated: bool,
}

struct Entry {
    row: Row,
    // A window has one kind: 32-byte symbol keys or 16-byte file keys. Equal
    // padding within a kind preserves the original BLOB ordering.
    key: [u8; 32],
}
impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Entry {}
impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        // The maximum is the worst retained row. None follows every timestamp,
        // including negative timestamps, exactly as SQLite's descending order.
        other.row.1.cmp(&self.row.1).then(self.key.cmp(&other.key))
    }
}

pub(super) fn collect(sql: &SqlView<'_>, plan: &Plan) -> AtlasResult<Selected> {
    let source_key_bytes = match plan.kind {
        Kind::Symbol => Some(32),
        Kind::File => Some(16),
        Kind::Record | Kind::Commit => None,
    };
    let mut statement = sql.prepare(&plan.sql)?;
    let mut rows = statement
        .query(rusqlite::params_from_iter(plan.values.iter()))
        .map_err(cache_error)?;
    let Some(key_bytes) = source_key_bytes else {
        let mut output = Vec::with_capacity(WINDOW + 1);
        while let Some(row) = rows.next().map_err(cache_error)? {
            output.push(value(row, plan.lexical)?);
        }
        let truncated = output.len() > WINDOW;
        output.truncate(WINDOW);
        return Ok(Selected {
            rows: output,
            truncated,
        });
    };
    let mut window = BinaryHeap::with_capacity(WINDOW);
    let mut truncated = false;
    while let Some(row) = rows.next().map_err(cache_error)? {
        let key = row
            .get_ref(if plan.lexical { 3 } else { 2 })
            .map_err(cache_error)?
            .as_blob()
            .map_err(cache_error)?;
        if key.len() != key_bytes {
            return Err(cache_error("invalid source candidate key"));
        }
        let mut bytes = [0; 32];
        bytes[..key_bytes].copy_from_slice(key);
        let entry = Entry {
            row: value(row, plan.lexical)?,
            key: bytes,
        };
        if window.len() < WINDOW {
            window.push(entry);
        } else {
            truncated = true;
            if window.peek().is_some_and(|worst| entry < *worst) {
                *window
                    .peek_mut()
                    .ok_or_else(|| cache_error("candidate window absent"))? = entry;
            }
        }
    }
    // The discarded marker contributes only truncation, never a ranked row.
    Ok(Selected {
        rows: window
            .into_sorted_vec()
            .into_iter()
            .map(|entry| entry.row)
            .collect(),
        truncated,
    })
}

fn value(row: &rusqlite::Row<'_>, lexical: bool) -> AtlasResult<Row> {
    let score = if lexical { get::<f64>(row, 2)? } else { 0.0 };
    if !score.is_finite() || score > 0.0 {
        return Err(cache_error("invalid BM25 score"));
    }
    Ok((get(row, 0)?, get(row, 1)?, score))
}
