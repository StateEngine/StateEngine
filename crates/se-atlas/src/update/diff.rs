use crate::{
    cache::connection::SqlView,
    errors::{AtlasResult, cache_error},
    lifecycle::*,
    model::*,
};
use rusqlite::{OptionalExtension, params};
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Fact {
    pub file: FileId,
    pub symbol: Option<SymbolId>,
    pub path: RelativePath,
    pub span: Option<Span>,
    pub kind: ChangeKind,
    pub previous: Option<ContentHash>,
    pub current: Option<ContentHash>,
    pub baseline_reset: bool,
}
pub struct Baseline {
    pub hash: Option<ContentHash>,
    pub reset: bool,
    pub cold: bool,
}
type Hashes = (Option<Vec<u8>>, Option<Vec<u8>>);
pub fn retire(
    sql: &SqlView<'_>,
    row: i64,
    file: FileId,
    path: &RelativePath,
    baseline: Baseline,
    mut emit: impl FnMut(Fact) -> AtlasResult<()>,
) -> AtlasResult<()> {
    if baseline.cold {
        return Ok(());
    }
    let fact = |symbol, span, kind| Fact {
        file,
        symbol,
        path: path.clone(),
        span,
        kind,
        previous: baseline.hash,
        current: None,
        baseline_reset: baseline.reset,
    };
    if baseline.reset {
        return emit(fact(None, None, ChangeKind::FileOnly));
    }
    let mut statement=sql.prepare("SELECT key,start_byte,end_byte,start_line,start_column,end_line,end_column FROM symbols WHERE file=?1 ORDER BY id")?;
    let mut rows = statement.query([row]).map_err(cache_error)?;
    let mut any = false;
    while let Some(row) = rows.next().map_err(cache_error)? {
        let (id, span) = site(row)?;
        emit(fact(Some(id), Some(span), ChangeKind::Removed))?;
        any = true;
    }
    if !any {
        emit(fact(None, None, ChangeKind::Removed))?;
    }
    Ok(())
}
pub fn compare(
    sql: &SqlView<'_>,
    row: i64,
    path: &RelativePath,
    parsed: &ParsedFile,
    baseline: Baseline,
    mut emit: impl FnMut(Fact) -> AtlasResult<()>,
) -> AtlasResult<()> {
    let Baseline {
        hash: old_hash,
        reset,
        cold,
    } = baseline;
    if cold {
        return Ok(());
    }
    let fact = |symbol, span, kind| Fact {
        file: parsed.file,
        symbol,
        path: path.clone(),
        span,
        kind,
        previous: old_hash,
        current: Some(parsed.content_hash),
        baseline_reset: reset,
    };
    if reset {
        return emit(fact(None, None, ChangeKind::FileOnly));
    }
    let mut count = 0;
    for symbol in &parsed.symbols {
        let old: Option<Hashes> = sql
            .prepare("SELECT signature_hash,body_hash FROM symbols WHERE file=?1 AND key=?2")?
            .query_row(params![row, symbol.id.0.as_slice()], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()
            .map_err(cache_error)?;
        let kind = match old {
            None => Some(ChangeKind::Added),
            Some((signature, body)) => {
                if signature.as_deref() != symbol.signature_hash.as_ref().map(|v| v.0.as_slice()) {
                    Some(ChangeKind::SignatureChanged)
                } else if body.as_deref() != symbol.body_hash.as_ref().map(|v| v.0.as_slice()) {
                    Some(ChangeKind::BodyChanged)
                } else {
                    None
                }
            }
        };
        if let Some(kind) = kind {
            emit(fact(Some(symbol.id), Some(symbol.span), kind))?;
            count += 1;
        }
    }
    let mut statement=sql.prepare("SELECT key,start_byte,end_byte,start_line,start_column,end_line,end_column FROM symbols WHERE file=?1 ORDER BY id")?;
    let mut rows = statement.query([row]).map_err(cache_error)?;
    while let Some(row) = rows.next().map_err(cache_error)? {
        let (id, span) = site(row)?;
        if parsed.symbols.iter().any(|s| s.id == id) {
            continue;
        }
        emit(fact(Some(id), Some(span), ChangeKind::Removed))?;
        count += 1;
    }
    if count == 0 && old_hash != Some(parsed.content_hash) {
        emit(fact(None, None, ChangeKind::FileOnly))?
    }
    Ok(())
}
fn site(row: &rusqlite::Row<'_>) -> AtlasResult<(SymbolId, Span)> {
    let key: Vec<u8> = row.get(0).map_err(cache_error)?;
    let id = SymbolId(
        key.try_into()
            .map_err(|_| cache_error("invalid symbol key"))?,
    );
    let span = Span {
        start_byte: super::column(row, 1).map_err(cache_error)?,
        end_byte: super::column(row, 2).map_err(cache_error)?,
        start: Position {
            line: row.get(3).map_err(cache_error)?,
            byte_column: row.get(4).map_err(cache_error)?,
        },
        end: Position {
            line: row.get(5).map_err(cache_error)?,
            byte_column: row.get(6).map_err(cache_error)?,
        },
    };
    Ok((id, span))
}
