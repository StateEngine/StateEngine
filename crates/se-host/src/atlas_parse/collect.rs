//! Bound decoded rows before publication; no worker output can mutate SQL.
use super::*;
use std::mem::size_of;
struct Rows {
    bytes: usize,
    rows: u32,
    maximum: u32,
}
impl Rows {
    fn push<T>(&mut self, into: &mut Vec<T>, row: T, strings: usize) -> AtlasResult<()> {
        if self.rows >= self.maximum {
            return Err(failure("parse result exceeds row reservation"));
        }
        let growth = if into.len() == into.capacity() {
            into.capacity().max(4)
        } else {
            0
        };
        let charge = growth
            .saturating_mul(size_of::<T>())
            .saturating_add(strings);
        self.bytes = self
            .bytes
            .checked_sub(charge)
            .ok_or_else(|| failure("parse result exceeds extraction reservation"))?;
        if growth > 0 {
            into.try_reserve_exact(growth).map_err(failure)?;
        }
        into.push(row);
        self.rows += 1;
        Ok(())
    }
}
fn reply(worker: &mut AtlasWorker, deadline: Instant) -> AtlasResult<protocol::Reply> {
    loop {
        if Instant::now() >= deadline {
            return Err(expired());
        }
        if let Some(bytes) = worker.receive().map_err(failure)? {
            return serde_json::from_slice(&bytes).map_err(failure);
        }
        if worker.try_reap().map_err(failure)?.is_some() {
            return Err(failure("parse child exited before complete output"));
        }
        worker.wait_ready(deadline).map_err(failure)?;
    }
}
pub(super) fn read(
    worker: &mut AtlasWorker,
    source: &Source,
    snapshot: &SourceSnapshot,
    language: Language,
    budget: ParseBudget,
    profile: ParserProfile,
    deadline: Instant,
) -> AtlasResult<ParsedFile> {
    let first = reply(worker, deadline)?;
    let coverage = match first {
        protocol::Reply::Start {
            file,
            language: got,
            hash,
            coverage,
        } if file == source.scope.file_id(&snapshot.path)
            && got == language
            && hash == snapshot.content_hash =>
        {
            coverage
        }
        protocol::Reply::Failed { error } => return Err(SeError::from(error)),
        _ => return Err(failure("parse result does not match bound source")),
    };
    let mut parsed = ParsedFile {
        file: source.scope.file_id(&snapshot.path),
        language,
        content_hash: snapshot.content_hash,
        coverage,
        symbols: Vec::new(),
        imports: Vec::new(),
        references: Vec::new(),
        scopes: Vec::new(),
    };
    let mut rows = Rows {
        bytes: profile.extraction_bytes as usize,
        rows: 0,
        maximum: budget.max_rows.min(profile.max_rows),
    };
    loop {
        match reply(worker, deadline)? {
            protocol::Reply::Symbol(row) => {
                span(&row.span, snapshot)?;
                let strings = row.name.capacity()
                    + row.doc_line.capacity()
                    + row.export_alias.as_ref().map_or(0, String::capacity);
                rows.push(&mut parsed.symbols, row, strings)?;
            }
            protocol::Reply::Import(row) => {
                span(&row.span, snapshot)?;
                let strings = row.spelling.capacity()
                    + row.local_name.as_ref().map_or(0, String::capacity)
                    + row.imported_name.as_ref().map_or(0, String::capacity);
                rows.push(&mut parsed.imports, row, strings)?;
            }
            protocol::Reply::Reference(row) => {
                if row.site.site.file != parsed.file
                    || row.site.site.path != snapshot.path
                    || row.site.site.content_hash != Some(snapshot.content_hash)
                {
                    return Err(failure("parse reference belongs to another source"));
                }
                if let Some(value) = &row.site.site.span {
                    span(value, snapshot)?;
                }
                let qualifiers = match &row.qualifier {
                    ReferenceQualifier::Namespace(parts) => {
                        parts.capacity() * size_of::<String>()
                            + parts.iter().map(String::capacity).sum::<usize>()
                    }
                    _ => 0,
                };
                let strings =
                    row.site.spelling.capacity() + row.site.site.path.as_str().len() + qualifiers;
                rows.push(&mut parsed.references, row, strings)?;
            }
            protocol::Reply::Scope(row) => {
                span(&row.span, snapshot)?;
                rows.push(&mut parsed.scopes, row, 0)?;
            }
            protocol::Reply::Done => {
                if Instant::now() >= deadline {
                    return Err(expired());
                }
                return Ok(parsed);
            }
            protocol::Reply::Failed { error } => return Err(SeError::from(error)),
            protocol::Reply::Start { .. } => return Err(failure("duplicate parse result header")),
        }
    }
}
fn span(value: &Span, snapshot: &SourceSnapshot) -> AtlasResult<()> {
    if value.start_byte > value.end_byte || value.end_byte > snapshot.bytes.len() as u64 {
        return Err(failure("parse span exceeds its verified source"));
    }
    Ok(())
}
