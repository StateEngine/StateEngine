use super::target::*;
use super::*;
use rusqlite::types::Value;
impl QueryReader<'_> {
    pub fn refs(&self, query: &RefsQuery) -> AtlasResult<Answer<Read<Page<ReferenceHit>>>> {
        let end = deadline(query.budget)?;
        if query.kinds.len() > 5 {
            return Err(se_types::SeError::invalid(
                "reference kinds",
                "at most five kinds",
            ));
        }
        let digest = cursor::digest(&(
            "refs",
            &query.target,
            &query.kinds,
            query.include_name_only,
            &self.viewer,
        ))?;
        let answer = self.cache.read(end, |sql| {
            let snapshot = self.snapshot(sql)?;
            let Some(target) = resolve(sql, &query.target)? else {
                return Ok(snapshot
                    .unknown("target not indexed; search by name or path and inspect coverage"));
            };
            let previous = query
                .next
                .as_ref()
                .map(PositionCursor::decode)
                .transpose()?;
            let advanced = previous
                .as_ref()
                .map(|p| p.validate(&snapshot.index, "refs", digest))
                .transpose()?
                .unwrap_or(false);
            let key = previous.as_ref().map(|p| &p.last_key);
            if key.is_some_and(|k| {
                k.integers.len() != 4
                    || k.integers[0] > 2
                    || (k.integers[0] < 2 && !(17..=40).contains(&k.bytes.len()))
                    || (k.integers[0] == 2 && !(1..=256).contains(&k.bytes.len()))
            }) {
                return Err(cursor::invalid("invalid reference key"));
            }
            let mut items = Vec::new();
            let mut bytes = 0;
            let mut last = key.cloned().unwrap_or_default();
            let mut more = false;
            for phase in 0..=1 {
                if key.is_some_and(|k| k.integers[0] > phase)
                    || phase == 1 && !query.include_name_only
                {
                    continue;
                }
                if phase == 0 && !matches!(target.file.coverage, FileCoverage::Indexed) {
                    continue;
                }
                let (statement, values) = reference_plan(
                    query,
                    &target,
                    key.filter(|k| k.integers[0] == phase),
                    phase,
                )?;
                let ids = {
                    let mut stmt = sql.prepare(&statement)?;
                    let mut rows = stmt
                        .query(rusqlite::params_from_iter(values))
                        .map_err(cache_error)?;
                    let mut ids = Vec::with_capacity(query.budget.max_results as usize + 1);
                    while let Some(row) = rows.next().map_err(cache_error)? {
                        ids.push(get::<i64>(row, 0)?);
                    }
                    ids
                };
                let scan_limited = ids.len() == 513;
                for id in ids.into_iter().take(512) {
                    let reference = reference_by_id(sql, id)?;
                    if crate::policy::built_in_denied(&reference.site.path) {
                        last = reference_key(&reference, id)?;
                        continue;
                    }
                    if !query.kinds.is_empty() && !query.kinds.contains(&reference.kind) {
                        last = reference_key(&reference, id)?;
                        continue;
                    }
                    let cost = size(&reference)?;
                    if items.len() == query.budget.max_results as usize
                        || bytes + cost + size(&snapshot.index)? + 1800
                            > query.budget.max_bytes as usize
                    {
                        more = true;
                        break;
                    }
                    last = reference_key(&reference, id)?;
                    bytes += cost;
                    items.push(ReferenceHit::Code(reference));
                }
                if scan_limited {
                    more = true;
                }
                if more {
                    break;
                }
            }
            if !more {
                let record_key = key.filter(|k| k.integers[0] == 2).map(|k| Key {
                    integers: vec![1, k.integers[1]],
                    bytes: k.bytes.clone(),
                });
                let linked = super::linked::for_file(
                    self,
                    sql,
                    &snapshot,
                    super::linked::LinkedRequest {
                        file: &target.file.pointer,
                        limit: query.budget.max_results as usize - items.len(),
                        bytes: (query.budget.max_bytes as usize)
                            .saturating_sub(bytes + size(&snapshot.index)? + 500),
                        after: record_key.as_ref(),
                        query: None,
                        end,
                    },
                )?;
                more = linked.more;
                for record in linked.items {
                    bytes += size(&record)?;
                    items.push(ReferenceHit::Record(record));
                }
                if let Some(mut k) = linked.last {
                    k.integers = vec![2, k.integers[1], 0, 0];
                    last = k;
                }
            }
            if more && last == key.cloned().unwrap_or_default() {
                return Err(capacity("Atlas refs response bytes", 1, 0));
            }
            let next = more
                .then(|| {
                    PositionCursor::new(&snapshot.index, "refs", digest, last, None)
                        .and_then(|p| p.encode())
                })
                .transpose()?;
            let output = page(
                &snapshot,
                items,
                query.budget,
                next,
                !snapshot.negative_complete() || advanced,
                bytes,
                query.next.as_ref(),
            )?;
            check_output(
                snapshot.answer(Read::Present { value: output }, advanced),
                query.budget,
            )
        })?;
        super::freshness::finish(self, answer, query.budget, end)
    }
}
fn reference_plan(
    query: &RefsQuery,
    target: &Target,
    after: Option<&Key>,
    phase: u64,
) -> AtlasResult<(String, Vec<Value>)> {
    let mut values = vec![Value::Integer(target.file.rowid)];
    let mut statement = "SELECT r.id FROM refs r JOIN files f ON f.id=r.file WHERE ".to_owned();
    let spelling = if phase == 0 { "id" } else { "name" };
    statement.push_str(&format!(
        "r.{} IN (SELECT {spelling} FROM symbols WHERE file=?1",
        if phase == 0 { "target" } else { "spelling" }
    ));
    if let Some(symbol) = &target.symbol {
        values.push(symbol.rowid.into());
        statement.push_str(" AND id=?2");
    }
    statement.push(')');
    if phase == 0 {
        statement.push_str(" AND r.accuracy<>'NameOnly' AND f.coverage_json='\"Indexed\"'");
    } else {
        statement.push_str(" AND r.accuracy='NameOnly'");
    }
    if let Some(key) = after {
        let start = values.len() + 1;
        let kind = std::str::from_utf8(&key.bytes[16..]).map_err(cursor::invalid)?;
        values.extend([
            Value::Blob(key.bytes[..16].to_vec()),
            Value::Integer(signed(key.integers[1])?),
            Value::Integer(signed(key.integers[2])?),
            Value::Text(kind.into()),
            Value::Integer(signed(key.integers[3])?),
        ]);
        statement.push_str(&format!(
            " AND (f.key,r.start_byte,r.end_byte,r.kind,r.id)>(?{},?{},?{},?{},?{})",
            start,
            start + 1,
            start + 2,
            start + 3,
            start + 4
        ));
    }
    values.push(Value::Integer(if query.kinds.is_empty() {
        i64::from(query.budget.max_results) + 1
    } else {
        513
    }));
    statement.push_str(&format!(
        " ORDER BY f.key,r.start_byte,r.end_byte,r.kind,r.id LIMIT ?{}",
        values.len()
    ));
    Ok((statement, values))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reference_keysets_fit_statement_share() -> Result<(), Box<dyn std::error::Error>> {
        let db = rusqlite::Connection::open_in_memory()?;
        db.execute_batch(include_str!("../cache/schema.sql"))?;
        let mut target = Target {
            file: FileRow {
                rowid: 1,
                pointer: CodePointer {
                    file: FileId([1; 16]),
                    path: RelativePath::new("alpha.rs")?,
                    span: None,
                    content_hash: None,
                    freshness: SnapshotFreshness::Current,
                },
                coverage: FileCoverage::Indexed,
                language: Some(Language::Rust),
            },
            symbol: None,
        };
        let mut query = RefsQuery {
            target: AtlasTarget::File(RelativePath::new("alpha.rs")?),
            kinds: vec![],
            include_name_only: true,
            next: None,
            budget: Validate.query_budget(10, 4096)?,
        };
        for symbol in [false, true] {
            if symbol {
                target.symbol = Some(SymbolRow {
                    rowid: 1,
                    value: OutlineSymbol {
                        id: SymbolId([1; 32]),
                        parent: None,
                        name: "alpha".into(),
                        kind: SymbolKind::Function,
                        span: Span {
                            start: Position {
                                line: 1,
                                byte_column: 0,
                            },
                            end: Position {
                                line: 1,
                                byte_column: 1,
                            },
                            start_byte: 0,
                            end_byte: 1,
                        },
                    },
                });
            }
            for kinds in [false, true] {
                if kinds {
                    query.kinds = vec![
                        ReferenceKind::Call,
                        ReferenceKind::Import,
                        ReferenceKind::Export,
                        ReferenceKind::TypeUse,
                        ReferenceKind::ValueUse,
                    ];
                }
                for phase in 0..=1 {
                    for next in [false, true] {
                        let key = Key {
                            integers: vec![phase, 0, 1, 1],
                            bytes: [[1u8; 16].as_slice(), b"Call"].concat(),
                        };
                        let (statement, _) =
                            reference_plan(&query, &target, next.then_some(&key), phase)?;
                        let stmt = db.prepare(&statement)?;
                        let bytes = stmt.get_status(rusqlite::StatementStatus::MemUsed);
                        assert!(bytes <= 16384, "{bytes}: {statement}");
                    }
                }
            }
        }
        Ok(())
    }
}
