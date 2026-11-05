use super::*;
use rusqlite::params;
impl QueryReader<'_> {
    pub fn changes(&self, query: &ChangesQuery) -> AtlasResult<Answer<Read<Page<CodeChange>>>> {
        let end = deadline(query.budget)?;
        let digest = cursor::digest(&("changes", &query.since, &query.scope, &self.viewer))?;
        query.scope.validate()?;
        let answer = self.cache.read(end, |sql| {
            let snapshot = self.snapshot(sql)?;
            let baseline = baseline(self, sql, &snapshot, &query.since)?;
            let previous = query.next.as_ref().map(PositionCursor::decode).transpose()?;
            let advanced = previous.as_ref().map(|p| p.validate(&snapshot.index, "changes", digest)).transpose()?.unwrap_or(false);
            let last = previous.as_ref().map_or(&baseline.last_key, |p| &p.last_key);
            validate_key(last)?;
            let fence = previous.as_ref().and_then(|p| p.change_fence).or(baseline.change_fence).unwrap_or(snapshot.published);
            if fence.0 > snapshot.published.0 || fence.0 < last.integers[0] {
                return Err(cursor::invalid("invalid changes fence"));
            }
            check_retention(&snapshot, last.integers[0], &self.viewer)?;
            let ids={
                let mut stmt=sql.prepare("SELECT generation,ordinal FROM changes WHERE (generation,ordinal)>(?1,?2) AND generation<=?3 ORDER BY generation,ordinal LIMIT 513")?;
                let mut rows=stmt.query(params![signed(last.integers[0])?,signed(last.integers[1])?,signed(fence.0)?]).map_err(cache_error)?;
                let mut ids=Vec::with_capacity(513);while let Some(row)=rows.next().map_err(cache_error)?{ids.push((number(row,0)?,get::<u32>(row,1)?));}ids
            };
            let scan_limited=ids.len()==513;
            let mut incomplete=false;let mut items=Vec::new();let mut bytes=0;let mut key=last.clone();let mut more=false;
            for (generation,ordinal) in ids.into_iter().take(512){
                let mut value=change_by_id(sql,generation,ordinal)?;
                let position=Key{integers:vec![generation,u64::from(ordinal)],bytes:vec![]};
                if !public_change(&mut value) {key=position;continue;}
                if let CodeChange::Edit(edit)=&value {
                    if !query.scope.includes_path(&edit.pointer.path){key=position;continue;}
                    if !query.scope.languages.is_empty(){
                        match file_by_path(sql,&edit.pointer.path)?.and_then(|f|f.language){
                            Some(language) if query.scope.languages.contains(&language)=>(),
                            Some(_)=>{key=position;continue;},
                            None=>{incomplete=true;key=position;continue;},
                        }
                    }
                }else if !query.scope.languages.is_empty(){incomplete=true;}
                let cost=size(&value)?;
                if items.len()>=query.budget.max_results as usize||bytes+cost+size(&snapshot.index)?+1800>query.budget.max_bytes as usize{more=true;break;}
                key=position;items.push(value);bytes+=cost;
            }
            more|=scan_limited;
            if more&&key==*last{return Err(capacity("Atlas change response bytes",1,0));}
            let next = more.then(|| PositionCursor::new(&snapshot.index, "changes", digest, key, Some(fence)).and_then(|p| p.encode())).transpose()?;
            let page = page(&snapshot, items, query.budget, next, !snapshot.negative_complete() || advanced || incomplete,
                bytes, query.next.as_ref())?;
            check_output(snapshot.answer(Read::Present { value: page }, advanced), query.budget)
        })?;
        super::freshness::finish(self, answer, query.budget, end)
    }
}
pub(super) fn change(row: &rusqlite::Row<'_>, author: AuthorHint) -> AtlasResult<CodeChange> {
    let id = ChangeId {
        generation: Generation(number(row, 0)?),
        ordinal: get(row, 1)?,
    };
    let kind: String = get(row, 2)?;
    if kind == "Bulk" {
        let value: BulkChange = json(&get::<String>(row, 10)?)?;
        if value.id != id || value.sample_paths.len() > 5 {
            return Err(cache_error("invalid bulk change identity or samples"));
        }
        return Ok(CodeChange::Bulk(value));
    }
    let dependents = DependentCount {
        count: optional_number(row, 6)?.unwrap_or(0),
        complete: get::<Option<bool>>(row, 7)?.unwrap_or(false),
        at_generation: Generation(optional_number(row, 8)?.unwrap_or(id.generation.0)),
        reason: None,
    };
    Ok(CodeChange::Edit(Box::new(CodeEdit {
        id,
        pointer: json(&get::<String>(row, 3)?)?,
        symbol: optional_blob(row, 4)?.map(SymbolId),
        previous_hash: optional_blob(row, 5)?.map(ContentHash),
        kind: tag(kind)?,
        baseline_reset: get(row, 9)?,
        author,
        dependents,
    })))
}
pub(super) fn author(
    sql: &SqlView<'_>,
    generation: u64,
    ordinal: u32,
) -> AtlasResult<(AuthorHint, Option<u64>)> {
    let mut stmt = sql.prepare(
        "SELECT hint_json,resolved_at_generation FROM authors WHERE generation=?1 AND ordinal=?2",
    )?;
    let mut rows = stmt
        .query(params![signed(generation)?, ordinal])
        .map_err(cache_error)?;
    if let Some(row) = rows.next().map_err(cache_error)? {
        Ok((json(&get::<String>(row, 0)?)?, Some(number(row, 1)?)))
    } else {
        Ok((AuthorHint::Unknown, None))
    }
}
pub(super) fn change_by_id(
    sql: &SqlView<'_>,
    generation: u64,
    ordinal: u32,
) -> AtlasResult<CodeChange> {
    let author = author(sql, generation, ordinal)?.0;
    let mut stmt=sql.prepare("SELECT generation,ordinal,kind,pointer_json,symbol_key,previous_hash,dependent_count,dependent_complete,dependent_generation,baseline_reset,bulk_json FROM changes WHERE generation=?1 AND ordinal=?2")?;
    let mut rows = stmt
        .query(params![signed(generation)?, ordinal])
        .map_err(cache_error)?;
    let row = rows
        .next()
        .map_err(cache_error)?
        .ok_or_else(|| cache_error("change disappeared in snapshot"))?;
    change(row, author)
}
fn validate_key(key: &Key) -> AtlasResult<()> {
    if key.integers.len() != 2 || !key.bytes.is_empty() || key.integers[1] > u64::from(u32::MAX) {
        return Err(cursor::invalid("invalid change ordering key"));
    }
    Ok(())
}
pub(super) fn range_cursor(
    snapshot: &Snapshot,
    viewer: &AtlasPrincipal,
    lower: u64,
    upper: Option<Generation>,
) -> AtlasResult<PositionCursor> {
    PositionCursor::new(
        &snapshot.index,
        "changes-range",
        cursor::digest(&("changes-range", viewer))?,
        Key {
            integers: vec![lower, u64::from(u32::MAX)],
            bytes: vec![],
        },
        upper,
    )
}
pub(super) fn check_retention(
    snapshot: &Snapshot,
    generation: u64,
    viewer: &AtlasPrincipal,
) -> AtlasResult<()> {
    if generation < snapshot.floor.0 {
        return Err(se_types::SeError::new(se_types::Detail::CursorExpired(
            se_types::details::CursorExpired {
                oldest_available: wire_cursor(
                    &range_cursor(snapshot, viewer, snapshot.floor.0, None)?.encode()?,
                )?,
            },
        )));
    }
    Ok(())
}
fn baseline(
    reader: &QueryReader<'_>,
    sql: &SqlView<'_>,
    snapshot: &Snapshot,
    since: &ChangeBaseline,
) -> AtlasResult<PositionCursor> {
    let generation = match since {
        ChangeBaseline::Cursor(value) => {
            let cursor = PositionCursor::decode(value)?;
            cursor.validate(
                &snapshot.index,
                "changes-range",
                cursor::digest(&("changes-range", &reader.viewer))?,
            )?;
            validate_key(&cursor.last_key)?;
            check_retention(snapshot, cursor.last_key.integers[0], &reader.viewer)?;
            return Ok(cursor);
        }
        ChangeBaseline::ObservedCommit(oid) => {
            let oid = match oid {
                GitObjectId::Sha1(v) => v.as_slice(),
                GitObjectId::Sha256(v) => v.as_slice(),
            };
            let mut stmt =
                sql.prepare("SELECT min(generation) FROM observed_commits WHERE oid=?1")?;
            stmt.query_row([oid], |r| r.get::<_, Option<i64>>(0))
                .map_err(cache_error)?
                .ok_or_else(|| {
                    cursor::invalid(
                        "BaselineUnavailable: commit was not retained as an observed baseline",
                    )
                })? as u64
        }
        ChangeBaseline::ObservedUnixMillis(time) => {
            let regressed: bool = {
                let mut stmt=sql.prepare("SELECT EXISTS(SELECT 1 FROM (SELECT observed_unix_ms,lag(observed_unix_ms) OVER (ORDER BY generation) previous FROM generations) WHERE previous>observed_unix_ms)")?;
                stmt.query_row([], |r| r.get(0)).map_err(cache_error)?
            };
            if regressed {
                return Err(cursor::invalid(
                    "BaselineUnavailable: observation clock regressed",
                ));
            }
            let generation = {
                let mut stmt = sql.prepare(
                    "SELECT max(generation) FROM generations WHERE observed_unix_ms<=?1",
                )?;
                stmt.query_row([time], |r| r.get::<_, Option<i64>>(0))
                    .map_err(cache_error)?
            };
            generation.ok_or_else(|| {
                cursor::invalid("BaselineUnavailable: time predates retained observations")
            })? as u64
        }
    };
    check_retention(snapshot, generation, &reader.viewer)?;
    range_cursor(snapshot, &reader.viewer, generation, None)
}

pub(super) fn public_change(change: &mut CodeChange) -> bool {
    match change {
        CodeChange::Edit(edit) => !crate::policy::built_in_denied(&edit.pointer.path),
        CodeChange::Bulk(bulk) => {
            let before = bulk.sample_paths.len();
            bulk.sample_paths
                .retain(|path| !crate::policy::built_in_denied(path));
            if before != bulk.sample_paths.len() {
                bulk.complete = false;
            }
            true
        }
    }
}
