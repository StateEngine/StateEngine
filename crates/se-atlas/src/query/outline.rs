use super::*;
use rusqlite::params;
impl QueryReader<'_> {
    pub fn outline(&self, query: &OutlineQuery) -> AtlasResult<Answer<Read<Outline>>> {
        let end = deadline(query.budget)?;
        let digest = cursor::digest(&("outline", &query.path, &self.viewer))?;
        self.cache.read(end, |sql| {
            let snapshot = self.snapshot(sql)?;
            if crate::policy::built_in_denied(&query.path) {return Ok(snapshot.unknown("source path is excluded by the built-in private-file policy"));}
            let previous = query.next.as_ref().map(PositionCursor::decode).transpose()?;
            let advanced = previous.as_ref().map(|p| p.validate(&snapshot.index, "outline", digest)).transpose()?.unwrap_or(false);
            let key = previous.as_ref().map(|p| &p.last_key);
            if let Some(k) = key { validate_key(k)?; }
            let Some(file) = file_by_path(sql, &query.path)? else {
                return if snapshot.negative_complete() {
                    Ok(snapshot.answer(Read::Absent { checked: format!("registered cache path {} in epoch {}", query.path.as_str(), self.cache.identity().epoch) }, advanced))
                } else { Ok(snapshot.unknown("path is not indexed; discovery or semantics are incomplete")) };
            };
            let mut output = Outline { file: file.pointer, language: file.language, coverage: file.coverage,
                symbols: Vec::new(), records: Vec::new(), complete: snapshot.negative_complete() && !advanced, next: None };
            let phase = key.map_or(0, |k| k.integers[0]);
            let mut last = key.cloned().unwrap_or_default();
            let mut more = false;
            if phase == 0 {
                let start = key.map_or(0, |k| k.integers[1]);
                let stop = key.map_or(u64::MAX, |k| k.integers[2]);
                let symbol_key = key.map_or(&[][..], |k| k.bytes.as_slice());
                let ids={
                    let mut stmt=sql.prepare("SELECT id FROM symbols WHERE file=?1 AND (?2=0 OR start_byte>?3 OR (start_byte=?3 AND (end_byte<?4 OR (end_byte=?4 AND key>?5)))) ORDER BY start_byte,end_byte DESC,key LIMIT ?6")?;
                    let mut rows=stmt.query(params![file.rowid,key.is_some(),signed(start)?,i64::try_from(stop).unwrap_or(i64::MAX),symbol_key,u32::from(query.budget.max_results)+1]).map_err(cache_error)?;
                    let mut ids=Vec::with_capacity(query.budget.max_results as usize+1);
                    while let Some(row)=rows.next().map_err(cache_error)?{ids.push(get::<i64>(row,0)?);}ids
                };
                for id in ids {
                    let symbol=symbol_by_id(sql,id)?.0.value;
                    if output.symbols.len() >= query.budget.max_results as usize { more = true; break; }
                    let next_key = Key { integers: vec![0, symbol.span.start_byte, symbol.span.end_byte], bytes: symbol.id.0.to_vec() };
                    output.symbols.push(symbol);
                    if size(&output)? + size(&snapshot.index)? + 1200 > query.budget.max_bytes as usize {
                        output.symbols.pop(); more = true; break;
                    }
                    last = next_key;
                }
            }
            if !more {
                let linked = super::linked::for_file(self, sql, &snapshot, super::linked::LinkedRequest {
                    file: &output.file, limit: query.budget.max_results as usize-output.symbols.len(),
                    bytes: (query.budget.max_bytes as usize).saturating_sub(size(&output)?),
                    after: if phase==1 {key} else {None}, query: None, end,
                })?;
                output.records = linked.items;
                more = linked.more;
                if let Some(k) = linked.last { last = k; }
            }
            if more {
                if last == key.cloned().unwrap_or_default() {
                    return Err(capacity("Atlas outline response bytes", 1, 0));
                }
                output.next = Some(PositionCursor::new(&snapshot.index, "outline", digest, last, None)?.encode()?);
                output.complete = false;
            }
            check_output(snapshot.answer(Read::Present { value: output }, advanced), query.budget)
        })
    }
}
fn validate_key(key: &Key) -> AtlasResult<()> {
    match key.integers.first() {
        Some(0) if key.integers.len() == 3 && key.bytes.len() == 32 => Ok(()),
        Some(1) if key.integers.len() == 2 && !key.bytes.is_empty() && key.bytes.len() <= 256 => {
            Ok(())
        }
        _ => Err(cursor::invalid("invalid outline ordering key")),
    }
}
