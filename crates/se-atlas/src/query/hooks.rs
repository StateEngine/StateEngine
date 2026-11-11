//! Small index-only provider hints. These never call the authoritative record
//! reader, open source bodies, score activity or traverse beyond direct callers.
use super::*;
use rusqlite::params;
#[path = "hook_records.rs"]
mod records;
pub use records::LinkedSample;
pub enum HookTarget<'a> {
    Symbol(&'a str),
    File(&'a RelativePath),
}
pub struct HookContext {
    pub file: CodePointer,
    pub symbols: Vec<OutlineSymbol>,
    pub callers: Vec<CodePointer>,
    pub linked: LinkedSample,
}
impl QueryReader<'_, '_, '_> {
    pub fn hook_context(
        &mut self,
        target: HookTarget<'_>,
        end: Instant,
    ) -> AtlasResult<Option<HookContext>> {
        // Native ingress supplies the five-millisecond deadline. Keeping the
        // supplied bound lets functional consumers exercise rows independently
        // of the separately measured native latency requirement.
        let identity = self.cache.identity().clone();
        let env = self.ctx.split();
        self.cache.read(end, |sql| {
            let snapshot=snapshot(&identity, &env, sql)?;
            let coverage = &snapshot.index.coverage;
            // Optional Git enrichment cannot disable fresh source hints. A
            // history-only limitation must still have complete source watches
            // and a current authoritative-record fence.
            let source_current = matches!(snapshot.index.state, IndexState::Current)
                || matches!(snapshot.index.state,
                    IndexState::VerificationNeeded { reason }
                    if matches!(reason, CoverageReason::HistoryUnavailable | CoverageReason::ResultLimit)
                        && crate::history::limitation(sql)? == Some(reason)
                        && coverage.watch_discovery_complete
                        && coverage.unwatched_directories == 0
                        && !coverage.reasons.iter().any(|r| matches!(r,
                            CoverageReason::StaleSnapshot | CoverageReason::RecordFeedLag
                            | CoverageReason::RecordBodyLimit | CoverageReason::PartialWatch
                            | CoverageReason::WatchLoss)));
            if !source_current || snapshot.epoch_retired || env.hostless || !env.record_feed_current {
                return Ok(None);
            }
            match target {
                HookTarget::Symbol(name)=> {
                    let ids={
                        let mut stmt=sql.prepare("SELECT s.id FROM names n JOIN symbols s ON s.name=n.id WHERE n.text=?1 ORDER BY s.id LIMIT 2")?;
                        let mut rows=stmt.query([name]).map_err(cache_error)?;
                        let mut ids=Vec::with_capacity(2);
                        while let Some(row)=rows.next().map_err(cache_error)? {ids.push(get::<i64>(row,0)?);}
                        ids
                    };
                    let [id]=ids.as_slice() else {return Ok(None);};
                    let (symbol,file)=symbol_by_id(sql,*id)?;
                    let mut file=file_by_id(sql,file)?.pointer;
                    if !usable(&file) {return Ok(None);}
                    file.span=Some(symbol.value.span);
                    let ids={
                        let mut stmt=sql.prepare("SELECT r.id FROM refs r JOIN files f ON f.id=r.file LEFT JOIN activity a ON a.target_kind='file' AND a.target_key=f.key WHERE r.target=?1 AND r.kind='Call' AND r.accuracy!='NameOnly' ORDER BY a.last_touch_unix_ms DESC,f.key,r.start_byte,r.id LIMIT 3")?;
                        let mut rows=stmt.query([id]).map_err(cache_error)?;
                        let mut ids=Vec::with_capacity(3);
                        while let Some(row)=rows.next().map_err(cache_error)? {ids.push(get::<i64>(row,0)?);}
                        ids
                    };
                    let mut callers=Vec::with_capacity(3);
                    for id in ids {
                        let reference=super::target::reference_by_id(sql,id)?;
                        if reference.resolved_target==Some(symbol.value.id) && usable(&reference.site) {
                            callers.push(reference.site);
                        }
                    }
                    let linked=records::sample(&env,sql,&file.file,Some(&symbol.value.id))?;
                    Ok(Some(HookContext {file,symbols:vec![symbol.value],callers,linked}))
                }
                HookTarget::File(path)=> {
                    if crate::policy::built_in_denied(path) {return Ok(None);}
                    let Some(file)=file_by_path(sql,path)? else {return Ok(None);};
                    if !usable(&file.pointer) {return Ok(None);}
                    let ids={
                        let mut stmt=sql.prepare("SELECT id FROM symbols WHERE file=?1 ORDER BY start_byte,end_byte DESC,key LIMIT 4")?;
                        let mut rows=stmt.query(params![file.rowid]).map_err(cache_error)?;
                        let mut ids=Vec::with_capacity(4);
                        while let Some(row)=rows.next().map_err(cache_error)? {ids.push(get::<i64>(row,0)?);}
                        ids
                    };
                    let mut symbols=Vec::with_capacity(4);
                    for id in ids {symbols.push(symbol_by_id(sql,id)?.0.value);}
                    let linked=records::sample(&env,sql,&file.pointer.file,None)?;
                    Ok(Some(HookContext {file:file.pointer,symbols,callers:vec![],linked}))
                }
            }
        })
    }
}
fn usable(pointer: &CodePointer) -> bool {
    pointer.freshness == SnapshotFreshness::Current
        && !crate::policy::built_in_denied(&pointer.path)
}
