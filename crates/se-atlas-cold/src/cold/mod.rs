//! One derived cold epoch. Only the native private child invokes `run_child`.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
mod cpu;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
mod finish;
#[cfg(target_os = "linux")]
mod history;
#[cfg(any(windows, target_os = "macos"))]
#[path = "history_unavailable.rs"]
mod history;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
mod ingest;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
pub mod job;
pub mod protocol;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
mod walk;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
use crate::atlas_cache::NativeAtlasCache;
use crate::atlas_source::NativeAtlasSource;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
use se_atlas::{
    cache::{connection::*, *},
    parse::SemanticParser,
};
use se_atlas::{errors::AtlasResult, lifecycle::*, model::*, source::RegisteredSource};
use se_types::{
    ErrorBody, SeError,
    code::{AtlasText, HistoryCommitNote},
};
pub(super) type HistorySeed = (Generation, Option<ErrorBody>, Vec<HistoryCommitNote>);
use std::time::{Duration, Instant};
pub const EXTRACTOR: &str = "atlas-semantic-2";
pub fn failure(reason: impl std::fmt::Display) -> SeError {
    SeError::invalid("Atlas cold index", &reason.to_string())
}
pub fn sql_deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
pub fn empty_coverage() -> Coverage {
    Coverage {
        discovered_files: 0,
        indexed_files: 0,
        partial_files: 0,
        deferred_files: 0,
        failed_files: 0,
        discovery_complete: false,
        stale_files: 0,
        resolved_references: 0,
        name_only_references: 0,
        watched_directories: 0,
        unwatched_directories: 0,
        watch_discovery_complete: false,
        watch_stats_started: None,
        watch_activation_attempts: 0,
        watch_limited_activations: 0,
        history_unavailable: None,
        reasons: Vec::new(),
        history_commit_notes: Vec::new(),
    }
}
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
pub(crate) fn parse_budget() -> ParseBudget {
    ParseBudget {
        max_source_bytes: 524288,
        max_rows: 65536,
        max_work: Duration::from_millis(200),
        reserved_bytes: 49_000_000,
    }
}
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
pub fn parser_memory_guard() -> AtlasResult<()> {
    cpu::check()?;
    let (used, measurement) = se_proc::atlas_worker::memory_usage().map_err(failure)?;
    // Reserve space for cancellation, fallible extraction, SQL and a native
    // allocation between Tree-sitter's progress checks, including realloc copy.
    #[cfg(target_os = "linux")]
    let reusable = se_proc::atlas_worker::reusable_arena_bytes();
    #[cfg(any(windows, target_os = "macos"))]
    let reusable = 0;
    let requested = used.saturating_sub(reusable).saturating_add(8_000_000);
    #[cfg(target_os = "linux")]
    let ceiling = se_proc::atlas_worker::ADDRESS_SPACE_BYTES;
    #[cfg(any(windows, target_os = "macos"))]
    let ceiling = se_proc::atlas_worker::MEMORY_BYTES;
    if requested > ceiling {
        return Err(SeError::new(se_types::Detail::AtlasResourceBudget(
            se_types::details::AtlasResourceBudget {
                resource: format!(
                    "Atlas cold {measurement}, including 8 MB cancellation/SQL margin and {reusable} reusable arena bytes (credit capped at 2 MB)"
                ),
                requested,
                available: ceiling,
            },
        )));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
pub fn private_entry_with(
    channel: &mut se_proc::atlas_worker::WorkerChannel,
    bytes: &[u8],
) -> AtlasResult<u8> {
    let request: protocol::Request = serde_json::from_slice(bytes).map_err(failure)?;
    let job = request.job;
    let result = run_child(&request, |reply| {
        let frame = serde_json::to_vec(&reply).map_err(failure)?;
        channel.send(&frame).map_err(failure)?;
        if matches!(
            reply,
            protocol::Reply::Working {
                phase: protocol::Phase::SourceRead
                    | protocol::Phase::Resolve
                    | protocol::Phase::Commit,
                ..
            }
        ) {
            channel.await_source_read().map_err(failure)?;
        }
        Ok(())
    });
    let reply = match result {
        Ok(summary) => protocol::Reply::Completed {
            job,
            summary: Box::new(summary),
        },
        Err(error) => protocol::Reply::Failed {
            job,
            error: error.body,
        },
    };
    channel
        .send(&serde_json::to_vec(&reply).map_err(failure)?)
        .map_err(failure)?;
    channel.await_reap().map_err(failure)?;
    Ok(if matches!(reply, protocol::Reply::Completed { .. }) {
        0
    } else {
        1
    })
}
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
pub(crate) fn run_child(
    request: &protocol::Request,
    mut notify: impl FnMut(protocol::Reply) -> AtlasResult<()>,
) -> AtlasResult<IndexSummary> {
    request.validate()?;
    notify(working(request, None, protocol::Phase::Startup))?;
    let deadline = Instant::now() + Duration::from_secs(899);
    // Coverage and publication scale with the captured prefix too. Reserve a
    // third of the existing job clock for finishing rather than spending it
    // all on discovery and losing every captured answer at the parent bound.
    let work_deadline = deadline - Duration::from_secs(300);
    let source = request.source()?;
    let scope = source.scope.clone();
    let cache = reserve(request, &scope)?;
    let seed = cold_seed(request, &scope);
    let mut db = CacheConnection::create(
        &cache,
        &seed,
        ConnectionRole::ColdWriter,
        &SqlProfile::contained_cold(),
        deadline,
    )?;
    let mut parser = SemanticParser::contained_cold(scope)?;
    parser.set_resource_guard(parser_memory_guard);
    let mut completed = 0u64;
    let mut coverage = seed.coverage.clone();
    notify(working(request, None, protocol::Phase::Discovery))?;
    let discovery_complete = walk::files(&source, request, work_deadline, |entry| {
        let path = match entry {
            walk::Entry::Directory {
                path,
                #[cfg(all(windows, feature = "listener"))]
                identity,
            } => {
                #[cfg(all(windows, feature = "listener"))]
                db.write(65536, sql_deadline(), |sql| {
                    sql.prepare("INSERT INTO watch_directories(descriptor,path,identity) SELECT coalesce(min(descriptor),0)-1,?1,?2 FROM watch_directories WHERE descriptor<0")?
                        .execute((path.as_ref().map_or("", |path| path.as_str()), identity.as_slice()))
                        .map_err(failure)?;
                    Ok(())
                })?;
                return notify(working(request, path, protocol::Phase::Discovery));
            }
            walk::Entry::File(path) => path,
        };
        if coverage.discovered_files >= u64::from(request.max_files) {
            return Err(failure(
                "cold file count limit reached; candidate remains unpublished",
            ));
        }
        coverage.discovered_files += 1;
        ingest_one(&source, &mut db, &mut parser, request, &path, &mut notify)?;
        completed += 1;
        let discovered = coverage.discovered_files;
        settle_file(
            &mut db,
            request,
            &mut notify,
            completed,
            discovered,
            path,
            deadline,
        )
    })?;
    // Resolve against the completed catalog. Walking SQL in small key windows
    // avoids retaining a source inventory or reparsing once per graph edge.
    let mut after = 0i64;
    loop {
        // Preserve captured files even when discovery is incomplete. Cross-file
        // resolution improves those rows, rather than discarding all of them.
        // Keep the reserved part of the existing job budget for coverage,
        // checkpoint and exact-reap publication; skipped files stay partial.
        if !discovery_complete || Instant::now() >= work_deadline {
            finish::limited_resolution(&mut db, after, deadline)?;
            break;
        }
        let Some((id, path)) = next_file(&mut db, after)? else {
            break;
        };
        after = id;
        let path = RelativePath::new(&path)?;
        ingest_one(&source, &mut db, &mut parser, request, &path, &mut notify)?;
        se_proc::atlas_worker::release_allocator_pages();
        completed += 1;
        let discovered = coverage.discovered_files;
        settle_file(
            &mut db,
            request,
            &mut notify,
            completed,
            discovered,
            path,
            deadline,
        )?;
    }
    coverage.discovery_complete = discovery_complete;
    notify(working(request, None, protocol::Phase::Finalize))?;
    db.prepare_cold_publication()?;
    let summary = finish::finish(&mut db, coverage, deadline)?;
    db.finish_cold_publication(deadline)?;
    // Exact parent reopen/integrity validation happens only after process reap.
    drop(parser);
    drop(db);
    drop(cache);
    notify(protocol::Reply::Progress {
        job: request.job,
        discovered: summary.coverage.discovered_files,
        completed,
    })?;
    Ok(summary)
}
/// Open the cache and refuse unless its published epoch is still the one the
/// parent expected when it reserved this child.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn reserve(
    request: &protocol::Request,
    scope: &se_atlas::scope::Scope,
) -> AtlasResult<NativeAtlasCache> {
    let cache = NativeAtlasCache::create(&request.home.to_local()?, scope.clone())?;
    let expected = cache.read_pointer()?;
    let expected_epoch = expected
        .as_ref()
        .map(|v| se_atlas::cache::pointer::decode(v, scope).map(|p| p.epoch))
        .transpose()?;
    if expected_epoch != request.expected_epoch {
        return Err(failure("old epoch changed before child reservation"));
    }
    Ok(cache)
}
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn working(
    request: &protocol::Request,
    path: Option<RelativePath>,
    phase: protocol::Phase,
) -> protocol::Reply {
    protocol::Reply::Working {
        job: request.job,
        path,
        phase,
    }
}
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn cold_seed(request: &protocol::Request, scope: &se_atlas::scope::Scope) -> CacheSeed {
    let mut coverage = empty_coverage();
    coverage.history_unavailable = request.history_unavailable.clone();
    if coverage.history_unavailable.is_some() {
        coverage.reasons.push(CoverageReason::HistoryUnavailable);
    }
    CacheSeed {
        identity: CacheIdentity {
            scope: scope.clone(),
            epoch: request.epoch.clone(),
        },
        extractor_version: EXTRACTOR.into(),
        ignore_digest: request.ignore_digest,
        coverage,
        state: IndexState::ColdIndexing {
            job: request.job,
            discovered_files: 0,
        },
    }
}
/// Index one file, reporting each of its phases against that path.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn ingest_one(
    source: &RegisteredSource<NativeAtlasSource>,
    db: &mut CacheConnection<'_>,
    parser: &mut SemanticParser,
    request: &protocol::Request,
    path: &RelativePath,
    notify: &mut impl FnMut(protocol::Reply) -> AtlasResult<()>,
) -> AtlasResult<()> {
    ingest::file(source, db, parser, path, request, &mut |phase| {
        notify(working(request, Some(path.clone()), phase))
    })
}
/// Report progress every sixteen files, then checkpoint and release memory.
/// This private, exclusively owned epoch has no foreground readers. A disk
/// checkpoint uses the whole-job wall allowance, not the short SQL query
/// allowance; fsync can finish after that allowance without SQLite's VM
/// progress handler being able to interrupt it.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn settle_file(
    db: &mut CacheConnection<'_>,
    request: &protocol::Request,
    notify: &mut impl FnMut(protocol::Reply) -> AtlasResult<()>,
    completed: u64,
    discovered: u64,
    path: RelativePath,
    deadline: Instant,
) -> AtlasResult<()> {
    if completed.is_multiple_of(16) {
        notify(protocol::Reply::Progress {
            job: request.job,
            discovered,
            completed,
        })?;
    }
    notify(working(request, Some(path), protocol::Phase::Checkpoint))?;
    if !db.checkpoint(deadline)? {
        return Err(failure("unpublished cold epoch checkpoint remains busy"));
    }
    db.release_cold_memory(sql_deadline())?;
    se_proc::atlas_worker::release_allocator_pages();
    Ok(())
}
/// The next captured file after `after` by id, or none once the catalog ends.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn next_file(db: &mut CacheConnection<'_>, after: i64) -> AtlasResult<Option<(i64, String)>> {
    db.read(sql_deadline(), |sql| {
        let mut statement =
            sql.prepare("SELECT id,path FROM files WHERE id>?1 ORDER BY id LIMIT 1")?;
        let mut rows = statement.query([after]).map_err(failure)?;
        let Some(row) = rows.next().map_err(failure)? else {
            return Ok(None);
        };
        Ok(Some((
            row.get::<_, i64>(0).map_err(failure)?,
            row.get::<_, String>(1).map_err(failure)?,
        )))
    })
}
