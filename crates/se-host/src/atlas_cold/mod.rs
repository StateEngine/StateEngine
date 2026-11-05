//! One derived cold epoch. Only the native private child invokes `run_child`.
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
use se_types::{SeError, code::AtlasText};
use std::time::{Duration, Instant};
pub const EXTRACTOR: &str = "atlas-semantic-2";
pub(crate) fn failure(reason: impl std::fmt::Display) -> SeError {
    SeError::invalid("Atlas cold index", &reason.to_string())
}
pub(crate) fn sql_deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
pub(crate) fn empty_coverage() -> Coverage {
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
fn parser_memory_guard() -> AtlasResult<()> {
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
pub fn private_entry() -> AtlasResult<u8> {
    let (mut channel, bytes) = se_proc::atlas_worker::WorkerChannel::receive().map_err(failure)?;
    let request: protocol::Request = serde_json::from_slice(&bytes).map_err(failure)?;
    let job = request.job;
    let result = run_child(&request, |reply| {
        let bytes = serde_json::to_vec(&reply).map_err(failure)?;
        channel.send(&bytes).map_err(failure)
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
    notify(protocol::Reply::Working {
        job: request.job,
        path: None,
        phase: protocol::Phase::Startup,
    })?;
    let deadline = Instant::now() + Duration::from_secs(899);
    // Coverage and publication scale with the captured prefix too. Reserve a
    // third of the existing job clock for finishing rather than spending it
    // all on discovery and losing every captured answer at the parent bound.
    let work_deadline = deadline - Duration::from_secs(300);
    let source = request.source()?;
    let scope = source.scope.clone();
    let cache = NativeAtlasCache::create(&request.home.to_local()?, scope.clone())?;
    let expected = cache.read_pointer()?;
    let expected_epoch = expected
        .as_ref()
        .map(|v| se_atlas::cache::pointer::decode(v, &scope).map(|p| p.epoch))
        .transpose()?;
    if expected_epoch != request.expected_epoch {
        return Err(failure("old epoch changed before child reservation"));
    }
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope: scope.clone(),
            epoch: request.epoch.clone(),
        },
        extractor_version: EXTRACTOR.into(),
        ignore_digest: request.ignore_digest,
        coverage: {
            let mut coverage = empty_coverage();
            coverage.history_unavailable = request.history_unavailable.clone();
            if coverage.history_unavailable.is_some() {
                coverage.reasons.push(CoverageReason::HistoryUnavailable);
            }
            coverage
        },
        state: IndexState::ColdIndexing {
            job: request.job,
            discovered_files: 0,
        },
    };
    let db = CacheConnection::create(
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
    notify(protocol::Reply::Working {
        job: request.job,
        path: None,
        phase: protocol::Phase::Discovery,
    })?;
    let discovery_complete = walk::files(&source, request, work_deadline, |entry| {
        let path = match entry {
            walk::Entry::Directory(path) => {
                return notify(protocol::Reply::Working {
                    job: request.job,
                    path,
                    phase: protocol::Phase::Discovery,
                });
            }
            walk::Entry::File(path) => path,
        };
        if coverage.discovered_files >= u64::from(request.max_files) {
            return Err(failure(
                "cold file count limit reached; candidate remains unpublished",
            ));
        }
        coverage.discovered_files += 1;
        ingest::file(&source, &db, &mut parser, &path, request, &mut |phase| {
            notify(protocol::Reply::Working {
                job: request.job,
                path: Some(path.clone()),
                phase,
            })
        })?;
        completed += 1;
        if completed.is_multiple_of(16) {
            notify(protocol::Reply::Progress {
                job: request.job,
                discovered: coverage.discovered_files,
                completed,
            })?;
        }
        notify(protocol::Reply::Working {
            job: request.job,
            path: Some(path.clone()),
            phase: protocol::Phase::Checkpoint,
        })?;
        // This private, exclusively owned epoch has no foreground readers.
        // A disk checkpoint uses the existing whole-job wall allowance, not
        // the short SQL query allowance; fsync can finish after that allowance
        // without SQLite's VM progress handler being able to interrupt it.
        if !db.checkpoint(deadline)? {
            return Err(failure("unpublished cold epoch checkpoint remains busy"));
        }
        db.release_cold_memory(sql_deadline())?;
        se_proc::atlas_worker::release_allocator_pages();
        Ok(())
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
            finish::limited_resolution(&db, after, deadline)?;
            break;
        }
        let next = db.read(sql_deadline(), |sql| {
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
        })?;
        let Some((id, path)) = next else { break };
        after = id;
        ingest::file(
            &source,
            &db,
            &mut parser,
            &RelativePath::new(&path)?,
            request,
            &mut |phase| {
                notify(protocol::Reply::Working {
                    job: request.job,
                    path: Some(RelativePath::new(&path)?),
                    phase,
                })
            },
        )?;
        se_proc::atlas_worker::release_allocator_pages();
        completed += 1;
        if completed.is_multiple_of(16) {
            notify(protocol::Reply::Progress {
                job: request.job,
                discovered: coverage.discovered_files,
                completed,
            })?;
        }
        notify(protocol::Reply::Working {
            job: request.job,
            path: Some(RelativePath::new(&path)?),
            phase: protocol::Phase::Checkpoint,
        })?;
        if !db.checkpoint(deadline)? {
            return Err(failure("unpublished cold epoch checkpoint remains busy"));
        }
        db.release_cold_memory(sql_deadline())?;
        se_proc::atlas_worker::release_allocator_pages();
    }
    coverage.discovery_complete = discovery_complete;
    notify(protocol::Reply::Working {
        job: request.job,
        path: None,
        phase: protocol::Phase::Finalize,
    })?;
    let summary = finish::finish(&db, coverage, deadline)?;
    // Closing the last writer checkpoints even a sub-threshold WAL. Exact
    // parent reopen/integrity validation happens only after process reap.
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
