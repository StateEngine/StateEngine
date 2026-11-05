//! Parent-side cold history phase. Git reuses the exactly reaped parser's
//! process reservation; SQL uses the measured host share, not a cold exemption.
use super::*;
use se_atlas::history::{Commit, HistoryBound, HistoryFeed, HistoryLimit};
use se_proc::atlas_git::{GitRegistration, GitRepository};
use std::path::PathBuf;

enum HistoryRead {
    Available(Option<HistoryFeed>),
    Unavailable(SeError),
}
pub(super) struct Plan {
    metadata: GitMetadataRegistration,
    overhead: u32,
}
impl Plan {
    pub(super) fn new(
        metadata: GitMetadataRegistration,
        profile: Option<&SqlProfile>,
    ) -> AtlasResult<Self> {
        let overhead = profile
            .and_then(SqlProfile::qualified_overhead_bytes)
            .ok_or_else(|| {
                failure("Git history in the parent requires measured host SQL overhead")
            })?;
        Ok(Self { metadata, overhead })
    }
    pub(super) fn seed(
        self,
        cache: &NativeAtlasCache,
        request: &protocol::Request,
        deadline: Instant,
    ) -> AtlasResult<(Generation, Option<se_types::ErrorBody>)> {
        if Instant::now() >= deadline {
            return Err(failure("cold job deadline elapsed before Git history"));
        }
        let feed = self.read(request, deadline)?;
        // All Git processes and the private control directory are gone before
        // opening the writer; this phase cannot overlap the parser or renewal.
        let source = request.source()?;
        let profile = SqlProfile::from_qualified_overhead(self.overhead)?;
        let db = CacheConnection::open(
            cache,
            CacheIdentity {
                scope: source.scope,
                epoch: request.epoch.clone(),
            },
            ConnectionRole::HostWriter,
            &profile,
            sql_deadline().min(deadline),
        )?
        .ok_or_else(|| failure("history candidate disappeared"))?;
        match feed {
            HistoryRead::Available(Some(feed)) => Ok((
                se_atlas::history::ingest(&db, &feed, sql_deadline().min(deadline))?.generation,
                None,
            )),
            HistoryRead::Unavailable(error) => {
                let diagnostic = error.body;
                db.write(131072, sql_deadline().min(deadline), |sql| {
                    let saved: String = sql
                        .prepare("SELECT coverage_json FROM meta WHERE singleton=1")?
                        .query_row([], |r| r.get(0))
                        .map_err(failure)?;
                    let mut coverage: Coverage = serde_json::from_str(&saved).map_err(failure)?;
                    coverage.history_unavailable = Some(diagnostic.clone());
                    if !coverage
                        .reasons
                        .contains(&CoverageReason::HistoryUnavailable)
                    {
                        coverage.reasons.push(CoverageReason::HistoryUnavailable);
                    }
                    let state = IndexState::VerificationNeeded {
                        reason: CoverageReason::HistoryUnavailable,
                    };
                    sql.prepare(
                        "UPDATE meta SET coverage_json=?1,state_json=?2 WHERE singleton=1",
                    )?
                    .execute([
                        serde_json::to_string(&coverage).map_err(failure)?,
                        serde_json::to_string(&state).map_err(failure)?,
                    ])
                    .map_err(failure)?;
                    Ok(())
                })?;
                Ok((generation(&db, deadline)?, Some(diagnostic)))
            }
            HistoryRead::Available(None) => Ok((generation(&db, deadline)?, None)),
        }
    }
    // Unavailable enrichment is data. Failed process or private-directory
    // cleanup remains an adoption error.
    fn read(&self, request: &protocol::Request, deadline: Instant) -> AtlasResult<HistoryRead> {
        let image = match git_image() {
            Ok(image) => image,
            Err(error) => return Ok(HistoryRead::Unavailable(error)),
        };
        let home = request.home.to_local()?;
        let parent = home
            .parent()
            .ok_or_else(|| failure("Atlas home has no parent"))?;
        se_proc::NativeStateFiles::open(parent).map_err(failure)?;
        let control = parent.join(format!(".se-atlas-git-{}", request.epoch.as_str()));
        let registration = GitRegistration {
            git_directory: self.metadata.physical_git_directory.clone(),
            common_directory: self.metadata.physical_common_directory.clone(),
            git_identity: self.metadata.git_directory_identity,
            common_identity: self.metadata.common_directory_identity,
        };
        let reader = match GitRepository::open(&image, &registration, &control) {
            Ok(reader) => reader,
            Err(error) => {
                return match std::fs::symlink_metadata(&control) {
                    Err(absent) if absent.kind() == std::io::ErrorKind::NotFound => {
                        Ok(HistoryRead::Unavailable(failure(error)))
                    }
                    Ok(_) => Err(failure("Git control directory remains after failed setup")
                        .with_cause(error)),
                    Err(check) => Err(failure(check).with_cause(error)),
                };
            }
        };
        let result = feed(&reader, request, deadline).and_then(|feed| {
            if let Some(feed) = &feed {
                feed.validate()?;
            }
            Ok(feed)
        });
        match reader.close().map_err(failure) {
            Ok(()) => Ok(match result {
                Ok(feed) => HistoryRead::Available(feed),
                Err(error) => HistoryRead::Unavailable(error),
            }),
            Err(close) => Err(match result {
                Err(error) => error.with_cause(close),
                Ok(_) => close,
            }),
        }
    }
}
fn generation(db: &CacheConnection<'_>, deadline: Instant) -> AtlasResult<Generation> {
    db.read(sql_deadline().min(deadline), |sql| {
        let value: i64 = sql
            .prepare("SELECT index_generation FROM meta WHERE singleton=1")?
            .query_row([], |r| r.get(0))
            .map_err(failure)?;
        Ok(Generation(value.try_into().map_err(failure)?))
    })
}

fn feed(
    reader: &GitRepository,
    request: &protocol::Request,
    job_deadline: Instant,
) -> AtlasResult<Option<HistoryFeed>> {
    let Some(head) = reader.head().map_err(failure)? else {
        return Ok(None);
    };
    let deadline = (Instant::now() + Duration::from_secs(60)).min(job_deadline);
    let mut window = reader.window(&head, 4, deadline).map_err(failure)?;
    let mut paths = window.commits.iter().map(|c| c.paths.len()).sum::<usize>();
    while paths > 32 && window.commits.len() > 1 {
        let removed = window
            .commits
            .pop()
            .ok_or_else(|| failure("history window disappeared"))?;
        paths -= removed.paths.len();
        window.next = Some(removed.oid);
        window.limit = se_proc::atlas_git::HistoryLimit::CommitCount;
    }
    if paths > 32 {
        return Err(failure(
            "Git history's newest complete commit exceeds 32 changed paths; source index remains available",
        ));
    }
    let oldest = window.commits.last().map(|c| c.oid.clone());
    let commits = window
        .commits
        .into_iter()
        .map(|commit| {
            Ok(Commit {
                oid: commit.oid,
                parent: commit.parent,
                author_unix_ms: commit.author_unix_ms,
                author: commit.author,
                subject: commit.subject,
                paths: commit
                    .paths
                    .into_iter()
                    .map(|path| RelativePath::new(&path))
                    .collect::<AtlasResult<_>>()?,
            })
        })
        .collect::<AtlasResult<Vec<_>>>()?;
    Ok(Some(HistoryFeed {
        project: request.project.clone(),
        root: request.root.clone(),
        expected: None,
        bound: HistoryBound {
            head,
            oldest,
            next: window.next,
            limit: match window.limit {
                se_proc::atlas_git::HistoryLimit::Complete => HistoryLimit::Complete,
                se_proc::atlas_git::HistoryLimit::CommitCount => HistoryLimit::CommitCount,
                se_proc::atlas_git::HistoryLimit::Bytes => HistoryLimit::Bytes,
            },
        },
        observed_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(failure)?
            .as_millis()
            .try_into()
            .map_err(failure)?,
        commits,
    }))
}
fn git_image() -> AtlasResult<PathBuf> {
    let paths = std::env::var_os("PATH")
        .ok_or_else(|| failure("Git history requires Git on the host PATH; PATH is absent"))?;
    for directory in std::env::split_paths(&paths) {
        if !directory.is_absolute() {
            continue;
        }
        let image = directory.join("git");
        match std::fs::metadata(&image) {
            Ok(metadata) if metadata.is_file() => return image.canonicalize().map_err(failure),
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(failure(error)),
        }
    }
    Err(failure(
        "Git history requires a native Git executable on the host PATH; install Git and restart this home",
    ))
}
