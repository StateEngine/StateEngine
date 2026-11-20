//! Parent-side cold history phase. Git reuses the exactly reaped parser's
//! process reservation; SQL uses the measured host share, not a cold exemption.
use super::*;
use crate::atlas_git::{GitRegistration, GitRepository};
use se_atlas::history::{Commit, HistoryBound, HistoryFeed, HistoryLimit};
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
    ) -> AtlasResult<HistorySeed> {
        if Instant::now() >= deadline {
            return Err(failure("cold job deadline elapsed before Git history"));
        }
        let feed = self.read(request, deadline)?;
        // All Git processes and the private control directory are gone before
        // opening the writer; this phase cannot overlap the parser or renewal.
        let source = request.source()?;
        let profile = SqlProfile::from_qualified_overhead(self.overhead)?;
        let mut db = CacheConnection::open(
            cache,
            CacheIdentity {
                scope: source.scope,
                epoch: request.epoch.clone(),
            },
            ConnectionRole::HostWriter,
            &profile,
            deadline,
        )?
        .ok_or_else(|| failure("history candidate disappeared"))?;
        match feed {
            HistoryRead::Available(Some(feed)) => {
                let notes = se_atlas::history::commit_notes(&feed);
                let generation =
                    crate::apply::ingest(&mut db, &feed, sql_deadline().min(deadline))?.generation;
                // Per-commit omissions replace, never accumulate: they describe
                // the current history window and clear when it moves on.
                crate::apply::publish_coverage(
                    &mut db,
                    sql_deadline().min(deadline),
                    &notes,
                    None,
                )?;
                Ok((generation, None, notes))
            }
            HistoryRead::Unavailable(error) => {
                let diagnostic = error.body;
                crate::apply::publish_coverage(
                    &mut db,
                    sql_deadline().min(deadline),
                    &[],
                    Some(&diagnostic),
                )?;
                Ok((generation(&mut db, deadline)?, Some(diagnostic), Vec::new()))
            }
            HistoryRead::Available(None) => Ok((generation(&mut db, deadline)?, None, Vec::new())),
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
fn generation(db: &mut CacheConnection<'_>, deadline: Instant) -> AtlasResult<Generation> {
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
    let window = reader.window(&head, 4, deadline).map_err(failure)?;
    let limit = match window.limit {
        crate::atlas_git::HistoryLimit::Complete => HistoryLimit::Complete,
        crate::atlas_git::HistoryLimit::CommitCount => HistoryLimit::CommitCount,
        crate::atlas_git::HistoryLimit::Bytes => HistoryLimit::Bytes,
    };
    // The writer quantum fits on native paths before portability validation,
    // so a non-portable path in a commit the quantum degrades cannot unmake
    // the window; validation then runs once, on retained paths only.
    let pending = window
        .commits
        .into_iter()
        .map(PendingCommit::new)
        .collect::<Vec<_>>();
    let (pending, next, limit) = crate::quantum::fit_writer_quantum(pending, window.next, limit);
    let commits = pending
        .into_iter()
        .map(PendingCommit::commit)
        .collect::<AtlasResult<Vec<_>>>()?;
    let oldest = commits.last().map(|c| c.oid.clone());
    Ok(Some(HistoryFeed {
        project: request.project.clone(),
        root: request.root.clone(),
        expected: None,
        bound: HistoryBound {
            head,
            oldest,
            next,
            limit,
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
/// A changed-path window commit whose paths are still native strings, so
/// the writer quantum fits before portability validation.
struct PendingCommit {
    git: crate::atlas_git::GitCommit,
    withheld: Option<(String, u32)>,
}
impl PendingCommit {
    fn new(git: crate::atlas_git::GitCommit) -> Self {
        Self {
            git,
            withheld: None,
        }
    }
    fn commit(self) -> AtlasResult<Commit> {
        let (paths, paths_note, allowed_paths) = match self.withheld {
            Some((note, allowed)) => (Vec::new(), Some(note), Some(allowed)),
            None => (
                self.git
                    .paths
                    .iter()
                    .map(|path| RelativePath::new(path.as_str()))
                    .collect::<AtlasResult<Vec<_>>>()?,
                self.git.paths_note,
                self.git.allowed_paths,
            ),
        };
        Ok(Commit {
            oid: self.git.oid,
            parent: self.git.parent,
            author_unix_ms: self.git.author_unix_ms,
            author: self.git.author,
            subject: self.git.subject,
            paths,
            paths_note,
            allowed_paths,
        })
    }
}
impl crate::quantum::WriterQuantumCommit for PendingCommit {
    fn quantum_oid(&self) -> &str {
        &self.git.oid
    }
    fn quantum_native_paths(&self) -> &[String] {
        &self.git.paths
    }
    fn quantum_withhold(&mut self, note: &str, allowed: u32) {
        self.withheld = Some((note.to_owned(), allowed));
    }
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
