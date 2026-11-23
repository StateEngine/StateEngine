//! What one root's index can honestly claim. `Current` holds only when
//! discovery finished, no batch is pending, the dirty set is empty and not
//! overflowed, no file failed to read, and the watch is armed. Skipped files
//! (binary, minified, private, unsupported) and Git history never hold a
//! root back from `Current`.
use crate::dirty::DirtySet;
use se_types::{
    ErrorBody, SeError,
    code::{AtlasJobId, CacheEpoch, Coverage, CoverageReason, IndexState},
    details,
};

/// Where the writer is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The writer has not opened the store yet.
    Opening,
    /// A cold build is running; `job` numbers builds of this root.
    Cold {
        job: u64,
        discovered: u64,
    },
    /// A stat walk is finding what changed while nothing watched.
    Reconciling,
    Ready,
    /// The root or its store cannot be used; the text says why.
    Failed(String),
    Stopped,
}

/// Whether the watcher can report changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Watch {
    Pending,
    Armed { directories: u64 },
    Failed(String),
}

/// File counts of the last build plus everything since.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub discovered: u64,
    pub indexed: u64,
    /// Files that could not be read; retried when they next change.
    pub failed: u64,
    /// Directories discovery could not list.
    pub unlisted_directories: u64,
}

#[derive(Clone, Debug)]
pub struct Progress {
    pub phase: Phase,
    pub counts: Counts,
    pub discovery_complete: bool,
    /// A writer batch is committing.
    pub batch_running: bool,
    pub watch: Watch,
    pub epoch: Option<CacheEpoch>,
    pub generation: Option<u64>,
}

impl Default for Progress {
    fn default() -> Self {
        Self {
            phase: Phase::Opening,
            counts: Counts::default(),
            discovery_complete: false,
            batch_running: false,
            watch: Watch::Pending,
            epoch: None,
            generation: None,
        }
    }
}

impl Progress {
    /// The settling invariant.
    pub fn current(&self, dirty: &DirtySet) -> bool {
        self.phase == Phase::Ready
            && self.discovery_complete
            && !self.batch_running
            && dirty.is_empty()
            && self.counts.failed == 0
            && matches!(self.watch, Watch::Armed { .. })
    }

    pub fn state(&self, dirty: &DirtySet) -> IndexState {
        match &self.phase {
            Phase::Failed(reason) => IndexState::Unreadable {
                error: unreadable(reason),
            },
            Phase::Stopped => IndexState::Closed,
            Phase::Opening => IndexState::Opening,
            Phase::Cold { job, discovered } => IndexState::ColdIndexing {
                job: job_id(*job),
                discovered_files: *discovered,
            },
            Phase::Reconciling => self.updating(dirty, 1),
            Phase::Ready if self.current(dirty) => IndexState::Current,
            Phase::Ready if self.batch_running || !dirty.is_empty() => {
                self.updating(dirty, u32::from(self.batch_running))
            }
            Phase::Ready => match &self.watch {
                Watch::Failed(_) | Watch::Pending => IndexState::VerificationNeeded {
                    reason: CoverageReason::WatchLoss,
                },
                Watch::Armed { .. } if self.counts.failed > 0 => IndexState::Partial {
                    error: partial(&format!(
                        "{} files could not be read; each is retried when it next changes",
                        self.counts.failed
                    )),
                },
                Watch::Armed { .. } => IndexState::Partial {
                    error: partial(&format!(
                        "discovery stopped early; {} directories could not be listed",
                        self.counts.unlisted_directories
                    )),
                },
            },
        }
    }

    fn updating(&self, dirty: &DirtySet, batches: u32) -> IndexState {
        IndexState::Updating {
            pending_files: dirty.len() as u64,
            pending_change_batches: batches.max(u32::from(dirty.overflowed())),
            discovery_complete: self.discovery_complete,
        }
    }

    pub fn coverage(&self, dirty: &DirtySet) -> Coverage {
        let (watched, armed) = match self.watch {
            Watch::Armed { directories } => (directories, true),
            _ => (0, false),
        };
        let mut reasons = Vec::new();
        if !dirty.is_empty() || self.batch_running {
            reasons.push(CoverageReason::StaleSnapshot);
        }
        if !armed && self.phase == Phase::Ready {
            reasons.push(CoverageReason::WatchLoss);
        }
        if self.counts.failed > 0 {
            reasons.push(CoverageReason::ReadFailure);
        }
        Coverage {
            discovered_files: self.counts.discovered,
            indexed_files: self.counts.indexed,
            partial_files: 0,
            deferred_files: 0,
            failed_files: self.counts.failed,
            discovery_complete: self.discovery_complete,
            stale_files: dirty.len() as u64 + u64::from(dirty.overflowed()),
            resolved_references: 0,
            name_only_references: 0,
            watched_directories: watched,
            unwatched_directories: u64::from(!armed),
            watch_discovery_complete: armed,
            watch_stats_started: None,
            watch_activation_attempts: 0,
            watch_limited_activations: 0,
            reasons,
            history_unavailable: None,
            history_commit_notes: Vec::new(),
        }
    }
}

/// Build numbers become the job id the wire reports.
pub fn job_id(job: u64) -> AtlasJobId {
    let mut bytes = [0; 16];
    bytes[8..].copy_from_slice(&job.to_be_bytes());
    AtlasJobId(bytes)
}

fn unreadable(reason: &str) -> ErrorBody {
    SeError::new(se_types::Detail::SourceUnreadable(
        details::SourceUnreadable {
            subject: "the Atlas code index".into(),
            reason: reason.into(),
            next_step: "Restore access to the project folder and the host state folder, then run se down and se up.".into(),
        },
    ))
    .body
}

fn partial(reason: &str) -> ErrorBody {
    SeError::new(se_types::Detail::SourceUnreadable(
        details::SourceUnreadable {
            subject: "part of the project folder".into(),
            reason: reason.into(),
            next_step: "Restore read access to those files; hits from the rest of the project are still returned.".into(),
        },
    ))
    .body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dirty::Change;

    fn ready() -> Progress {
        Progress {
            phase: Phase::Ready,
            discovery_complete: true,
            watch: Watch::Armed { directories: 1 },
            ..Progress::default()
        }
    }

    #[test]
    fn current_needs_every_part_of_the_invariant() {
        let clean = DirtySet::default();
        assert_eq!(ready().state(&clean), IndexState::Current);
        let mut dirty = DirtySet::default();
        dirty.mark("a.rs", Change::Modified);
        assert!(matches!(ready().state(&dirty), IndexState::Updating { .. }));
        let mut lost = DirtySet::default();
        lost.lose();
        assert!(matches!(ready().state(&lost), IndexState::Updating { .. }));
        let mut busy = ready();
        busy.batch_running = true;
        assert!(matches!(busy.state(&clean), IndexState::Updating { .. }));
        let mut unwatched = ready();
        unwatched.watch = Watch::Failed("limit".into());
        assert!(matches!(
            unwatched.state(&clean),
            IndexState::VerificationNeeded { .. }
        ));
        let mut failed = ready();
        failed.counts.failed = 1;
        assert!(matches!(failed.state(&clean), IndexState::Partial { .. }));
        let mut walk = ready();
        walk.discovery_complete = false;
        assert!(matches!(walk.state(&clean), IndexState::Partial { .. }));
        let cold = Progress {
            phase: Phase::Cold {
                job: 1,
                discovered: 9,
            },
            ..ready()
        };
        assert!(matches!(
            cold.state(&clean),
            IndexState::ColdIndexing { .. }
        ));
    }

    #[test]
    fn stale_counts_include_an_overflow() {
        let mut lost = DirtySet::default();
        lost.lose();
        assert_eq!(ready().coverage(&lost).stale_files, 1);
        assert!(
            ready()
                .coverage(&lost)
                .reasons
                .contains(&CoverageReason::StaleSnapshot)
        );
    }
}
