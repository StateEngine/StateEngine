//! Writer/storage shutdown stages. Native lifecycle, capture and delivery
//! coordinators must finish before the supervisor releases its exclusive lease.
use super::*;
use crate::client::lease::Deadline;
use se_core::store_error::store_error;
use se_store::{HostStore, WriterOwner};
use se_types::{Read, Result};

pub(crate) type WriterDrain = <se_store::SqliteWriter as WriterOwner>::Drain;
#[derive(Clone, Debug)]
pub struct StorageDrainReport {
    pub writer_joined: bool,
    pub flush: Read<se_store::FlushReport>,
    pub checkpoint: Read<se_store::CheckpointReport>,
    pub backup: Read<se_store::BackupReport>,
    pub pending: Vec<String>,
}
impl HostedRuntime {
    /// Call after fencing admission and joining accepted operation tasks. A
    /// timed-out join remains owned here and can be polled with a later bound.
    /// This method never claims agent/capture/debt closure or releases the lease.
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub async fn drain_storage(&mut self, deadline: &Deadline) -> Result<StorageDrainReport> {
        if let Some(report) = &self.storage_report {
            return Ok(report.clone());
        }
        if self.phase == crate::HostPhase::Poisoned {
            return Err(se_core::scope::unreadable(
                "host storage drain",
                "a prior join/close failed; retain the exclusive lease and its original failure",
            ));
        }
        self.fenced
            .store(true, std::sync::atomic::Ordering::Release);
        self.capture_fenced
            .store(true, std::sync::atomic::Ordering::Release);
        self.phase = crate::HostPhase::Draining;
        // Clean-close backup uses the SqliteHost's own two-slot reader budget,
        // rather than the runtime's configurable reader. Drain foreground work
        // before reaching that independent maintenance context.
        self.execution.blocking.quiesce(deadline).await?;
        let reads = self.admission_reads.clone();
        self.execution
            .blocking
            .run_owned(deadline, move || {
                reads.close().map_err(|error| store_error(&error))
            })
            .await?;
        let drain_budget = deadline.remaining()?;
        if self.drain.is_none()
            && let Some(writer) = self.writer.take()
        {
            self.drain = Some(Box::pin(writer.drain(drain_budget)));
        }
        if let Some(wait) = self.drain.as_mut() {
            let result = super::pool::within(deadline, wait.as_mut()).await?;
            self.drain = None;
            match result {
                Ok(drained) => {
                    self.drained = Some(drained.host);
                    self.flush = Some(drained.report);
                }
                Err(error) => {
                    self.phase = crate::HostPhase::Poisoned;
                    return Err(store_error(&error));
                }
            }
        }
        if self
            .flush
            .as_ref()
            .is_some_and(|flush| flush.pending_requests == 0 && flush.indeterminate.is_empty())
        {
            self.execution.pending_writes.clear()?;
        }
        let mut report = StorageDrainReport {
            writer_joined: self.flush.is_some(),
            flush: self.flush.clone().map_or_else(
                || Read::Unknown {
                    what: "writer join has not returned its report".into(),
                },
                |value| Read::Present { value },
            ),
            checkpoint: Read::Unknown {
                what: "checkpoint has not run".into(),
            },
            backup: Read::Unknown {
                what: "clean-close backup has not run".into(),
            },
            pending: vec![],
        };
        if let Some(flush) = &self.flush
            && (flush.pending_requests != 0 || !flush.indeterminate.is_empty())
        {
            report.pending.push(format!("Writer join reports {} pending requests and indeterminate original identities {:?}; resolve them before resource closure.", flush.pending_requests, flush.indeterminate));
            return Ok(report);
        }
        let close_permit = self.execution.blocking.admit_owned(deadline).await?;
        let remaining = deadline.remaining()?;
        if let Some(mut host) = self.drained.take() {
            let lease = std::sync::Arc::clone(&self.lease);
            let (checkpoint,backup)=self.execution.blocking.run_admitted_owned(close_permit,move || {
                let checkpoint=host.checkpoint(se_store::CheckpointMode::Truncate,lease.as_ref());
                if !matches!(&checkpoint,Ok(value) if !value.busy && value.checkpointed_frames==value.wal_frames) {
                    return Ok((checkpoint,None,Some(host)));
                }
                Ok((checkpoint,Some(host.close_clean(lease.as_ref(),remaining)),None))
            }).await.map(|(checkpoint,backup,host)| {self.drained=host;(checkpoint,backup)})?;
            report.checkpoint = match checkpoint {
                Ok(value) => Read::Present { value },
                Err(error) => {
                    report.pending.push(error.to_string());
                    Read::Unreadable {
                        source: "shutdown checkpoint".into(),
                        reason: error.to_string(),
                        error: Some(Box::new(store_error(&error).body)),
                    }
                }
            };
            report.backup = match backup {
                Some(Ok(value)) => {
                    self.phase = crate::HostPhase::Drained;
                    Read::Present { value }
                }
                Some(Err(error)) => {
                    self.phase = crate::HostPhase::Poisoned;
                    report.pending.push(error.to_string());
                    Read::Unreadable {
                        source: "shutdown backup".into(),
                        reason: error.to_string(),
                        error: Some(Box::new(store_error(&error).body)),
                    }
                }
                None => {
                    report.pending.push("Checkpoint remains busy or failed; maintenance host and exclusive lease are retained.".into());
                    Read::Unknown {
                        what: "clean close deferred until checkpoint succeeds".into(),
                    }
                }
            };
        }
        if self.phase == crate::HostPhase::Drained {
            self.storage_report = Some(report.clone());
        }
        Ok(report)
    }
}
