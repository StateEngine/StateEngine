//! Shared shutdown for standalone children and embedded consumers. Every stage
//! runs even when an earlier stage fails; the returned owner retains custody.
use super::*;
use crate::client::{ClientOptions, endpoint::*, lease::Deadline};
use se_types::{Read, Result, SeError};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

pub struct HostShutdown {
    pub runtime: HostedRuntime,
    pub storage: Read<StorageDrainReport>,
    pub transport_closed: bool,
    pub endpoint_retired: bool,
    pub pending: Vec<String>,
    /// Includes errors retaining native reservations on pending transport close.
    pub errors: Vec<SeError>,
}
impl HostServeExit {
    /// Accepted tasks are already fenced and joined by serve. Drain errors and
    /// a disconnected stop client cannot skip transport or publication cleanup.
    /// Replies precede transport join because their channel is itself an instance.
    pub async fn finish(mut self, drain_deadline: &Deadline) -> HostShutdown {
        // serve has already spent part of this budget joining admitted calls and
        // delivering their replies. A caller may shorten it, never renew it.
        let drain_deadline = self.runtime.shutdown_deadline.as_ref().map_or_else(
            || drain_deadline.clone(),
            |bound| drain_deadline.capped_by(bound),
        );
        #[cfg(windows)]
        let started = std::time::Instant::now();
        #[cfg(windows)]
        trace("storage-drain-start", started, true);
        let mut errors: Vec<_> = self.failure.take().into_iter().collect();
        let mut pending: Vec<_> = errors.iter().map(ToString::to_string).collect();
        let storage = match self.runtime.drain_storage(&drain_deadline).await {
            Ok(report) => {
                pending.extend(report.pending.iter().cloned());
                if !matches!(report.backup, Read::Present { .. }) {
                    pending.push("Storage clean-close backup remains pending.".into());
                }
                Read::Present { value: report }
            }
            Err(error) => {
                pending.push(format!("Storage drain remains pending: {error}"));
                let failure = Read::Unreadable {
                    source: "host storage drain".into(),
                    reason: error.to_string(),
                    error: Some(Box::new(error.body.clone())),
                };
                errors.push(error);
                failure
            }
        };
        #[cfg(windows)]
        trace(
            "storage-drain-return",
            started,
            matches!(&storage, Read::Present { .. }),
        );
        match self.runtime.execution.pending_writes.describe() {
            Ok(identities) => pending.extend(identities),
            Err(error) => {
                pending.push(error.to_string());
                errors.push(error);
            }
        }
        let writer_joined = match &storage {
            Read::Present { value } => value.writer_joined,
            _ => self.runtime.flush.is_some(),
        };
        if let Some(flush) = &self.runtime.flush {
            for identity in &flush.indeterminate {
                pending.push(format!(
                    "Indeterminate original write identity: {identity:?}"
                ));
            }
        }
        if let Some(stop) = self.stop.take() {
            let mut reply_pending = pending.clone();
            reply_pending.push("Native transport release and endpoint retirement are pending; agent/debt/resume/final lease-release witnesses remain separate obligations.".into());
            let reply = RuntimeStopReply {
                epoch: stop.request().expected_epoch.clone(),
                generation: stop.request().generation,
                key: stop.request().key.clone(),
                outcome: RuntimeStopOutcome::Facts {
                    achieved: if writer_joined {
                        vec![RuntimeStopFact::WriterJoined]
                    } else {
                        vec![]
                    },
                    retained_resume: vec![],
                    pending: reply_pending,
                },
            };
            let result = match cleanup_deadline() {
                Ok(bound) => stop.reply(&reply, &bound).await,
                Err(error) => Err(error),
            };
            #[cfg(windows)]
            trace("stop-reply-return", started, result.is_ok());
            if let Err(error) = result {
                pending.push(format!("Stop reply delivery remains unconfirmed: {error}"));
                errors.push(error);
            }
        }
        let pool = self.runtime.blocking_pool();
        let (closed, retired) = self.listener.finish_transport(&pool).await;
        let transport_closed = closed.is_ok();
        let endpoint_retired = retired.is_ok();
        #[cfg(windows)]
        trace(
            "shutdown-return",
            started,
            transport_closed && endpoint_retired,
        );
        for (stage, result) in [
            ("Native transport release", closed),
            ("Endpoint retirement", retired),
        ] {
            if let Err(error) = result {
                pending.push(format!("{stage} remains pending: {error}"));
                errors.push(error);
            }
        }
        HostShutdown {
            runtime: self.runtime,
            storage,
            transport_closed,
            endpoint_retired,
            pending,
            errors,
        }
    }
}
/// Private Windows host diagnostics contain only fixed stages and measured time.
#[cfg(windows)]
pub(crate) fn trace(stage: &str, started: std::time::Instant, succeeded: bool) {
    eprintln!(
        "host shutdown pid={} stage={stage} elapsed_ms={} succeeded={succeeded}",
        std::process::id(),
        started.elapsed().as_millis()
    );
}
/// Cleanup gets its own finite budget after a possibly exhausted drain bound.
/// Stop-client cancellation never cancels ownership cleanup.
pub(crate) fn cleanup_deadline() -> Result<Deadline> {
    Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(5),
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}
