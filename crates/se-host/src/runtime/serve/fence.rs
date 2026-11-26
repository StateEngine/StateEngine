//! After the loop ends: fence admission, bound the shutdown, request the
//! authorized stop, then join every accepted task within that same budget.
use super::*;

impl HostServeExit {
    pub(super) async fn fence_and_join(
        &mut self,
        mut tasks: JoinSet<Result<ConnectionEnd>>,
        shutdown: &watch::Sender<Option<Deadline>>,
    ) {
        self.runtime.fenced.store(true, Ordering::Release);
        if let Err(error) = self.runtime.execution.mail_waits.close() {
            self.failure.get_or_insert(error);
        }
        self.runtime.phase = crate::HostPhase::Draining;
        // Waiting for the next request is cancellable; an admitted request owns
        // its execution and reply until completion. Charge that join against the
        // same shutdown budget used by storage drain, rather than renewing it.
        self.runtime.shutdown_deadline = match shutdown_bound(self.stop.as_deref()) {
            Ok(deadline) => Some(deadline),
            Err(error) => {
                self.failure.get_or_insert(error);
                None
            }
        };
        shutdown.send_replace(self.runtime.shutdown_deadline.clone());
        // A launch call can itself be waiting for readiness. Request its
        // authorized FULL stop before joining that call, while the writer is
        // still available; otherwise it spends shutdown's storage budget.
        if let (Some(custody), Some(deadline)) = (
            self.runtime.execution.custody.get().cloned(),
            self.runtime.shutdown_deadline.as_ref(),
        ) && let Err(error) = custody.begin_shutdown(deadline).await
        {
            self.failure.get_or_insert(error);
        }
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(ConnectionEnd::Stop(stop))) => {
                    refuse_raced_stop(&mut self.runtime, stop).await;
                }
                Ok(Err(error)) => self.runtime.failed_connection(error),
                #[cfg(any(target_os = "linux", target_os = "macos", windows))]
                Ok(Ok(ConnectionEnd::Atlas(Err(error)))) => {
                    self.failure.get_or_insert(error);
                }
                Ok(Ok(ConnectionEnd::CatchUp(Err(error)))) => self.runtime.failed_connection(error),
                Err(error) => {
                    self.failure.get_or_insert_with(|| {
                        se_core::scope::unreadable("joined host task", &error.to_string())
                    });
                }
                _ => (),
            }
        }
        self.failed_connections = self.runtime.connection_failures;
        self.last_connection_error = self.runtime.last_connection_error.clone();
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        if let (Some(service), Some(bound)) = (
            self.runtime.atlas_owner.clone(),
            self.runtime.shutdown_deadline.as_ref(),
        ) && let Err(error) =
            crate::runtime::atlas_owner::close(service, &self.runtime.execution, bound).await
        {
            self.failure.get_or_insert(error);
        }
    }
}
/// A second authenticated stop raced the fence. Its original control request
/// is refused, never relabelled as success.
async fn refuse_raced_stop(runtime: &mut HostedRuntime, stop: Box<AuthorizedStop>) {
    let error = SeError::invalid(
        "runtime stop",
        "the already admitted shutdown result; preserve this original key and rediscover",
    );
    let request = match stop.request() {
        Ok(request) => request,
        Err(error) => {
            runtime.failed_connection(error);
            return;
        }
    };
    let reply = crate::client::endpoint::RuntimeStopReply {
        epoch: request.expected_epoch.clone(),
        generation: request.generation,
        key: request.key.clone(),
        outcome: crate::client::endpoint::RuntimeStopOutcome::Refused {
            error: match se_types::ErrorEnvelope::new(error.body, &se_types::RenderCx::default()) {
                Ok(envelope) => envelope,
                Err(error) => {
                    runtime.failed_connection(error);
                    return;
                }
            },
        },
    };
    match runtime
        .shutdown_deadline
        .as_ref()
        .cloned()
        .map_or_else(|| options(CALL_TIMEOUT), Ok)
    {
        Ok(deadline) => {
            if let Err(error) = stop.reply(&reply, &deadline).await {
                runtime.failed_connection(error);
            }
        }
        Err(error) => runtime.failed_connection(error),
    }
}
