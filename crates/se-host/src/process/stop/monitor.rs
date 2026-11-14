//! Lifecycle observation, capture/mail maintenance, and bounded retry wakeups.
use super::*;
use crate::process::{mail, supervisor::Job};
use std::sync::atomic::Ordering;

impl LaunchCoordinator {
    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(in crate::process) async fn monitor(self: &Arc<Self>, job: Arc<Job>) {
        let mut retry_at = None;
        let mut backoff = Duration::from_millis(100);
        let mut observation_failed = false;
        loop {
            let mut observation_retry_at = None;
            let capability_retry_at;
            let wake = {
                let mut state = job.state.lock().await;
                if state.released {
                    return;
                }
                let mut deadline = match Deadline::idle() {
                    Ok(value) => value,
                    Err(error) => {
                        state.cleanup_failure = Some(error.body);
                        return;
                    }
                };
                if state.native_already_reconciled
                    && let Err(error) = self.capture.wait_until_open(&deadline).await
                {
                    state.cleanup_failure = Some(error.body);
                    return;
                }
                let failed_start =
                    !state.setup_expired && matches!(&*job.ready.borrow(), Some(Err(_)));
                if failed_start
                    || (state.meta.provider == se_store::Provider::SeCode
                        && !state.active
                        && !state.activated)
                {
                    let result = match deadline.stage(Duration::from_secs(20)) {
                        Ok(bound) => self.cleanup_failed(&mut state, &bound).await,
                        Err(error) => Err(error),
                    };
                    match result {
                        Ok(()) => {
                            if !job.settled.swap(true, Ordering::AcqRel) {
                                self.activity
                                    .send_modify(|count| *count = count.saturating_sub(1));
                            }
                            return;
                        }
                        Err(error) => {
                            state.cleanup_failure = Some(error.body);
                            let wake = state.wake.clone();
                            drop(state);
                            // Retain the original lifecycle and release its lock
                            // between bounded cleanup attempts. Never replay input.
                            monitor_wake(
                                &wake.event,
                                Some(tokio::time::Instant::now() + Duration::from_secs(1)),
                            )
                            .await;
                            continue;
                        }
                    }
                }
                if state.recover_provider
                    && !self.recover_control(&mut state, &job, &deadline).await
                {
                    return;
                }
                capability_retry_at = self.maintain_secode_capability(&state, &deadline).await;
                let mut capture_pending = job.capture_pending.swap(false, Ordering::AcqRel);
                if let Some(binding) = state
                    .binding
                    .as_ref()
                    .and_then(|binding| binding.claude.as_ref())
                {
                    match binding.completion.take() {
                        Ok(Some(observed_at)) => {
                            deadline = deadline.observed_since(observed_at);
                            state.mail.idle = true;
                            job.mail_pending.store(true, Ordering::Release);
                            capture_pending = true;
                        }
                        Ok(None) => (),
                        Err(error) => {
                            let reported = self.report_capture_failure(&state, &error).await;
                            state.cleanup_failure = Some(reported.err().unwrap_or(error).body);
                        }
                    }
                }
                if let Some(binding) = state
                    .binding
                    .as_ref()
                    .and_then(|binding| binding.codex.as_ref())
                {
                    let changed = binding.completion.take();
                    let activity = binding.active_turn();
                    match activity {
                        Ok(turn) => state.mail.idle = turn.is_none(),
                        Err(error) => state.cleanup_failure = Some(error.body),
                    }
                    if changed {
                        job.mail_pending.store(true, Ordering::Release);
                        capture_pending = true;
                    }
                }
                if let Some(binding) = state
                    .binding
                    .as_ref()
                    .and_then(|binding| binding.secode.as_ref())
                {
                    let changed = binding.completion.take();
                    let failure = binding
                        .diagnostics
                        .lock()
                        .map_err(|_| error("SE Code stream state", "poisoned diagnostics"))
                        .and_then(|diagnostics| match &diagnostics.failure {
                            Some(body) => Err(se_types::SeError::from(body.clone())),
                            None => Ok(()),
                        });
                    if let Err(error) = failure {
                        state.cleanup_failure = Some(error.body);
                    }
                    if changed {
                        job.mail_pending.store(true, Ordering::Release);
                        capture_pending = true;
                    }
                }
                if let Some(binding) = state
                    .binding
                    .as_ref()
                    .and_then(|binding| binding.acp.as_ref())
                    .cloned()
                {
                    match binding.session.observe() {
                        Ok(observed) => {
                            state.mail.idle =
                                observed.active_input.is_none() && !observed.cancelling;
                            if !observed.completed.is_empty() {
                                if state.meta.capture {
                                    capture_pending = true;
                                } else {
                                    for request in &observed.completed {
                                        if let Err(error) =
                                            binding.session.discard_after_capture_opt_out(*request)
                                        {
                                            state.cleanup_failure = Some(error.body);
                                            break;
                                        }
                                    }
                                }
                                job.mail_pending.store(true, Ordering::Release);
                            }
                            if let Some(failure) = observed.failure {
                                state.cleanup_failure = Some(failure);
                            }
                        }
                        Err(error) => state.cleanup_failure = Some(error.body),
                    }
                }
                // Hook retries and native completions share one capture window.
                if capture_pending {
                    let result = match deadline.stage(Duration::from_secs(10)) {
                        Ok(bound) => self.capture_progress(&mut state, &bound).await,
                        Err(error) => Err(error),
                    };
                    if let Err(error) = result {
                        state.cleanup_failure = Some(error.body);
                    }
                }
                // Capture and mail each have a bounded maintenance window.
                // Release between them so an already queued stop acquires the
                // agent before another window starts; accepted work is joined.
                drop(state);
                let mut state = job.state.lock().await;
                if state.released {
                    return;
                }
                let result = self.exit_observation(&state, &deadline).await;
                if result.is_ok() && observation_failed {
                    if let Ok(mut fault) = job.fault.lock() {
                        *fault = None;
                    }
                    observation_failed = false;
                }
                match result {
                    Ok(StopObservation::Complete(witness)) => {
                        state.admission = state.cleanup_admission.clone();
                        match self.finish(&mut state, *witness, &deadline).await {
                            Ok(()) => {
                                job.settled.store(true, Ordering::Release);
                                self.activity
                                    .send_modify(|count| *count = count.saturating_sub(1));
                            }
                            Err(error) => {
                                if state.native_already_reconciled
                                    && let Ok(mut fault) = job.fault.lock()
                                {
                                    *fault = Some(error.to_string());
                                }
                                state.cleanup_failure = Some(error.body);
                            }
                        }
                        return;
                    }
                    Ok(_) => {
                        if !state.setup_expired
                            && retry_at.is_none_or(|at| tokio::time::Instant::now() >= at)
                            && job.mail_pending.swap(false, Ordering::AcqRel)
                        {
                            let result = match deadline.stage(Duration::from_secs(10)) {
                                Ok(bound) => self.deliver_mail(&mut state, &bound).await,
                                Err(error) => Err(error),
                            };
                            if let Err(error) = result {
                                if state.mail.flight.is_none() {
                                    job.mail_pending.store(true, Ordering::Release);
                                    retry_at = Some(tokio::time::Instant::now() + backoff);
                                    backoff = (backoff * 2).min(Duration::from_secs(2));
                                } else {
                                    retry_at = None;
                                }
                                mail::diagnostic::report(&state, &error);
                            } else {
                                retry_at = None;
                                backoff = Duration::from_millis(100);
                            }
                        }
                        state.wake.clone()
                    }
                    Err(error) => {
                        if let Ok(mut fault) = job.fault.lock() {
                            *fault = Some(format!(
                                "Native scope observation failed: {error}. Supervision and custody remain retained; retrying within one second. No scope exit has been proved."
                            ));
                        }
                        observation_failed = true;
                        state.cleanup_failure = Some(error.body);
                        observation_retry_at =
                            Some(tokio::time::Instant::now() + Duration::from_secs(1));
                        state.wake.clone()
                    }
                }
            };
            // Mail cannot be delivered until native observation succeeds. Its
            // expired retry clock must not spin while that observation is failing.
            let next = [observation_retry_at.or(retry_at), capability_retry_at]
                .into_iter()
                .flatten()
                .min();
            monitor_wake(&wake.event, next).await;
        }
    }
}

async fn monitor_wake(wake: &tokio::sync::Notify, retry_at: Option<tokio::time::Instant>) {
    let Some(at) = retry_at else {
        return wake.notified().await;
    };
    use std::{future::Future, task::Poll};
    let changed = wake.notified();
    let delayed = tokio::time::sleep_until(at);
    tokio::pin!(changed, delayed);
    std::future::poll_fn(|cx| {
        if changed.as_mut().poll(cx).is_ready() {
            return Poll::Ready(());
        }
        delayed.as_mut().poll(cx)
    })
    .await;
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    #[test]
    fn retry_timer_wakes_without_an_unrelated_event_and_keeps_native_events_prompt() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|error| {
                se_core::scope::unreadable("retry test executor", &error.to_string())
            })?;
        runtime.block_on(async {
            let wake = tokio::sync::Notify::new();
            let at = tokio::time::Instant::now() + Duration::from_millis(20);
            assert!(
                tokio::time::timeout(Duration::from_secs(1), monitor_wake(&wake, Some(at)))
                    .await
                    .is_ok()
            );
            wake.notify_one();
            let later = tokio::time::Instant::now() + Duration::from_secs(60);
            assert!(
                tokio::time::timeout(Duration::from_secs(1), monitor_wake(&wake, Some(later)))
                    .await
                    .is_ok()
            );
        });
        Ok(())
    }
}
