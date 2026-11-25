//! Lifecycle observation, capture/mail maintenance, and bounded retry wakeups.
use super::supervisor::Job;
use super::*;
use crate::client::lease::Deadline;
use se_proc::StopObservation;
use std::{sync::atomic::Ordering, time::Duration};

/// What one monitor pass leaves for the loop, acted on after the agent's lock
/// is released.
enum Pass {
    Done,
    /// Retain the lifecycle and retry within one second. Never replay input.
    RetrySoon(Arc<events::Wake>),
    Wait {
        wake: Arc<events::Wake>,
        observation_retry_at: Option<tokio::time::Instant>,
        capability_retry_at: Option<tokio::time::Instant>,
        pace_at: Option<tokio::time::Instant>,
        nudge_at: Option<tokio::time::Instant>,
    },
}
/// Backoff for mail delivery that failed before any input was in flight.
struct MailRetry {
    at: Option<tokio::time::Instant>,
    backoff: Duration,
}
impl LaunchCoordinator {
    pub(in crate::process) async fn monitor(self: &Arc<Self>, job: Arc<Job>) {
        let mut mail_retry = MailRetry {
            at: None,
            backoff: Duration::from_millis(100),
        };
        let mut observation_failed = false;
        loop {
            match self
                .monitor_pass(&job, &mut mail_retry, &mut observation_failed)
                .await
            {
                Pass::Done => return,
                Pass::RetrySoon(wake) => {
                    monitor_wake(
                        &wake.event,
                        Some(tokio::time::Instant::now() + Duration::from_secs(1)),
                    )
                    .await;
                }
                Pass::Wait {
                    wake,
                    observation_retry_at,
                    capability_retry_at,
                    pace_at,
                    nudge_at,
                } => {
                    // Mail cannot be delivered until native observation succeeds. Its
                    // expired retry clock must not spin while that observation is failing.
                    // Paced mail stays pending and wakes this loop when its gap ends.
                    let paced = pace_at.filter(|_| job.mail_pending.load(Ordering::Acquire));
                    let next = [
                        observation_retry_at.or(mail_retry.at),
                        capability_retry_at,
                        paced,
                        nudge_at,
                    ]
                    .into_iter()
                    .flatten()
                    .min();
                    monitor_wake(&wake.event, next).await;
                }
            }
        }
    }
    /// One supervision pass: cleanup or recovery first, then capture, native
    /// exit observation, and mail, each under its own bounded window.
    async fn monitor_pass(
        self: &Arc<Self>,
        job: &Arc<Job>,
        mail_retry: &mut MailRetry,
        observation_failed: &mut bool,
    ) -> Pass {
        let mut state = job.state.lock().await;
        if state.released {
            return Pass::Done;
        }
        let mut deadline = match Deadline::idle() {
            Ok(value) => value,
            Err(error) => {
                state.cleanup_failure = Some(error.body);
                return Pass::Done;
            }
        };
        if state.native_already_reconciled
            && let Err(error) = self.capture.wait_until_open(&deadline).await
        {
            state.cleanup_failure = Some(error.body);
            return Pass::Done;
        }
        if let Some(pass) = self.cleanup_unstarted(job, &mut state, &deadline).await {
            return pass;
        }
        if state.recover_provider && !self.recover_control(&mut state, job, &deadline).await {
            return Pass::Done;
        }
        if state.recover_provider {
            return Pass::RetrySoon(state.wake.clone());
        }
        let capability_retry_at = self.maintain_secode_capability(&state, &deadline).await;
        self.maintain_capture(job, &mut state, &mut deadline).await;
        // Capture and mail each have a bounded maintenance window.
        // Release between them so an already queued stop acquires the
        // agent before another window starts; accepted work is joined.
        drop(state);
        let mut state = job.state.lock().await;
        if state.released {
            return Pass::Done;
        }
        let result = self.exit_observation(&state, &deadline).await;
        if result.is_ok() && *observation_failed {
            if let Ok(mut fault) = job.fault.lock() {
                *fault = None;
            }
            *observation_failed = false;
        }
        match result {
            Ok(StopObservation::Complete(witness)) => {
                self.finish_observed(job, &mut state, *witness, &deadline)
                    .await;
                Pass::Done
            }
            Ok(_) => {
                if self.maybe_stop_one_shot(&mut state, job, &deadline).await {
                    return Pass::Done;
                }
                let pace_at = self.mail_pace(&state, job);
                self.deliver_due_mail(job, &mut state, mail_retry, pace_at, &deadline)
                    .await;
                let nudge_at = self.nudge(&mut state, job, &deadline).await;
                Pass::Wait {
                    wake: state.wake.clone(),
                    observation_retry_at: None,
                    capability_retry_at,
                    pace_at,
                    nudge_at,
                }
            }
            Err(error) => {
                if let Ok(mut fault) = job.fault.lock() {
                    *fault = Some(format!(
                        "Native scope observation failed: {error}. Supervision and custody remain retained; retrying within one second. No scope exit has been proved."
                    ));
                }
                *observation_failed = true;
                state.cleanup_failure = Some(error.body);
                Pass::Wait {
                    wake: state.wake.clone(),
                    observation_retry_at: Some(
                        tokio::time::Instant::now() + Duration::from_secs(1),
                    ),
                    capability_retry_at,
                    pace_at: None,
                    nudge_at: None,
                }
            }
        }
    }
    /// A failed start, or an SE Code launch that never activated, is cleaned
    /// up before any other maintenance; a failed cleanup retries.
    async fn cleanup_unstarted(
        &self,
        job: &Job,
        state: &mut owned::Work,
        deadline: &Deadline,
    ) -> Option<Pass> {
        let failed_start = !state.setup_expired && matches!(&*job.ready.borrow(), Some(Err(_)));
        if !(failed_start
            || (state.meta.provider == se_store::Provider::SeCode
                && !state.active
                && !state.activated))
        {
            return None;
        }
        let result = match deadline.stage(Duration::from_secs(20)) {
            Ok(bound) => self.cleanup_failed(state, &bound).await,
            Err(error) => Err(error),
        };
        Some(match result {
            Ok(()) => {
                if !job.settled.swap(true, Ordering::AcqRel) {
                    self.activity
                        .send_modify(|count| *count = count.saturating_sub(1));
                }
                Pass::Done
            }
            Err(error) => {
                state.cleanup_failure = Some(error.body);
                // Retain the original lifecycle and release its lock
                // between bounded cleanup attempts. Never replay input.
                Pass::RetrySoon(state.wake.clone())
            }
        })
    }
    /// Folds the binding's latest observation into this pass, then runs one
    /// capture window when a hook retry or native completion is pending.
    async fn maintain_capture(&self, job: &Job, state: &mut owned::Work, deadline: &mut Deadline) {
        let mut capture_pending = job.capture_pending.swap(false, Ordering::AcqRel);
        if let Some(binding) = &state.binding {
            let observed = binding.observe(state.meta.capture);
            if let Some(at) = observed.observed_at {
                *deadline = deadline.clone().observed_since(at);
            }
            if let Some(idle) = observed.idle {
                state.mail.idle = idle;
            }
            if observed.mail_pending {
                job.mail_pending.store(true, Ordering::Release);
            }
            capture_pending |= observed.capture_pending;
            if let Some(error) = observed.capture_failure {
                let reported = self.report_capture_failure(state, &error).await;
                state.cleanup_failure = Some(reported.err().unwrap_or(error).body);
            }
            if let Some(failure) = observed.failure {
                state.cleanup_failure = Some(failure);
            }
        }
        // Hook retries and native completions share one capture window.
        if capture_pending {
            let result = match deadline.stage(Duration::from_secs(10)) {
                Ok(bound) => self.capture_progress(state, &bound).await,
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                state.cleanup_failure = Some(error.body);
            }
        }
    }
    async fn finish_observed(
        &self,
        job: &Job,
        state: &mut owned::Work,
        witness: se_proc::StopWitness,
        deadline: &Deadline,
    ) {
        state.admission = state.cleanup_admission.clone();
        match self.finish(state, witness, deadline).await {
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
    }
    /// Delivers pending mail once its retry and pacing gaps allow, backing off
    /// only when the failure left no input in flight.
    async fn deliver_due_mail(
        &self,
        job: &Job,
        state: &mut owned::Work,
        retry: &mut MailRetry,
        pace_at: Option<tokio::time::Instant>,
        deadline: &Deadline,
    ) {
        if !(!state.setup_expired
            && retry.at.is_none_or(|at| tokio::time::Instant::now() >= at)
            && pace_at.is_none()
            && job.mail_pending.swap(false, Ordering::AcqRel))
        {
            return;
        }
        let result = match deadline.stage(Duration::from_secs(10)) {
            Ok(bound) => {
                let reoffer =
                    if (state.mail.idle || state.secode.is_some()) && state.mail.flight.is_none() {
                        job.mail_reoffer.swap(false, Ordering::AcqRel)
                    } else {
                        false
                    };
                let result = self.deliver_mail(state, reoffer, &bound).await;
                if result.is_err() && reoffer {
                    job.mail_reoffer.store(true, Ordering::Release);
                }
                result
            }
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            if state.mail.flight.is_none() {
                job.mail_pending.store(true, Ordering::Release);
                retry.at = Some(tokio::time::Instant::now() + retry.backoff);
                retry.backoff = (retry.backoff * 2).min(Duration::from_secs(2));
            } else {
                retry.at = None;
            }
            mail::diagnostic::report(state, &error);
        } else {
            retry.at = None;
            retry.backoff = Duration::from_millis(100);
        }
    }
}

/// The configured gap between wakes for mail: 0 (off, the default) through an
/// hour. Host start calls this so an out-of-range value refuses loudly.
pub fn mail_wake_interval(runtime: &se_config::config_policy::RuntimeConfig) -> Result<Duration> {
    match runtime.mail_wake_interval_seconds.unwrap_or(0) {
        seconds @ 0..=3_600 => Ok(Duration::from_secs(u64::from(seconds))),
        _ => Err(se_types::SeError::new(
            se_types::Detail::ConfigurationInvalid(se_types::details::ConfigurationInvalid {
                subject: "runtime.mail_wake_interval_seconds".into(),
                reason: "expected 0 (off) through 3600 seconds".into(),
                next_step: "Correct the selected user config.toml and retry.".into(),
            }),
        )),
    }
}
impl LaunchCoordinator {
    /// When pending mail may next wake this agent, if the configured gap since
    /// its last wake has not passed. A redelivery the runtime itself arms (an
    /// owner's explicit wake or recovery) is never held, and no sender's label
    /// is consulted.
    pub(super) fn mail_pace(&self, state: &owned::Work, job: &Job) -> Option<tokio::time::Instant> {
        let interval = mail_wake_interval(&self.options.configuration.runtime).ok()?;
        if interval.is_zero() || job.mail_reoffer.load(Ordering::Acquire) {
            return None;
        }
        let at = state.mail.last_offer? + interval;
        (at > tokio::time::Instant::now()).then_some(at)
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
