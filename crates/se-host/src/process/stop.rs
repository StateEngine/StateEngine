//! Graceful stop, exact native scope stop, durable terminal publication, then
//! credential/file retirement and native release. An incomplete witness keeps
//! the supervisor and its obligations live.
mod completion;
use super::*;
use super::{
    launch::Work,
    launch_util::{call, wait},
    supervisor::Job,
};
use crate::{Harness, client::lease::Deadline};
use se_core::ops::process_commit;
use se_proc::{CheckpointKind, CheckpointSource, ProcessRuntime, StopObservation};
use se_store::{EventBody, ProcessState, Snapshot};
use se_types::Result;
use std::{sync::atomic::Ordering, time::Duration};

impl LaunchCoordinator {
    pub(super) async fn monitor(self: &Arc<Self>, job: Arc<Job>) {
        loop {
            let wake = {
                let mut state = job.state.lock().await;
                if state.released {
                    return;
                }
                let deadline = match Deadline::idle() {
                    Ok(value) => value,
                    Err(error) => {
                        state.cleanup_failure = Some(error.body);
                        return;
                    }
                };
                if let Some(binding) = state
                    .binding
                    .as_ref()
                    .and_then(|binding| binding.claude.as_ref())
                {
                    match binding.completion.take() {
                        Ok(true) => {
                            let result = match deadline.stage(Duration::from_secs(10)) {
                                Ok(bound) => self.capture_progress(&mut state, &bound).await,
                                Err(error) => Err(error),
                            };
                            if let Err(error) = result {
                                state.cleanup_failure = Some(error.body);
                            }
                        }
                        Ok(false) => (),
                        Err(error) => {
                            let reported = self.report_capture_failure(&state, &error).await;
                            state.cleanup_failure = Some(reported.err().unwrap_or(error).body);
                        }
                    }
                }
                let result = self.exit_observation(&state, &deadline).await;
                match result {
                    Ok(StopObservation::Complete(witness)) => {
                        state.admission = state.cleanup_admission.clone();
                        match self.finish(&mut state, *witness, &deadline).await {
                            Ok(()) => {
                                job.settled.store(true, Ordering::Release);
                                self.activity
                                    .send_modify(|count| *count = count.saturating_sub(1));
                            }
                            Err(error) => state.cleanup_failure = Some(error.body),
                        }
                        return;
                    }
                    Ok(_) => state.wake.clone(),
                    Err(error) => {
                        state.cleanup_failure = Some(error.body);
                        return;
                    }
                }
            };
            wake.event.notified().await;
        }
    }
    pub(super) async fn cleanup_failed(&self, work: &mut Work, deadline: &Deadline) -> Result<()> {
        if work.reservation_uncertain {
            let actor = work.admission.actor.clone();
            let key = work.meta.request.clone();
            let session = work.meta.session.clone();
            self.store.read(work.cleanup_admission.clone(), deadline, move |cx| {
                let receipt = se_core::scope::require_present(cx.read.operation_receipt(actor,key).map_err(|e|se_core::store_error::store_error(&e))?, "uncertain launch reservation", "Retry the original launch key; no native effect can proceed until its FULL outcome is established.")?;
                let event = se_core::scope::require_present(cx.read.event(receipt.primary_event).map_err(|e|se_core::store_error::store_error(&e))?, "original launch event", "Keep the original request identity for reconciliation.")?;
                if !matches!(event.body, EventBody::SessionPrepared {session:found,..} if found==session) {
                    return Err(se_core::scope::unreadable("uncertain launch reservation", "the retained receipt differs from this exact preparation"));
                }
                Ok(())
            }).await?;
            work.committed = true;
            work.reservation_uncertain = false;
        }
        work.admission = work.cleanup_admission.clone();
        if !work.committed {
            return Ok(());
        }
        if work.native_already_reconciled {
            let witness = self.stop_native(work, deadline).await?;
            return self.finish(work, witness, deadline).await;
        }
        let agent = work.meta.agent.id.clone();
        let session = work.meta.session.clone();
        let actual = self.store.read(work.cleanup_admission.clone(), deadline, move |cx| {
            let target=se_core::scope::require_present(cx.read.control_target(agent).map_err(|e|se_core::store_error::store_error(&e))?, "failed launch session", "Keep its exact lifecycle for reconciliation.")?;
            let head = target.sessions.into_iter().chain(match target.latest_session {se_types::Read::Present {value}=>Some(value),_=>None}).find(|s|matches!(&s.current.body, EventBody::SessionPrepared {session:found,..}|EventBody::SessionActivated {session:found,..}|EventBody::SessionEnded {session:found,..}|EventBody::SessionRevoked {session:found,..} if found==&session));
            head.map(|head|head.current.body).ok_or_else(||se_core::scope::unreadable("failed launch session", "the exact committed preparation is absent"))
        }).await?;
        match actual {
            EventBody::SessionActivated { .. } => {
                work.active = true;
                work.activated = true;
            }
            EventBody::SessionEnded { .. } | EventBody::SessionRevoked { .. } => {
                work.session_retired = true
            }
            _ => (),
        }
        // Failed preparation loses both capabilities immediately, even when
        // native termination or file cleanup subsequently remains unproved.
        if !work.active && !work.session_retired {
            self.retire_session(work, "launch preparation failed", deadline)
                .await?;
        }
        if work.process.is_none() {
            let reservation = work.reservation.clone().ok_or_else(|| {
                se_core::scope::unreadable(
                    "launch cleanup",
                    "the durable reservation is unavailable",
                )
            })?;
            let native = self.native.clone();
            let generation = self.options.epoch.generation;
            let result = self
                .store
                .pool
                .run_owned(deadline, move || {
                    let plan = native
                        .plan_recovery(se_proc::RecoverySource::Reservation(Box::new(reservation)))
                        .map_err(|e| error("failed preparation recovery", e))?;
                    native
                        .recover(plan, generation)
                        .map_err(|e| error("failed preparation recovery", e))
                })
                .await?;
            match result {
                se_proc::RecoveryOutcome::Recovered { process, .. }
                | se_proc::RecoveryOutcome::PendingScope { process, .. } => {
                    work.process = Some(Arc::new(process))
                }
                se_proc::RecoveryOutcome::Exited(witness) => {
                    work.native_already_reconciled = true;
                    work.last_witness = Some((*witness).clone());
                    return self.finish(work, *witness, deadline).await;
                }
                _ => {
                    return Err(se_core::scope::unreadable(
                        "failed preparation custody",
                        "native recovery did not return an owned reference; reservation remains retained",
                    ));
                }
            }
        }
        // If exec was genuinely witnessed before provider readiness failed,
        // record that historical native fact without activating the session.
        if let Some(record) = work.record.as_ref().filter(|_| work.exec_observed) {
            let head = self.head(work, deadline).await?;
            if matches!(
                head.current.body,
                EventBody::ProcessTransition {
                    to: ProcessState::Starting,
                    ..
                }
            ) {
                let identity = native_record::identity_meta(
                    &work.meta,
                    CheckpointKind::Process(record.clone()),
                    Some((&record.root, record.argv_sha256)),
                    Some(record.guarantee),
                    &self.options.epoch.owner.fields().boot,
                )?;
                self.change(
                    work,
                    "exec-observed-before-readiness-failure",
                    identity,
                    (ProcessState::Starting, ProcessState::Running),
                    deadline,
                )
                .await?;
            }
        }
        let witness = self.stop_native(work, deadline).await?;
        self.finish(work, witness, deadline).await
    }
    pub(super) async fn exit_observation(
        &self,
        work: &Work,
        deadline: &Deadline,
    ) -> Result<StopObservation> {
        let owner = work.process.clone().ok_or_else(|| {
            se_core::scope::unreadable("native exit observation", "owned reference is unavailable")
        })?;
        let native = self.native.clone();
        self.store
            .pool
            .run_owned(deadline, move || {
                native
                    .witness_exit(&owner)
                    .map_err(|e| error("native scope exit witness", e))
            })
            .await
    }
    pub(super) async fn stop_native(
        &self,
        work: &mut Work,
        deadline: &Deadline,
    ) -> Result<se_proc::StopWitness> {
        // Recovery can prove exit without adopting a live native handle. Both
        // explicit stop and host shutdown must retain that fresh proof while
        // retrying later capture, session or file cleanup.
        if work.native_already_reconciled {
            return work
                .last_witness
                .clone()
                .ok_or_else(|| error("cold stop", "no fresh native exit proof"));
        }
        if let StopObservation::Complete(witness) = self.exit_observation(work, deadline).await? {
            return Ok(*witness);
        }
        let previous = self.head(work, deadline).await?;
        let (identity, from) = match &previous.current.body {
            EventBody::ProcessRegistered { identity, initial } => {
                (identity.as_ref().clone(), *initial)
            }
            EventBody::ProcessTransition { identity, to, .. } => (identity.as_ref().clone(), *to),
            _ => {
                return Err(se_core::scope::unreadable(
                    "stop CAS",
                    "wrong process projection",
                ));
            }
        };
        if from != ProcessState::StopRequested {
            self.change(
                work,
                "stop-requested",
                identity,
                (from, ProcessState::StopRequested),
                deadline,
            )
            .await?;
        }
        // The FULL transition rechecks the current control grant before even
        // closing provider stdin. Graceful closure is already a stop effect.
        if let Some(binding) = &work.binding {
            let graceful = deadline.stage(Duration::from_secs(5))?;
            match self
                .harness
                .graceful_stop(binding, call(self.store.generation, &graceful)?)
                .await
            {
                Ok(interrupt) if interrupt.requested => {
                    work.stop_method = Some("graceful".into());
                    loop {
                        if let StopObservation::Complete(witness) =
                            self.exit_observation(work, deadline).await?
                        {
                            return Ok(*witness);
                        }
                        if wait(&work.wake, &graceful).await.is_err() {
                            break;
                        }
                    }
                }
                Ok(_) => {
                    work.stop_failure = Some(
                        se_core::scope::unreadable(
                            "graceful stop",
                            "provider did not accept stdin closure",
                        )
                        .body,
                    )
                }
                Err(failure) => work.stop_failure = Some(failure.body),
            }
        }
        // Store admission and the graceful interval do not consume the native
        // force interval. Both stages remain capped by the original deadline.
        let force = deadline.stage(Duration::from_millis(500))?;
        let owner = work.process.clone().ok_or_else(|| {
            se_core::scope::unreadable("forced stop", "owned native reference is absent")
        })?;
        let native = self.native.clone();
        let generation = self.options.epoch.generation;
        let at = force.at();
        let prepared = self
            .store
            .pool
            .run_owned(&force, move || {
                native
                    .prepare_stop(&owner, generation, at)
                    .map_err(|e| error("native stop preparation", e))
            })
            .await?;
        let native = self.native.clone();
        let attempt = self
            .store
            .pool
            .run_owned(&force, move || {
                native
                    .request_stop(prepared)
                    .map_err(|e| error("exact native stop", e))
            })
            .await?;
        // A dispatch failure does not prevent observing a concurrent natural
        // exit; preserve it if the final bounded witness is still incomplete.
        let dispatch = attempt.dispatch;
        work.stop_method = Some("forced".into());
        let (ticket, result) = self.stop_observation(attempt.ticket, deadline).await?;
        self.finish_stop_wait(work, ticket, result, dispatch, force, deadline)
            .await
    }
    async fn stop_observation(
        &self,
        ticket: se_proc::StopTicket,
        deadline: &Deadline,
    ) -> Result<(se_proc::StopTicket, StopObservation)> {
        let native = self.native.clone();
        self.store
            .pool
            .run_owned(deadline, move || {
                let observed = native
                    .witness_stop(&ticket)
                    .map_err(|e| error("native stop witness", e))?;
                Ok((ticket, observed))
            })
            .await
    }

    async fn finish_stop_wait(
        &self,
        work: &mut Work,
        mut ticket: se_proc::StopTicket,
        mut observed: StopObservation,
        dispatch: se_proc::ProcResult<()>,
        force: Deadline,
        deadline: &Deadline,
    ) -> Result<se_proc::StopWitness> {
        loop {
            if let StopObservation::Complete(witness) = observed {
                return Ok(*witness);
            }
            if wait(&work.wake, &force).await.is_err() {
                // One final native read at the original force deadline.
                let (_, observed) = self.stop_observation(ticket, deadline).await?;
                if let StopObservation::Complete(witness) = observed {
                    return Ok(*witness);
                }
                let head = self.head(work, deadline).await?;
                let identity = match head.current.body {
                    EventBody::ProcessTransition { identity, .. } => *identity,
                    _ => {
                        return Err(se_core::scope::unreadable(
                            "stop outcome",
                            "missing StopRequested projection",
                        ));
                    }
                };
                self.change(
                    work,
                    "stop-unproved",
                    identity,
                    (ProcessState::StopRequested, ProcessState::StopUnproved),
                    deadline,
                )
                .await?;
                return Err(se_core::scope::unreadable(
                    "exact scope stop",
                    &format!(
                        "closure remains unproved at the achieved native bound; dispatch={dispatch:?}; observation={observed:?}"
                    ),
                ));
            }
            (ticket, observed) = self.stop_observation(ticket, deadline).await?;
        }
    }
    async fn revoke_credentials(&self, work: &mut Work, deadline: &Deadline) -> Result<()> {
        if !work.credentials_revoked {
            let session = work.meta.session.clone();
            let active = work.active;
            self.store
                .commit(
                    work.cleanup_admission.clone(),
                    deadline,
                    None,
                    move |kernel, cx| process_commit::revoke_binding(kernel, session, active, cx),
                )
                .await?;
            work.credentials_revoked = true;
        }
        Ok(())
    }
    pub(super) async fn retire_session(
        &self,
        work: &mut Work,
        reason: &'static str,
        deadline: &Deadline,
    ) -> Result<()> {
        self.revoke_credentials(work, deadline).await?;
        if let Err(error) = self.flush_capture(work, deadline).await {
            // A durable capture failure cannot keep a proved-empty native scope
            // and its revoked agent session active forever. Publication of that
            // failure must have succeeded before this retirement is legal.
            if !work.process_retired
                || work.last_witness.is_none()
                || work.capture_failure.is_none()
            {
                return Err(error);
            }
        }
        let reason = match &work.capture_failure {
            Some(error) => format!(
                "{reason}; capture incomplete ({}); native transcript and the durable capture failure are retained; launch this agent with --new for a fresh conversation",
                error.code().as_str()
            ),
            None => reason.to_owned(),
        };
        let session = work.meta.session.clone();
        let active = work.active;
        self.store
            .commit(
                work.cleanup_admission.clone(),
                deadline,
                None,
                move |kernel, cx| process_commit::end_binding(kernel, session, active, reason, cx),
            )
            .await?;
        work.session_retired = true;
        self.proofs.remove(&work.meta.session)?;
        Ok(())
    }
}
