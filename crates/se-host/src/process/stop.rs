//! Graceful stop, exact native scope stop, durable terminal publication, then
//! credential/file retirement and native release. An incomplete witness keeps
//! the supervisor and its obligations live.
mod completion;
mod monitor;
use super::*;
use super::{
    launch::Work,
    launch_util::{call, wait},
};
use crate::client::lease::Deadline;
use se_core::ops::process_commit;
use se_proc::{CheckpointKind, CheckpointSource, ProcessRuntime, StopObservation};
use se_store::{EventBody, ProcessState, Snapshot};
use se_types::Result;
use std::time::Duration;

impl LaunchCoordinator {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
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
            let reconnecting = work.plan.as_ref().is_some_and(|plan| {
                !plan.input.fresh
                    && !plan.input.detach
                    && matches!(&plan.control.latest_session, se_types::Read::Present { value }
                        if se_core::ops::agent_launch::retryable_attended_setup(value))
            });
            let reason = if reconnecting {
                se_core::ops::agent_launch::ATTENDED_RECONNECT_FAILED
            } else {
                "launch preparation failed"
            };
            self.retire_session(work, reason, deadline).await?;
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
        if work.native_already_reconciled {
            return work
                .last_witness
                .clone()
                .map(|witness| StopObservation::Complete(Box::new(witness)))
                .ok_or_else(|| error("recovered exit", "no retained native exit proof"));
        }
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
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    #[cfg_attr(
        not(windows),
        expect(
            clippy::cognitive_complexity,
            reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
        )
    )]
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
        // Standalone takeover uses stop followed by launch. Close the old
        // binding durably before any interruption, even with an empty inbox;
        // failed native closure must never reopen external admission.
        self.revoke_credentials(work, deadline).await?;
        // The FULL transition rechecks the current control grant before even
        // closing provider stdin. Graceful closure is already a stop effect.
        if let Some(binding) = &work.binding {
            let graceful = deadline.stage(Duration::from_secs(5))?;
            match self
                .harness_for(work.meta.provider)?
                .graceful_stop(binding, call(self.store.generation, &graceful)?)
                .await
            {
                Ok(interrupt) if interrupt.requested => {
                    if binding.secode.is_some()
                        && let Err(error) = self.interrupt_secode_client(work, &graceful).await
                    {
                        work.stop_failure = Some(error.body);
                    }
                    // Codex's WebSocket close ends this client's transport,
                    // not its persistent app-server listener. Ask the exact
                    // owned Linux scope to terminate before the force interval.
                    #[cfg(target_os = "linux")]
                    if binding.codex.is_some() {
                        let owner = work.process.clone().ok_or_else(|| {
                            error("graceful stop", "owned native reference is absent")
                        })?;
                        let native = self.native.clone();
                        let generation = self.options.epoch.generation;
                        let at = graceful.at();
                        let attempt = self
                            .store
                            .pool
                            .run_owned(&graceful, move || {
                                let prepared = native
                                    .prepare_stop(&owner, generation, at)
                                    .map_err(|e| error("graceful stop preparation", e))?;
                                native
                                    .request_termination(prepared)
                                    .map_err(|e| error("graceful termination", e))?
                                    .dispatch
                                    .map_err(|e| error("graceful termination dispatch", e))
                            })
                            .await;
                        if let Err(error) = attempt {
                            work.stop_failure = Some(error.body);
                        }
                    }
                    work.stop_method = Some("graceful".into());
                    loop {
                        // Register before observing: a monitor can otherwise
                        // consume the single retained nudge between read/wait.
                        let changed = work.wake.event.notified();
                        tokio::pin!(changed);
                        changed.as_mut().enable();
                        if let StopObservation::Complete(witness) =
                            self.exit_observation(work, deadline).await?
                        {
                            return Ok(*witness);
                        }
                        // This read also runs once at the graceful deadline,
                        // before preparing any force against the provider.
                        if graceful.remaining().is_err() {
                            break;
                        }
                        let _ = tokio::time::timeout_at(
                            tokio::time::Instant::from_std(graceful.at()),
                            changed,
                        )
                        .await;
                    }
                }
                Ok(_) => {
                    if binding
                        .claude
                        .as_ref()
                        .is_some_and(|binding| binding.attended)
                    {
                        work.stop_method = Some("native-window-scope".into());
                    } else {
                        work.stop_failure = Some(
                            se_core::scope::unreadable(
                                "graceful stop",
                                "provider did not accept stdin closure",
                            )
                            .body,
                        )
                    }
                }
                Err(failure) => work.stop_failure = Some(failure.body),
            }
        }
        // Queue admission and identity-checked dispatch use the caller's clock.
        // The force interval measures exit after dispatch, not time waiting for
        // a worker on a slow or busy machine.
        let owner = work.process.clone().ok_or_else(|| {
            se_core::scope::unreadable("forced stop", "owned native reference is absent")
        })?;
        let native = self.native.clone();
        let generation = self.options.epoch.generation;
        let at = deadline.at();
        let prepared = self
            .store
            .pool
            .run_owned(deadline, move || {
                native
                    .prepare_stop(&owner, generation, at)
                    .map_err(|e| error("native stop preparation", e))
            })
            .await?;
        let native = self.native.clone();
        let attempt = self
            .store
            .pool
            .run_owned(deadline, move || {
                native
                    .request_stop(prepared)
                    .map_err(|e| error("exact native stop", e))
            })
            .await?;
        // A dispatch failure does not prevent observing a concurrent natural
        // exit; preserve it if the final bounded witness is still incomplete.
        let dispatch = attempt.dispatch;
        if matches!(dispatch, Ok(se_proc::StopDispatch::NotNeeded)) {
            if work.stop_method.as_deref() != Some("graceful") {
                work.stop_method = Some("already-exited".into());
            }
        } else if dispatch.is_ok() {
            work.stop_method = Some("forced".into());
        }
        let force = deadline.stage(Duration::from_millis(500))?;
        let (ticket, result) = self.stop_observation(attempt.ticket, deadline).await?;
        self.finish_stop_wait(work, ticket, result, dispatch.map(|_| ()), force, deadline)
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
        // A stopped resident client cannot emit another wake. Settle only
        // notices proved by the final canonical capture before ending its
        // recipient session; uncertain admissions remain retained and unread.
        self.reconcile_stopped_secode_mail(work, deadline).await?;
        let reason = match &work.capture_failure {
            Some(_) if work.secode_service_lost => format!(
                "{reason}; original SE Code service lost; final capture and uncertain input remain unproved; preserve the original history and use an explicit --new conversation"
            ),
            Some(error) if work.meta.provider == se_store::Provider::SeCode => format!(
                "{reason}; capture incomplete ({}); restore the original authenticated service and retry stop to reconcile its retained cursor",
                error.code().as_str()
            ),
            Some(error) if work.meta.provider == se_store::Provider::Acp => format!(
                "{reason}; protocol capture incomplete ({}); preserve the partial history and use --new to start a separate conversation without replaying interrupted input",
                error.code().as_str()
            ),
            Some(error) => format!(
                "{reason}; capture incomplete ({}); restore the original transcript and retry stop to reconcile its retained cursor before resuming",
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
