//! Restore live services only after native recovery proved the original birth.
use super::*;
impl LaunchCoordinator {
    pub(in crate::process) async fn recover_control(
        &self,
        work: &mut Work,
        job: &Job,
        deadline: &Deadline,
    ) -> bool {
        work.recover_provider = false;
        let recovered = match deadline.stage(std::time::Duration::from_secs(20)) {
            Ok(bound) => self.restore_provider(work, &bound).await,
            Err(error) => Err(error),
        };
        if let Err(error) = recovered {
            let reason = format!(
                "{:?} agent {} ({}) session {}: provider control recovery failed: {error}. Preserve the original provider/session; inspect its protected rendezvous or use the exact public stop/resume command after proving native ownership. No replacement was launched or signalled.",
                work.meta.provider, work.meta.agent.name, work.meta.agent.id, work.meta.session
            );
            if let Ok(mut fault) = job.fault.lock() {
                *fault = Some(reason.clone());
            }
            eprintln!("{reason}");
            work.cleanup_failure = Some(error.body);
            let diagnostic = match deadline.stage(std::time::Duration::from_secs(2)) {
                Ok(bound) => self.provider_recovery_failed(work, reason, &bound).await,
                Err(error) => Err(error),
            };
            if let Err(error) = diagnostic {
                eprintln!("Provider recovery failure could not be retained: {error}");
                work.cleanup_failure = Some(error.body);
            }
            return false;
        }
        if let Ok(mut fault) = job.fault.lock() {
            *fault = None;
        }
        job.mail_pending
            .store(true, std::sync::atomic::Ordering::Release);
        true
    }
    pub(in crate::process) async fn provider_recovery_failed(
        &self,
        work: &Work,
        reason: String,
        deadline: &Deadline,
    ) -> Result<()> {
        let previous = self.head(work, deadline).await?;
        let identity = match &previous.current.body {
            EventBody::ProcessTransition { identity, .. } => *identity.clone(),
            _ => {
                return Err(error(
                    "provider recovery failure",
                    "native reconciliation is absent",
                ));
            }
        };
        self.mark_recovery_unproved(
            previous,
            identity,
            reason,
            work.cleanup_admission.clone(),
            deadline,
        )
        .await
    }
    pub(in crate::process) async fn restore_provider(
        &self,
        work: &mut Work,
        deadline: &Deadline,
    ) -> Result<()> {
        self.capture.wait_until_open(deadline).await?;
        let process = work
            .process
            .clone()
            .ok_or_else(|| error("provider recovery", "native owned process is absent"))?;
        let native = self.native.clone();
        let owned = process.clone();
        let observed = self
            .store
            .pool
            .run_owned(deadline, move || {
                native
                    .observe(&owned)
                    .map_err(|e| error("provider recovery birth", e))
            })
            .await?;
        if !matches!(observed.root, se_proc::ProcessObservation::Live(_)) {
            return Err(error(
                "provider recovery",
                "the original native provider birth is no longer live; no connection was adopted",
            ));
        }
        self.verify_retained_session(work, deadline).await?;
        if work.meta.provider == se_store::Provider::SeCode {
            self.restore_secode_work(work, deadline).await?;
        }
        if work.meta.capture {
            self.capture_progress(work, deadline).await?;
        }
        let identity = crate::SessionIdentity {
            project: work.meta.project.id.clone(),
            agent: work.meta.agent.id.clone(),
            session: work.meta.session.clone(),
        };
        let conversation = se_core::scope::require_present(
            work.meta.conversation.clone(),
            "provider recovery conversation",
            "Restore the original saved session before reconnecting.",
        )?;
        let binding = match work.meta.provider {
            se_store::Provider::SeCode => self.secode.recover(
                work.secode
                    .clone()
                    .ok_or_else(|| error("SE Code provider recovery", "original binding absent"))?,
            ),
            se_store::Provider::Codex => {
                self.codex
                    .recover(
                        &identity,
                        &conversation,
                        work.transcript.as_ref(),
                        work.meta.attended,
                        super::super::launch_util::call(self.store.generation, deadline)?,
                    )
                    .await?
            }
            _ => {
                return Err(error(
                    "Claude restart control",
                    "the original stdin stream cannot be reopened; preserve the session and use its exact public stop/resume command",
                ));
            }
        };
        let confirmed = async {
            let native = self.native.clone();
            let observed = self
                .store
                .pool
                .run_owned(deadline, move || {
                    native
                        .observe(&process)
                        .map_err(|e| error("provider recovered birth", e))
                })
                .await?;
            if !matches!(observed.root, se_proc::ProcessObservation::Live(_)) {
                return Err(error(
                    "provider recovery",
                    "the original provider exited during reconnect; no replacement was adopted",
                ));
            }
            if let Some(codex) = &binding.codex {
                codex.completion.arm(&work.wake.event)?;
            }
            if let Some(secode) = &binding.secode {
                secode.completion.arm(&work.wake.event)?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = confirmed {
            let cleanup = Deadline::idle()?.stage(std::time::Duration::from_secs(2))?;
            if let Err(failure) = self
                .harness_for(work.meta.provider)?
                .close_binding(
                    &binding,
                    super::super::launch_util::call(self.store.generation, &cleanup)?,
                )
                .await
            {
                return Err(error.with_cause(failure));
            }
            return Err(error);
        }
        work.binding = Some(binding);
        self.capture_progress(work, deadline).await?;
        Ok(())
    }
    async fn verify_retained_session(&self, work: &Work, deadline: &Deadline) -> Result<()> {
        let expected = work.pin_hash.ok_or_else(|| {
            error(
                "provider recovery session",
                "the protected cleanup/session record is unavailable",
            )
        })?;
        let home = self.options.home.clone();
        let meta = work.meta.clone();
        let reader = self.store.reader.clone();
        self.store
            .pool
            .run_owned(deadline, move || {
                use sha2::{Digest, Sha256};
                let files = se_proc::NativeStateFiles::open(&home)
                    .map_err(|e| error("provider recovery session", e))?;
                let pin = se_proc::read_session_pin(&files, meta.session.as_str())
                    .map_err(|e| error("provider recovery session", e))?;
                let actual: [u8; 32] = Sha256::digest(pin.expose()).into();
                if actual != expected {
                    return Err(error(
                        "provider recovery session",
                        "protected pin differs from the original committed session",
                    ));
                }
                let phase = reader
                    .read_phase()
                    .map_err(|e| se_core::store_error::store_error(&e))?;
                let result = (|| {
                    let credential = se_core::scope::require_present(
                        phase
                            .credential(actual)
                            .map_err(|e| se_core::store_error::store_error(&e))?,
                        "provider recovery credential",
                        "Restore the original active session credential.",
                    )?;
                    if credential.session != meta.session
                        || credential.agent != meta.agent.id
                        || credential.project != meta.project.id
                        || credential.purpose != "session"
                        || credential.state != se_store::CredentialState::Active
                        || credential.expires_at_us <= crate::runtime::start::now_unix_micros()?
                    {
                        return Err(error(
                            "provider recovery credential",
                            "the original session credential is not current and active",
                        ));
                    }
                    Ok(())
                })();
                crate::runtime::executor::close_read(result, phase.close())
            })
            .await
    }
}
