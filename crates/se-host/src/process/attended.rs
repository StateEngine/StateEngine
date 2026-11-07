//! Human onboarding has no short readiness clock. Native observations and
//! publication remain bounded, and the ten-minute credential limit is unchanged.
use super::{events::Wake, owned::Work, *};
use crate::{LaunchOutcome, client::lease::Deadline};
use se_core::ops::{AgentCommand, agent_launch::ATTENDED_SETUP_EXPIRED};
use se_proc::{ProcessObservation, ProcessRuntime};
use se_types::{Detail, Result, SeError, details};
use std::time::Duration;

impl LaunchCoordinator {
    pub(super) async fn window_activation_deadline(
        &self,
        work: &Work,
        deadline: &Deadline,
    ) -> Result<i64> {
        let hash = work
            .pin_hash
            .ok_or_else(|| error("window setup", "launch pin is absent"))?;
        let session = work.meta.session.clone();
        let reader = self.store.reader.clone();
        let generation = self.store.generation;
        self.store
            .pool
            .run_owned(deadline, move || {
                let phase = reader
                    .read_phase()
                    .map_err(|e| se_core::store_error::store_error(&e))?;
                let result = (|| {
                    let owner = se_core::scope::require_present(
                        phase
                            .runtime_owner()
                            .map_err(|e| se_core::store_error::store_error(&e))?,
                        "window setup owner",
                        "Reconnect to the current runtime.",
                    )?;
                    if owner.generation != generation {
                        return Err(error("window setup owner", "runtime generation changed"));
                    }
                    let credential = se_core::scope::require_present(
                        phase
                            .credential(hash)
                            .map_err(|e| se_core::store_error::store_error(&e))?,
                        "window setup credential",
                        "Relaunch this agent from the owner terminal.",
                    )?;
                    if credential.session != session
                        || credential.state != se_store::CredentialState::Prepared
                    {
                        return Err(error(
                            "window setup credential",
                            "the original prepared session is required",
                        ));
                    }
                    Ok(credential.activation_deadline_us)
                })();
                crate::runtime::executor::close_read(result, phase.close())
            })
            .await
    }

    /// None means the original credential preparation expired, not readiness.
    pub(super) async fn wait_window(
        &self,
        process: Arc<se_proc::OwnedProcess>,
        wake: Arc<Wake>,
        activation_deadline: i64,
        relaunch: String,
        future: impl std::future::Future<Output = Result<LaunchOutcome>>,
    ) -> Result<Option<LaunchOutcome>> {
        let mut future = std::pin::pin!(future);
        loop {
            let changed = wake.event.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            wake.require_startup()?;
            let native = self.native.clone();
            let process = process.clone();
            let check = Deadline::idle()?.stage(Duration::from_secs(2))?;
            let observed = self
                .store
                .pool
                .run_owned(&check, move || {
                    native
                        .observe(&process)
                        .map_err(|e| error("window setup process", e))
                })
                .await?;
            if !matches!(observed.root, ProcessObservation::Live(_)) {
                return Err(SeError::new(Detail::LaunchFailed(details::LaunchFailed {
                    subject: "Claude window".into(),
                    reason: "the original Claude process closed before connecting to StateEngine"
                        .into(),
                    next_step: format!(
                        "Run `{relaunch}` to open another conversation; completed Claude onboarding is retained."
                    ),
                })));
            }
            if crate::runtime::start::now_unix_micros()? >= activation_deadline {
                return Ok(None);
            }
            tokio::select! {
                result = &mut future => return result.map(Some),
                () = &mut changed => (),
                () = tokio::time::sleep(Duration::from_secs(1)) => (),
            }
        }
    }

    /// Expiration disconnects StateEngine, not the person's native window.
    pub(super) async fn retain_expired_window(&self, work: &mut Work) -> Result<bool> {
        let Some(at) = work.attended_setup_deadline else {
            return Ok(false);
        };
        if work.activated || crate::runtime::start::now_unix_micros()? < at {
            return Ok(false);
        }
        let Some(process) = work.process.clone() else {
            return Ok(false);
        };
        let native = self.native.clone();
        let deadline = Deadline::idle()?.next_call()?;
        let observed = self
            .store
            .pool
            .run_owned(&deadline, move || {
                native
                    .observe(&process)
                    .map_err(|e| error("expired window process", e))
            })
            .await?;
        if !matches!(observed.root, ProcessObservation::Live(_)) {
            return Ok(false);
        }
        self.retire_session(work, ATTENDED_SETUP_EXPIRED, &deadline)
            .await?;
        work.setup_expired = true;
        Ok(true)
    }

    pub(super) fn expired_window_error(&self, work: &Work) -> SeError {
        let command = self.window_command(work, false);
        SeError::new(Detail::LaunchFailed(details::LaunchFailed {
            subject: work.meta.agent.name.clone(),
            reason: "Setup took longer than 10 minutes, so this window isn't connected to StateEngine. The window is still open.".into(),
            next_step: format!("Finish Claude's welcome, then run `{command}` to connect this agent. You won't need to redo completed onboarding."),
        }))
    }

    pub(super) fn window_command(&self, work: &Work, fresh: bool) -> String {
        AgentCommand::launch_in_home(
            &work.meta.agent.id,
            &self.options.home,
            &work.meta.project.id,
            fresh,
        )
        .map(|c| c.with_detach(false).command)
        .unwrap_or_else(|| AgentCommand::HOME_UNAVAILABLE.into())
    }
}
