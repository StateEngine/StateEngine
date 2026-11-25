//! Native empty-scope proof closes a lost service without inventing final capture.
use super::*;
use se_proc::{CheckpointKind, ProcessRuntime, RecoveryOutcome, StopObservation};

impl<H: HostPort> Coordinator<'_, H> {
    pub fn secode_loss_error(&self, work: &impl SecodeWork) -> se_types::SeError {
        let next = se_core::ops::AgentCommand::launch_in_home(
            work.agent_id(),
            self.0.home(),
            work.project_id(),
            true,
        )
        .map(|command| command.command)
        .unwrap_or_else(|| "se launch <agent> --detach".into());
        let mut failure = error(
            "SE Code service lost",
            "the original native service scope exited; final capture and uncertain input remain unproved",
        );
        failure.body = failure.body.with_remedy(se_types::Remedy {
            text: format!(
                "Preserve the original profile and captured history. Start a different conversation with {next}; original input is not replayed. Ordinary se down can close the proved-empty service."
            ),
            command: None,
        });
        failure
    }

    pub async fn observe_secode_service_loss(
        &self,
        work: &mut impl SecodeWork,
        deadline: &Deadline,
    ) -> Result<bool> {
        let Some(slot) = self
            .0
            .services()
            .get(work.project_id(), work.agent_id(), deadline)
            .await?
        else {
            return Ok(false);
        };
        let mut service = lock_service(&slot, deadline).await?;
        if service.restart.is_some() {
            return Ok(false);
        }
        if service.journal.session != *work.session()
            || service
                .journal
                .client_closed
                .as_ref()
                .is_some_and(|closed| closed.capture_complete)
        {
            return Ok(false);
        }
        if let Some(owner) = service.process.clone() {
            let native = self.0.native().clone();
            let observed = self
                .0
                .run_blocking(deadline, move || {
                    native
                        .witness_exit(&owner)
                        .map_err(|e| error("SE Code lost service exit", e))
                })
                .await?;
            let StopObservation::Complete(witness) = observed else {
                return Ok(false);
            };
            if witness.scope_exit.exit_basis.is_none() {
                return Err(error(
                    "SE Code lost service",
                    "native service scope exit remains unproved",
                ));
            }
            self.retire_secode_auxiliary(&mut service, Auxiliary::Service, &witness, deadline)
                .await?;
        } else {
            let Some(CheckpointKind::Exit { source, .. }) = service
                .journal
                .service
                .as_ref()
                .map(|checkpoint| &checkpoint.checkpoint)
            else {
                return Ok(false);
            };
            let source = recovery::recovery_source(source);
            let native = self.0.native().clone();
            let generation = self.0.epoch().generation;
            let observed = self
                .0
                .run_blocking(deadline, move || {
                    let plan = native
                        .plan_recovery(source)
                        .map_err(|e| error("SE Code lost service recovery plan", e))?;
                    native
                        .recover(plan, generation)
                        .map_err(|e| error("SE Code lost service recovery", e))
                })
                .await?;
            match observed {
                RecoveryOutcome::Exited(witness) if witness.scope_exit.exit_basis.is_some() => {}
                RecoveryOutcome::Recovered { process, .. }
                | RecoveryOutcome::PendingScope { process, .. } => {
                    service.process = Some(Arc::new(process));
                    return Err(error(
                        "SE Code lost service",
                        "the terminal service checkpoint has a live or unproved native scope; retain original custody",
                    ));
                }
                _ => {
                    return Err(error(
                        "SE Code lost service",
                        "the original service scope is not proved empty; retain custody",
                    ));
                }
            }
        }
        service.live.invalidate()?;
        service.journal.lost = CustodyState::Lost;
        service.failure = None;
        service.control = None;
        service.persist(self.0, deadline).await?;
        work.set_secode_service_lost(true);
        Ok(true)
    }

    pub(crate) async fn retire_lost_secode_service(
        &self,
        service: &mut Service,
        deadline: &Deadline,
    ) -> Result<()> {
        let closed = service.journal.client_closed.as_ref().ok_or_else(|| {
            error(
                "SE Code lost service retirement",
                "client closure remains unproved",
            )
        })?;
        if !service.journal.lost.is_set() || closed.witness.scope_exit.exit_basis.is_none() {
            return Err(error(
                "SE Code lost service retirement",
                "original client and service scope exit must both be proved",
            ));
        }
        for key in Auxiliary::ALL {
            if service.owner(key).is_some()
                || service.journal.auxiliary(key).as_ref().is_some_and(|checkpoint| {
                    !matches!(&checkpoint.checkpoint, CheckpointKind::Exit { witness, .. } if witness.scope_exit.exit_basis.is_some())
                })
            {
                return Err(error(
                    "SE Code lost service retirement",
                    "an original auxiliary scope remains unproved",
                ));
            }
        }
        self.retire_secode_registration(service, deadline).await?;
        service.journal.retired = true;
        service.persist(self.0, deadline).await
    }
}
