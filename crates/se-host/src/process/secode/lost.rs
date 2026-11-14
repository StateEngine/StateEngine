//! Native empty-scope proof closes a lost service without inventing final capture.
use super::*;
use se_proc::{CheckpointKind, ProcessRuntime, RecoveryOutcome, StopObservation};

impl LaunchCoordinator {
    pub(in crate::process) fn secode_loss_error(&self, work: &owned::Work) -> se_types::SeError {
        let next = se_core::ops::AgentCommand::launch_in_home(
            &work.meta.agent.id,
            &self.options.home,
            &work.meta.project.id,
            true,
        )
        .map(|command| command.command)
        .unwrap_or_else(|| "se launch <agent> --new --detach".into());
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

    pub(in crate::process) async fn observe_secode_service_loss(
        &self,
        work: &mut owned::Work,
        deadline: &Deadline,
    ) -> Result<bool> {
        let Some(slot) = self
            .secode_services
            .get(&work.meta.project.id, &work.meta.agent.id, deadline)
            .await?
        else {
            return Ok(false);
        };
        let mut service = lock_service(&slot, deadline).await?;
        if service.journal.session != work.meta.session
            || service
                .journal
                .client_closed
                .as_ref()
                .is_some_and(|closed| closed.capture_complete)
        {
            return Ok(false);
        }
        if let Some(owner) = service.process.clone() {
            let native = self.native.clone();
            let observed = self
                .store
                .pool
                .run_owned(deadline, move || {
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
            let native = self.native.clone();
            let generation = self.options.epoch.generation;
            let observed = self
                .store
                .pool
                .run_owned(deadline, move || {
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
        service.journal.lost = true;
        service.failure = None;
        service.control = None;
        service.persist(self, deadline).await?;
        work.secode_service_lost = true;
        Ok(true)
    }

    pub(super) async fn retire_lost_secode_service(
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
        if !service.journal.lost || closed.witness.scope_exit.exit_basis.is_none() {
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
        service.persist(self, deadline).await
    }
}
