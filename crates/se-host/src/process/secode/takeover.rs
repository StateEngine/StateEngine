//! Explicit takeover may close the selected private service despite stale API state.
use super::*;
use se_proc::CheckpointKind;

impl LaunchCoordinator {
    pub(super) async fn force_retire_secode_service(
        &self,
        work: &mut owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        let slot = self
            .secode_services
            .get(&work.meta.project.id, &work.meta.agent.id, deadline)
            .await?
            .ok_or_else(|| {
                error(
                    "forced service replacement",
                    "original private service custody is unavailable",
                )
            })?;
        let mut service = lock_service(&slot, deadline).await?;
        if service.journal.session != work.meta.session {
            return Err(error(
                "forced service replacement",
                "the selected service session changed; no service was stopped",
            ));
        }
        self.force_retire_service(&mut service, deadline).await?;
        work.secode_service_lost = true;
        Ok(())
    }

    pub(super) async fn force_retire_service(
        &self,
        service: &mut Service,
        deadline: &Deadline,
    ) -> Result<()> {
        for auxiliary in Auxiliary::ALL {
            if service.owner(auxiliary).is_none()
                && service
                    .journal
                    .auxiliary(auxiliary)
                    .as_ref()
                    .is_some_and(|checkpoint| {
                        !matches!(checkpoint.checkpoint, CheckpointKind::Exit { .. })
                    })
            {
                self.recover_secode_auxiliary(service, auxiliary, deadline)
                    .await?;
            }
            if service.owner(auxiliary).is_some() {
                self.stop_secode_auxiliary(service, auxiliary, true, deadline)
                    .await?;
            }
        }
        for checkpoint in Auxiliary::ALL
            .into_iter()
            .filter_map(|key| service.journal.auxiliary(key).as_ref())
        {
            if !matches!(&checkpoint.checkpoint, CheckpointKind::Exit { witness, .. } if witness.scope_exit.exit_basis.is_some())
            {
                return Err(error(
                    "forced service replacement",
                    "an original native auxiliary scope remains unproved; no successor was launched",
                ));
            }
        }
        service.journal.lost = true;
        service.failure = None;
        service.control = None;
        service.persist(self, deadline).await?;
        Ok(())
    }
}
