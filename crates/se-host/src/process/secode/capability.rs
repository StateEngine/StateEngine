//! Re-present an owned credential after a service-generation change. This does
//! not adopt a new native process, release a hold or replay uncertain input.
use super::*;
use crate::harness::secode_process::{CapabilityRepair, Control, NoticeBinding, RepairPlan};
use se_store::{EventBody, Snapshot};
use sha2::{Digest, Sha256};
use std::time::Duration;

const CHECK_INTERVAL: Duration = Duration::from_secs(5);

impl LaunchCoordinator {
    pub(in crate::process) async fn require_secode_capability_settled(
        &self,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        let slot = self
            .secode_services
            .get(&work.meta.project.id, &work.meta.agent.id, deadline)
            .await?
            .ok_or_else(|| {
                error(
                    "SE Code capability repair",
                    "original service custody is absent",
                )
            })?;
        let service = lock_service(&slot, deadline).await?;
        if service
            .journal
            .capability_repair
            .as_ref()
            .is_some_and(|repair| repair.after.is_none())
        {
            return Err(error(
                "SE Code capability repair",
                "the original credential PUT remains unconfirmed; waiting for its readback before offering another notice",
            ));
        }
        Ok(())
    }

    pub(in crate::process) async fn maintain_secode_capability(
        &self,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> Option<tokio::time::Instant> {
        if work.secode.is_none()
            || !work.active
            || !work.activated
            || work.credentials_revoked
            || work.session_retired
            || work.stop_key.is_some()
        {
            return None;
        }
        let next = tokio::time::Instant::now() + CHECK_INTERVAL;
        let bound = match deadline.stage(Duration::from_secs(2)) {
            Ok(bound) => bound,
            Err(failure) => {
                crate::process::mail::diagnostic::report(work, &failure);
                return Some(next);
            }
        };
        let slot = match self
            .secode_services
            .get(&work.meta.project.id, &work.meta.agent.id, &bound)
            .await
        {
            Ok(Some(slot)) => slot,
            Ok(None) => return None,
            Err(failure) => {
                crate::process::mail::diagnostic::report(work, &failure);
                return Some(next);
            }
        };
        let mut service = match lock_service(&slot, &bound).await {
            Ok(service) => service,
            Err(failure) => {
                crate::process::mail::diagnostic::report(work, &failure);
                return Some(next);
            }
        };
        if service.journal.session != work.meta.session || service.journal.retired {
            return None;
        }
        if let Some(scheduled) = service.capability_check_at
            && scheduled > tokio::time::Instant::now()
        {
            return Some(scheduled);
        }
        service.capability_check_at = Some(next);
        let result = self
            .repair_secode_capability(&mut service, work, &bound)
            .await;
        let failure = result.err().map(|failure| failure.to_string());
        if failure != service.capability_failure {
            service.capability_failure = failure;
        }
        let next = tokio::time::Instant::now() + CHECK_INTERVAL;
        service.capability_check_at = Some(next);
        Some(next)
    }

    async fn repair_secode_capability(
        &self,
        service: &mut Service,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        let profile = service.journal.profile.to_local()?;
        let source_profile = profile.clone();
        let registration = self
            .store
            .pool
            .run_owned(deadline, move || {
                retirement::registration(&source_profile)?.ok_or_else(|| {
                    error(
                        "SE Code capability repair",
                        "service registration is absent; capability state is unknown",
                    )
                })
            })
            .await?;
        let stamp = se_types::Sha256::from_bytes(Sha256::digest(&registration).into());
        let previous = service.journal.capability_repair.as_ref();
        let known = previous
            .filter(|repair| repair.after.is_some())
            .map(|repair| repair.registration)
            .or_else(|| {
                service
                    .journal
                    .registration
                    .as_ref()
                    .map(|bytes| se_types::Sha256::from_bytes(Sha256::digest(bytes).into()))
            });
        if known == Some(stamp)
            && (service.capability_control.is_some()
                || previous.and_then(CapabilityRepair::owned_binding).is_none())
        {
            return Ok(());
        }
        let session = work.meta.session.clone();
        self.store
            .read(work.cleanup_admission.clone(), deadline, move |cx| {
                let current = se_core::scope::require_present(
                    cx.read
                        .session(session)
                        .map_err(|error| se_core::store_error::store_error(&error))?,
                    "SE Code capability owner",
                    "Reconcile the original session before credential repair.",
                )?;
                if !matches!(current.current.body, EventBody::SessionActivated { .. }) {
                    return Err(error(
                        "SE Code capability repair",
                        "the original engine session is not active",
                    ));
                }
                Ok(())
            })
            .await?;
        let fields = retirement::fields(&registration)?;
        let endpoint = fields["endpoint"].to_owned();
        let control_profile = profile.clone();
        let control = self
            .store
            .pool
            .run_owned(deadline, move || Control::open(&control_profile, &endpoint))
            .await?;
        // Managed services run in external-host mode. This authenticated route
        // verifies credential custody after a service-generation change.
        let before = control
            .binding(&service.journal.vendor_session, deadline)
            .await?;
        require_registration(&registration, &before)?;
        match CapabilityRepair::plan(stamp, before, previous)? {
            RepairPlan::Observed(repair) => {
                if repair.owned_binding().is_some() {
                    service.capability_control = Some(Arc::new(control));
                }
                service.journal.capability_repair = Some(repair);
                service.persist(self, deadline).await
            }
            RepairPlan::Put(repair) => {
                self.represent_secode_capability(service, repair, control, deadline)
                    .await
            }
        }
    }

    async fn represent_secode_capability(
        &self,
        service: &mut Service,
        repair: CapabilityRepair,
        control: Control,
        deadline: &Deadline,
    ) -> Result<()> {
        let profile = service.journal.profile.to_local()?;
        let policy_hash = service.journal.policy_sha256.ok_or_else(|| {
            error(
                "SE Code capability repair",
                "original protected policy digest is absent",
            )
        })?;
        let policy_profile = profile.clone();
        let authority = self.capability_admission.clone();
        let expected = crate::SessionIdentity {
            project: service.journal.project.clone(),
            agent: service.journal.agent.clone(),
            session: service.journal.session.clone(),
        };
        let credential = self
            .store
            .pool
            .run_owned(deadline, move || {
                let credential =
                    crate::harness::saved_session_capability(&policy_profile, policy_hash)?;
                authority.verify_session_capability(&credential, &expected)?;
                Ok(credential)
            })
            .await?;
        service.journal.capability_repair = Some(repair.clone());
        service.persist(self, deadline).await?;
        let repaired = repair
            .apply(
                &control,
                &credential,
                &profile.join("host-policy.json"),
                deadline,
            )
            .await?;
        // The old notice and native incarnation remain unchanged. A repair
        // receipt explains our own PUT; it never grants a replay.
        service.journal.capability_repair = Some(repaired);
        service.capability_control = Some(Arc::new(control));
        service.persist(self, deadline).await
    }
}

fn require_registration(bytes: &[u8], binding: &NoticeBinding) -> Result<()> {
    let fields = retirement::fields(bytes)?;
    if fields["instance"] != binding.service.service_instance
        || fields["generation"].parse::<u64>().ok() != Some(binding.service.generation)
        || fields["version"] != binding.service.registration_version
    {
        return Err(error(
            "SE Code capability repair",
            "authenticated service and current registration differ",
        ));
    }
    Ok(())
}
