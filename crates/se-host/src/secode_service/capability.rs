//! Re-present an owned credential after a service-generation change. This does
//! not adopt a new native process, release a hold or replay uncertain input.
use super::*;
use crate::harness::secode_process::{CapabilityRepair, Control, NoticeBinding, RepairPlan};
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
            .ok_or_else(|| repair_error("original service custody is absent"))?;
        let service = lock_service(&slot, deadline).await?;
        if service
            .journal
            .capability_repair
            .as_ref()
            .is_some_and(|repair| repair.after.is_none())
        {
            return Err(repair_error(
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
        let observed: Result<Option<tokio::time::Instant>> = async {
            let bound = deadline.stage(Duration::from_secs(2))?;
            let Some(slot) = self
                .secode_services
                .get(&work.meta.project.id, &work.meta.agent.id, &bound)
                .await?
            else {
                return Ok(None);
            };
            let mut service = lock_service(&slot, &bound).await?;
            if service.journal.session != work.meta.session || service.journal.retired {
                return Ok(None);
            }
            if let Some(scheduled) = service.capability_check_at
                && scheduled > tokio::time::Instant::now()
            {
                return Ok(Some(scheduled));
            }
            service.capability_check_at = Some(next);
            let result = self.repair_secode_capability(&mut service, &bound).await;
            if result.is_ok()
                && service
                    .journal
                    .capability_repair
                    .as_ref()
                    .and_then(CapabilityRepair::owned_binding)
                    .is_some()
                && let Some(binding) = work
                    .binding
                    .as_ref()
                    .and_then(|binding| binding.secode.as_ref())
            {
                // Canonical reads remain live even when the original pipe ended.
                binding.completion.nudge();
            }
            service.capability_failure = result.err().map(|failure| failure.to_string());
            let next = tokio::time::Instant::now() + CHECK_INTERVAL;
            service.capability_check_at = Some(next);
            Ok(Some(next))
        }
        .await;
        match observed {
            Ok(next) => next,
            Err(failure) => {
                crate::process::mail::diagnostic::report(work, &failure);
                Some(next)
            }
        }
    }

    async fn repair_secode_capability(
        &self,
        service: &mut Service,
        deadline: &Deadline,
    ) -> Result<()> {
        let (registration, control, before) =
            self.observe_secode_control(service, deadline).await?;
        let stamp = CapabilityRepair::fingerprint(&registration, &before.service);
        let previous = service.journal.capability_repair.as_ref();
        let original = service.journal.registration.as_deref() == Some(registration.as_slice())
            && service.journal.identity.as_ref() == Some(&before.service);
        let known = previous
            .filter(|repair| repair.after.is_some())
            .map_or(original, |repair| repair.registration == stamp);
        if known && previous.and_then(CapabilityRepair::owned_binding).is_none() {
            return Ok(());
        }
        match CapabilityRepair::plan(stamp, before, previous)? {
            RepairPlan::Observed(repair) => {
                self.record_secode_capability(service, repair, control, deadline)
                    .await
            }
            RepairPlan::Put(repair) => {
                self.represent_secode_capability(service, repair, control, deadline)
                    .await
            }
        }
    }

    async fn observe_secode_control(
        &self,
        service: &Service,
        deadline: &Deadline,
    ) -> Result<(Vec<u8>, Control, NoticeBinding)> {
        let profile = service.journal.profile.to_local()?;
        let (registration, control) = self
            .store
            .pool
            .run_owned(deadline, move || {
                let registration = retirement::registration(&profile)?.ok_or_else(|| {
                    repair_error("service registration is absent; capability state is unknown")
                })?;
                let fields = retirement::fields(&registration)?;
                let control = Control::open(&profile, fields["endpoint"])?;
                Ok((registration, control))
            })
            .await?;
        let fields = retirement::fields(&registration)?;
        let pid = self.observe_secode_birth(service, deadline).await?;
        if fields["pid"].parse::<u32>().ok() != Some(pid) {
            return Err(error(
                "SE Code capability custody",
                "registration PID differs from the original native birth",
            ));
        }
        // Managed services run in external-host mode. This authenticated route
        // verifies credential custody after a service-generation change.
        let before = control
            .binding(&service.journal.vendor_session, deadline)
            .await?;
        require_registration(&registration, &before)?;
        Ok((registration, control, before))
    }

    pub(super) async fn restore_secode_capability(
        &self,
        service: &mut Service,
        deadline: &Deadline,
    ) -> Result<()> {
        let previous = service
            .journal
            .capability_repair
            .clone()
            .ok_or_else(|| error("SE Code repair recovery", "retained repair is absent"))?;
        let (registration, control, before) =
            self.observe_secode_control(service, deadline).await?;
        let stamp = CapabilityRepair::fingerprint(&registration, &before.service);
        if stamp != previous.registration {
            return Err(repair_error(
                "current service differs from the retained repair; no replacement was adopted",
            ));
        }
        let RepairPlan::Observed(repair) = CapabilityRepair::plan(stamp, before, Some(&previous))?
        else {
            return Err(repair_error(
                "the retained unsent attempt requires active-session recovery before sending",
            ));
        };
        self.record_secode_capability(service, repair, control, deadline)
            .await
    }

    async fn record_secode_capability(
        &self,
        service: &mut Service,
        repair: CapabilityRepair,
        control: Control,
        deadline: &Deadline,
    ) -> Result<()> {
        service.journal.capability_repair = Some(repair.clone());
        service.persist(self, deadline).await?;
        let control = Arc::new(control);
        if repair.owned_binding().is_some() {
            service.live.publish(control.clone(), &repair)?;
        } else if service.journal.identity.as_ref() != Some(&repair.before.service) {
            service.live.invalidate()?;
        }
        service.control = Some(control);
        Ok(())
    }

    async fn represent_secode_capability(
        &self,
        service: &mut Service,
        repair: CapabilityRepair,
        control: Control,
        deadline: &Deadline,
    ) -> Result<()> {
        let profile = service.journal.profile.to_local()?;
        let policy_hash = service.journal.policy_sha256;
        let config = profile.join("host-policy.json");
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
                authority.saved_session_capability(&profile, policy_hash, &expected)
            })
            .await?;
        let mut attempted = repair.clone();
        attempted.put_attempted = true;
        service.live.invalidate()?;
        service.journal.capability_repair = Some(attempted.clone());
        if let Err(failure) = service.persist(self, deadline).await {
            // No PUT was polled. Keep that fact in memory while pending_save
            // reconciles any publication whose readback failed. A new host
            // only sees the durable attempted marker and must remain cautious.
            service.journal.capability_repair = Some(repair);
            return Err(failure);
        }
        let repaired = attempted
            .apply(&control, &credential, &config, deadline)
            .await?;
        // The old notice and native incarnation remain unchanged. A repair
        // receipt explains our own PUT; it never grants a replay.
        self.record_secode_capability(service, repaired, control, deadline)
            .await
    }
}

fn require_registration(bytes: &[u8], binding: &NoticeBinding) -> Result<()> {
    let fields = retirement::fields(bytes)?;
    if fields["instance"] != binding.service.service_instance
        || fields["generation"].parse::<u64>().ok() != Some(binding.service.generation)
        || fields["version"] != binding.service.registration_version
    {
        return Err(repair_error(
            "authenticated service and current registration differ",
        ));
    }
    Ok(())
}

fn repair_error(reason: &str) -> se_types::SeError {
    error("SE Code capability repair", reason)
}
