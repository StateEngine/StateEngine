//! Re-present an owned credential after a service-generation change. This does
//! not adopt a new native process, release a hold or replay uncertain input.
use super::*;
use se_harness::secode_process::{CapabilityRepair, Control, NoticeBinding, RepairPlan};
use std::time::Duration;

const CHECK_INTERVAL: Duration = Duration::from_secs(5);

impl<H: HostPort> Coordinator<'_, H> {
    pub async fn require_secode_capability_settled(
        &self,
        work: &impl SecodeWork,
        deadline: &Deadline,
    ) -> Result<()> {
        let slot = self
            .0
            .services()
            .get(work.project_id(), work.agent_id(), deadline)
            .await?
            .ok_or_else(|| repair_error("original service custody is absent"))?;
        let service = lock_service(&slot, deadline).await?;
        if service
            .restart
            .as_ref()
            .is_some_and(|restart| !restart.adopted)
        {
            return Err(repair_error(
                "the replacement control has not proved its restart capability; retry while mail remains unread",
            ));
        }
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

    pub async fn maintain_secode_capability(
        &self,
        work: &impl SecodeWork,
        deadline: &Deadline,
    ) -> Option<tokio::time::Instant> {
        if work.secode().is_none()
            || !work.active()
            || !work.activated()
            || work.credentials_revoked()
            || work.session_retired()
            || work.stop_key().is_some()
        {
            return None;
        }
        let next = tokio::time::Instant::now() + CHECK_INTERVAL;
        let observed: Result<Option<tokio::time::Instant>> = async {
            let bound = deadline.stage(Duration::from_secs(2))?;
            let Some(slot) = self
                .0
                .services()
                .get(work.project_id(), work.agent_id(), &bound)
                .await?
            else {
                return Ok(None);
            };
            let mut service = lock_service(&slot, &bound).await?;
            if service.journal.session != *work.session() || service.journal.retired {
                return Ok(None);
            }
            if let Some(scheduled) = service.capability_check_at
                && scheduled > tokio::time::Instant::now()
            {
                return Ok(Some(scheduled));
            }
            service.capability_check_at = Some(next);
            let restart_pending = service
                .restart
                .as_ref()
                .is_some_and(|restart| !restart.adopted);
            let result = if service.restart.is_some() {
                self.0.adopt_restart(&mut service, &bound).await
            } else {
                self.repair_secode_capability(&mut service, &bound).await
            };
            if result.is_ok() && restart_pending {
                self.0
                    .mark_job_mail_pending(work.project_id(), work.agent_id())?;
            }
            if result.is_ok()
                && service
                    .journal
                    .capability_repair
                    .as_ref()
                    .and_then(CapabilityRepair::owned_binding)
                    .is_some()
            {
                work.nudge_secode_completion();
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
                work.report_mail_diagnostic(&failure);
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
            .0
            .run_blocking(deadline, move || {
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

    pub(crate) async fn restore_secode_capability(
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
        service.persist(self.0, deadline).await?;
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
        let expected = se_harness::SessionIdentity {
            project: service.journal.project.clone(),
            agent: service.journal.agent.clone(),
            session: service.journal.session.clone(),
        };
        let credential = self
            .0
            .saved_session_capability(profile, policy_hash, expected, deadline)
            .await?;
        let mut attempted = repair.clone();
        attempted.put_attempted = true;
        service.live.invalidate()?;
        service.journal.capability_repair = Some(attempted.clone());
        if let Err(failure) = service.persist(self.0, deadline).await {
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
