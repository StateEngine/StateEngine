//! The public status reader authenticates health and registration together.
//! Native service birth and pinned images fence both sides of this read.
use super::*;
use crate::harness::secode_process::{Images, ServiceIdentity, probe};
use se_proc::ProcessRuntime;
use serde_json::Value;

pub(super) struct Registration(Value);
impl Registration {
    pub(super) fn require_bytes(&self, bytes: &[u8]) -> Result<()> {
        let fields = retirement::fields(bytes)?;
        for (field, status) in [
            ("slot", "serviceSlot"),
            ("instance", "serviceInstance"),
            ("environment", "environment"),
            ("version", "registrationVersion"),
            ("endpoint", "endpoint"),
        ] {
            if self.0[status].as_str() != fields.get(field).copied() {
                return Err(error(
                    "SE Code registration custody",
                    "registration differs from authenticated status",
                ));
            }
        }
        for field in ["generation", "pid"] {
            if self.0[field].as_u64().map(|n| n.to_string()).as_deref()
                != fields.get(field).copied()
            {
                return Err(error(
                    "SE Code registration custody",
                    "registration generation or native PID differs",
                ));
            }
        }
        Ok(())
    }
    pub fn require_same(&self, identity: &ServiceIdentity) -> Result<()> {
        if self.0["serviceInstance"] != identity.service_instance
            || self.0["generation"].as_u64() != Some(identity.generation)
            || self.0["registrationVersion"] != identity.registration_version
        {
            return Err(error(
                "SE Code authenticated readiness",
                "registration differs from the original authenticated service identity",
            ));
        }
        Ok(())
    }
}
impl LaunchCoordinator {
    pub(super) async fn secode_readiness(
        &self,
        service: &Service,
        images: Arc<std::sync::Mutex<Images>>,
        deadline: &Deadline,
    ) -> Result<Registration> {
        let owner = service.process.clone().ok_or_else(|| {
            error(
                "SE Code authenticated readiness",
                "original native owner absent",
            )
        })?;
        let native = self.native.clone();
        let before = owner.clone();
        self.store
            .pool
            .run_owned(deadline, move || {
                let found = native
                    .observe(&before)
                    .map_err(|e| error("SE Code readiness birth", e))?;
                if !matches!(found.root, se_proc::ProcessObservation::Live(_)) {
                    return Err(error(
                        "SE Code readiness birth",
                        "original service is not live",
                    ));
                }
                Ok(())
            })
            .await?;
        let pinned = images.clone();
        let cli = self
            .store
            .pool
            .run_owned(deadline, move || {
                let mut images = pinned
                    .lock()
                    .map_err(|_| error("SE Code readiness images", "poisoned custody"))?;
                images.validate()?;
                Ok(images.cli.clone())
            })
            .await?;
        let bytes = probe::command(
            &cli,
            &[
                "status".into(),
                "--service".into(),
                service.journal.profile.to_local()?.into_os_string(),
                "--jsonl".into(),
            ],
            deadline,
        )
        .await?;
        let status: Value =
            serde_json::from_slice(&bytes).map_err(|e| error("SE Code authenticated status", e))?;
        let record = match service.journal.service.as_ref().map(|c| &c.checkpoint) {
            Some(se_proc::CheckpointKind::Process(record)) => record,
            _ => {
                return Err(error(
                    "SE Code authenticated status",
                    "original service process record absent",
                ));
            }
        };
        if status["schema"] != "secode.cli.service-status.v1"
            || status["outcome"] != "ready"
            || status["pid"].as_u64() != Some(u64::from(record.root.pid.0))
            || status["endpoint"].as_str() != service.journal.endpoint.as_deref()
        {
            return Err(error(
                "SE Code authenticated status",
                "public readiness does not match the retained service birth and endpoint",
            ));
        }
        let native = self.native.clone();
        self.store
            .pool
            .run_owned(deadline, move || {
                images
                    .lock()
                    .map_err(|_| error("SE Code readiness images", "poisoned custody"))?
                    .validate()?;
                let found = native
                    .observe(&owner)
                    .map_err(|e| error("SE Code readiness birth", e))?;
                if !matches!(found.root, se_proc::ProcessObservation::Live(_)) {
                    return Err(error(
                        "SE Code readiness birth",
                        "original service exited during authenticated readiness",
                    ));
                }
                Ok(())
            })
            .await?;
        Ok(Registration(status))
    }
}
