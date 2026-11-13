//! Capability replacement and authenticated readback, independent of native
//! process custody. The coordinator persists the prepared record before PUT.
use super::{Control, NoticeBinding, NoticeStatus, ServiceIdentity, unreadable};
use crate::client::lease::Deadline;
use se_types::{Result, Secret, Sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Hasher};
use std::path::Path;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapabilityRepair {
    /// Registration joined to the authenticated application incarnation.
    pub registration: Sha256,
    pub before: NoticeBinding,
    pub after: Option<NoticeBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_failure: Option<se_types::ErrorBody>,
}

pub(crate) enum RepairPlan {
    Observed(CapabilityRepair),
    Put(CapabilityRepair),
}

impl CapabilityRepair {
    pub(crate) fn fingerprint(registration: &[u8], identity: &ServiceIdentity) -> Sha256 {
        let mut hash = Hasher::new();
        hash.update(b"secode-capability-observation-v1");
        hash.update((registration.len() as u64).to_le_bytes());
        hash.update(registration);
        hash.update(identity.incarnation.as_bytes());
        Sha256::from_bytes(hash.finalize().into())
    }

    pub(crate) fn validate(&self, session: &str) -> Result<()> {
        self.before.service.validate()?;
        if self.before.session_id != session {
            return Err(unreadable(
                "SE Code capability repair",
                "retained Session differs",
            ));
        }
        if self.before.status == NoticeStatus::RebindRequired {
            if self.before.target_id.is_some()
                || self.before.binding.is_some()
                || self.before.hold_id.is_some()
            {
                return Err(unreadable(
                    "SE Code capability repair",
                    "unbound readback carries target or hold coordinates",
                ));
            }
        } else {
            require_bound(&self.before)?;
        }
        if let Some(after) = &self.after {
            self.before.service.require_same(&after.service)?;
            if after.session_id != session {
                return Err(unreadable(
                    "SE Code capability repair",
                    "repair readback names another Session",
                ));
            }
            require_bound(after)?;
        }
        Ok(())
    }

    pub(crate) fn plan(
        registration: Sha256,
        current: NoticeBinding,
        previous: Option<&Self>,
    ) -> Result<RepairPlan> {
        if let Some(previous) = previous.filter(|previous| previous.registration == registration) {
            previous.before.service.require_same(&current.service)?;
            require_bound(&current)?;
            if let Some(after) = &previous.after
                && (after.target_id != current.target_id || after.binding != current.binding)
            {
                return Err(unreadable(
                    "SE Code capability repair",
                    "target changed after the original repair",
                ));
            }
            let mut repaired = previous.clone();
            repaired.after = Some(current);
            return Ok(RepairPlan::Observed(repaired));
        }
        let repair = Self {
            registration,
            before: current,
            after: None,
            write_failure: None,
        };
        repair.validate(&repair.before.session_id)?;
        if repair.before.status == NoticeStatus::RebindRequired {
            Ok(RepairPlan::Put(repair))
        } else {
            require_bound(&repair.before)?;
            Ok(RepairPlan::Observed(Self {
                after: Some(repair.before.clone()),
                ..repair
            }))
        }
    }

    pub(crate) fn owned_binding(&self) -> Option<&NoticeBinding> {
        (self.before.status == NoticeStatus::RebindRequired).then_some(())?;
        self.after.as_ref()
    }

    pub(crate) async fn apply(
        mut self,
        control: &Control,
        credential: &Secret,
        config: &Path,
        deadline: &Deadline,
    ) -> Result<Self> {
        let sent = control
            .put_session_capability(&self.before.session_id, credential, config, deadline)
            .await;
        let observed = control
            .binding(&self.before.session_id, deadline)
            .await
            .and_then(|after| {
                self.before.service.require_same(&after.service)?;
                require_bound(&after)?;
                Ok(after)
            });
        self.after = Some(match (sent, observed) {
            (Ok(()), Ok(after)) => after,
            (Err(write), Ok(after)) => {
                self.write_failure = Some(write.body);
                after
            }
            (Err(write), Err(read)) => return Err(read.with_cause(write)),
            (Ok(_), Err(read)) => return Err(read),
        });
        Ok(self)
    }
}

fn require_bound(binding: &NoticeBinding) -> Result<()> {
    match binding.status {
        NoticeStatus::Ready => {
            binding.require_ready()?;
        }
        NoticeStatus::Held => {
            binding.require_held()?;
        }
        NoticeStatus::RebindRequired => {
            return Err(unreadable(
                "SE Code capability repair",
                "the original PUT remains unconfirmed; retain its attempt while StateEngine waits for readback",
            ));
        }
    }
    Ok(())
}
