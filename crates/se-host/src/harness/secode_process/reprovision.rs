//! Capability replacement and authenticated readback, independent of native
//! process custody. The coordinator persists the prepared record before PUT.
use super::{Control, NoticeBinding, NoticeStatus, ServiceIdentity, unreadable};
use crate::client::lease::Deadline;
use se_types::{Result, Secret, Sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Hasher};
use std::{
    path::Path,
    sync::{Arc, RwLock},
};

/// One qualified service for every lifecycle consumer. Original capture and
/// input coordinates remain immutable in Managed and in their journals.
#[derive(Clone)]
pub(crate) struct QualifiedControl {
    pub control: Arc<Control>,
    pub service: ServiceIdentity,
    repaired: Option<NoticeBinding>,
}
impl QualifiedControl {
    pub(crate) async fn binding(
        &self,
        session: &str,
        deadline: &Deadline,
    ) -> Result<NoticeBinding> {
        let current = self.control.binding(session, deadline).await?;
        self.service.require_same(&current.service)?;
        if let Some(repaired) = &self.repaired
            && (repaired.session_id != current.session_id
                || repaired.target_id != current.target_id
                || repaired.binding != current.binding)
        {
            return Err(unreadable(
                "SE Code current binding",
                "target changed after our credential repair",
            ));
        }
        Ok(current)
    }
}

#[derive(Clone, Default)]
pub(crate) struct LiveBinding(Arc<RwLock<BindingState>>);
#[derive(Default)]
enum BindingState {
    #[default]
    Original,
    Repaired(Box<QualifiedControl>),
    Unavailable,
}
impl LiveBinding {
    pub(crate) fn resolve(
        &self,
        control: Arc<Control>,
        service: ServiceIdentity,
    ) -> Result<QualifiedControl> {
        let state = self
            .0
            .read()
            .map_err(|_| unreadable("SE Code current binding", "poisoned binding custody"))?;
        match &*state {
            BindingState::Repaired(current) => Ok(current.as_ref().clone()),
            BindingState::Original => Ok(QualifiedControl {
                control,
                service,
                repaired: None,
            }),
            BindingState::Unavailable => Err(unreadable(
                "SE Code current binding",
                "current binding is unqualified; preserve original input while repair or native custody is reconciled",
            )),
        }
    }
    pub(crate) fn publish(&self, control: Arc<Control>, repair: &CapabilityRepair) -> Result<()> {
        let binding = repair.owned_binding().ok_or_else(|| {
            unreadable(
                "SE Code current binding",
                "confirmed owned repair is absent",
            )
        })?;
        *self
            .0
            .write()
            .map_err(|_| unreadable("SE Code current binding", "poisoned binding custody"))? =
            BindingState::Repaired(Box::new(QualifiedControl {
                control,
                service: binding.service.clone(),
                repaired: Some(binding.clone()),
            }));
        Ok(())
    }
    pub(crate) fn invalidate(&self) -> Result<()> {
        *self
            .0
            .write()
            .map_err(|_| unreadable("SE Code current binding", "poisoned binding custody"))? =
            BindingState::Unavailable;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapabilityRepair {
    /// Registration joined to the authenticated application incarnation.
    pub registration: Sha256,
    pub before: NoticeBinding,
    pub after: Option<NoticeBinding>,
    /// Persisted before sending. Older pending records have an unknown outcome.
    #[serde(default = "unknown_attempt")]
    pub put_attempted: bool,
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
            if !previous.put_attempted
                && previous.after.is_none()
                && current.status == NoticeStatus::RebindRequired
            {
                return Ok(RepairPlan::Put(previous.clone()));
            }
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
            put_attempted: false,
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
        (self.put_attempted && self.before.status == NoticeStatus::RebindRequired).then_some(())?;
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

fn unknown_attempt() -> bool {
    true
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
