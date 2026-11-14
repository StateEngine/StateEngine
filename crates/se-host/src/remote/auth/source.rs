//! Source fences do not revoke the shared machine grant.
use super::*;

impl Security {
    pub(crate) fn source_fence(&self, address: &RemoteAgentAddress) -> Result<Arc<GrantFence>> {
        let (policy, pending) = self.store.read(|phase| {
            Ok((
                phase.remote_source_permission(address)?,
                phase.remote_source_revocation(address)?,
            ))
        })?;
        let (revision, allowed) = match policy {
            se_types::Read::Present { value } => (value.revision.value.get(), value.allowed),
            se_types::Read::Absent { .. } => (0, true),
            se_types::Read::Unreadable { .. } | se_types::Read::Unknown { .. } => {
                return Err(refused(
                    "source address permission is unreadable; the destination Owner must run se remote permissions --local in a terminal on the destination",
                ));
            }
        };
        match pending {
            se_types::Read::Present { .. } => {
                self.source_fence_at(address, revision, false)?;
                return Err(refused(
                    "this source address has an unresolved revocation and is blocked; its Owner can finish the revoke or explicitly allow it with se remote permissions --local in a terminal on the destination",
                ));
            }
            se_types::Read::Absent { .. } => (),
            _ => {
                return Err(refused(
                    "source revocation state is unreadable; its Owner must run se remote permissions --local in a terminal on the destination and resolve its reported error before access resumes",
                ));
            }
        }
        let fence = self.source_fence_with_limit(address, revision, allowed, true)?;
        if !allowed {
            return Err(source_denied());
        }
        drop(fence.output().map_err(|_| source_denied())?);
        Ok(fence)
    }

    pub(crate) fn source_fence_at(
        &self,
        address: &RemoteAgentAddress,
        revision: u64,
        allowed: bool,
    ) -> Result<Arc<GrantFence>> {
        self.source_fence_with_limit(address, revision, allowed, false)
    }

    fn source_fence_with_limit(
        &self,
        address: &RemoteAgentAddress,
        revision: u64,
        allowed: bool,
        admission: bool,
    ) -> Result<Arc<GrantFence>> {
        let key = serde_json::to_string(address)
            .map_err(|_| refused("source address cannot be encoded"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| refused("source security state poisoned"))?;
        if state.all_fenced {
            return Err(refused("remote access is fenced"));
        }
        // Keep revision tombstones: removing an idle entry would let a policy
        // read begun before a revoke recreate an obsolete open fence. The
        // admission budget belongs to one authenticated machine; native Owner
        // changes must still fence an address when that budget is exhausted.
        let fences = state.source_fences.entry(address.host.0.hex()).or_default();
        if let Some(cached) = fences.get(&key) {
            if cached.revision > revision {
                return Err(refused(
                    "source permission changed during admission; run se remote permissions --local in a terminal on the destination, then retry using the current policy",
                ));
            }
            if cached.revision == revision {
                if !allowed {
                    cached.fence.revoke()?;
                }
                return Ok(cached.fence.clone());
            }
            cached.fence.revoke()?;
        } else if admission && fences.len() >= 4096 {
            return Err(refused(
                "this machine reached its 4096-source admission capacity; existing sources and other machines still work; the destination Owner can restart the host to admit another source",
            ));
        }
        let fence = Arc::new(GrantFence::new());
        if !allowed {
            fence.revoke()?;
        }
        fences.insert(
            key,
            SourceFence {
                revision,
                fence: fence.clone(),
            },
        );
        Ok(fence)
    }
}

fn source_denied() -> se_types::SeError {
    se_types::SeError::new(se_types::Detail::CapabilityInvalid(
        se_types::details::CapabilityInvalid {
            subject: "source agent address permission".into(),
            reason: "the destination Owner revoked this source address".into(),
            next_step: "Ask the destination Owner to allow this address with se remote permissions --local in a terminal on the destination; reconnecting the machine does not restore agent access.".into(),
        },
    ))
}
