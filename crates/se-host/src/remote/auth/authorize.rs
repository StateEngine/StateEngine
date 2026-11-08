use super::*;
use se_store::remote::GrantState;

impl Security {
    /// Call inside a finite blocking phase: this intentionally reads the grant again.
    pub(super) fn current(&self, device: &AuthenticatedDevice) -> Result<GrantRecord> {
        let grant = self.store.grant(&device.grant.grant)?;
        self.checked(device, grant)
    }
    fn checked(&self, device: &AuthenticatedDevice, grant: GrantRecord) -> Result<GrantRecord> {
        if grant.host != self.host
            || grant.state != GrantState::Active
            || grant.expires_at_us <= now()?
            || grant.authority_revision != device.grant.authority_revision
            || grant.device != device.grant.device
            || grant.credential_sha256 != device.grant.credential_sha256
        {
            return Err(refused("device authority is no longer current"));
        }
        Ok(grant)
    }
    pub fn authorize(
        &self,
        device: &AuthenticatedDevice,
        request: RemoteRequest,
    ) -> Result<AuthorizedRemoteRequest> {
        self.authorize_invocation(
            device,
            RemoteInvocation {
                source: None,
                request,
            },
        )
    }
    /// Source attribution comes from the authorized broker's immutable call context.
    pub fn authorize_invocation(
        &self,
        device: &AuthenticatedDevice,
        invocation: RemoteInvocation,
    ) -> Result<AuthorizedRemoteRequest> {
        invocation.request.validate()?;
        let grant = self.current(device)?;
        if !grant.subject.admits_source(invocation.source.as_ref()) {
            return Err(refused(
                "source identity differs from the machine session subject",
            ));
        }
        let (verb, targets) = match &invocation.request {
            RemoteRequest::List(v) => (RemoteVerb::List, v.targets.as_slice()),
            RemoteRequest::Watch(v) => (RemoteVerb::Watch, v.targets.as_slice()),
            RemoteRequest::Send(v) => (RemoteVerb::Send, std::slice::from_ref(&v.target)),
        };
        let attribution = RemoteAttribution {
            host: self.host,
            store: grant.store.clone(),
            principal: grant.principal.clone(),
            grant: grant.grant.clone(),
            device: grant.device.clone(),
            authority_revision: grant.authority_revision.value.get(),
            source: invocation.source,
        };
        let admission = se_core::remote::authorize(grant, verb, targets, now()?)?;
        if let RemoteRequest::Watch(watch) = &invocation.request
            && (watch
                .cursors
                .iter()
                .any(|cursor| !admission.targets().contains(&cursor.target))
                || watch
                    .visible
                    .as_ref()
                    .is_some_and(|target| !admission.targets().contains(target)))
        {
            return Err(refused(
                "watch cursor or visible target is outside the machine session's scope",
            ));
        }
        // A revoke between the fresh read and this lock still refuses.
        drop(device.fence.output()?);
        Ok(AuthorizedRemoteRequest {
            admission,
            request: invocation.request,
            attribution,
            fence: device.fence.clone(),
        })
    }
    pub fn output_fence<'a>(
        &self,
        device: &'a AuthenticatedDevice,
        scope: &RemoteScope,
    ) -> Result<OutputFence<'a>> {
        scope.validate()?;
        let current = self.current(device)?;
        if scope
            .targets
            .iter()
            .any(|t| !current.scope.targets.is_empty() && !current.scope.targets.contains(t))
            || scope.verbs.iter().any(|v| !current.scope.verbs.contains(v))
        {
            return Err(refused(
                "output is outside the current machine session's scope",
            ));
        }
        device.fence.output()
    }
    pub fn register_output(
        &self,
        device: &AuthenticatedDevice,
        output: &Arc<dyn OutputInvalidation>,
    ) -> Result<()> {
        self.current(device)?;
        device.fence.register(output)
    }
    /// Call only after an authorized successful request or delivered watch item,
    /// never for connect/ping/refusal. The caller does not await a write per frame.
    pub async fn record_use(&self, device: &AuthenticatedDevice) -> Result<()> {
        drop(device.fence.output()?);
        let store = self.store.clone();
        let id = device.grant.grant.clone();
        let grant = self
            .blocking
            .run(
                crate::runtime::BlockingClass::Foreground,
                &super::super::session::control::deadline()?,
                move || store.grant(&id),
            )
            .await?;
        let grant = self.checked(device, grant)?;
        let at = now()?;
        if at
            .checked_sub(grant.last_use_at_us)
            .is_none_or(|age| age < se_store::remote::LEASE_COALESCE_US)
        {
            return Ok(());
        }
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| refused("remote security state poisoned"))?;
            if !state.renewing.insert(grant.grant.clone()) {
                return Ok(());
            }
        }
        let _pending = RenewalPending {
            state: &self.state,
            grant: grant.grant.clone(),
        };
        let key = se_types::IdempotencyKey::new(format!(
            "remote-lease-{}-{}",
            grant.grant, grant.lease_revision.value
        ))?;
        let intent = serde_json::json!({"grant":grant.grant,"authority_revision":grant.authority_revision,"lease_revision":grant.lease_revision});
        let transition = se_store::remote::SecurityTransition::Renew {
            grant: grant.grant,
            authority_revision: grant.authority_revision,
            expected_lease_revision: grant.lease_revision,
            proven_use_at_us: at,
        };
        self.store
            .commit(
                se_store::Actor::Remote(grant.principal),
                key,
                transition,
                intent,
            )
            .await?;
        Ok(())
    }
}
struct RenewalPending<'a> {
    state: &'a Mutex<State>,
    grant: RemoteGrantId,
}
impl Drop for RenewalPending<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.renewing.remove(&self.grant);
        }
    }
}
