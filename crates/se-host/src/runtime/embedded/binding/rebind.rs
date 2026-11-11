//! Reissue a process-local grant only after observing the adopted native target.
//! No session allocation, Select, unhold or invented durable commit occurs here.
use super::*;
use crate::client::lease::Deadline;

impl EmbeddedHost {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) async fn rebind(
        &self,
        router: &HostedRouter,
        request: api::BindingRequest,
        options: api::CallOptions,
        deadline: &Deadline,
    ) -> Result<api::IssuedSession> {
        if !self.negotiated.features.contains(&api::Feature::NativeMail) {
            return Err(denied("NativeMail was not negotiated for restart rebind"));
        }
        let (Some(target), Some(revision)) = (&request.target, request.expected_binding_revision)
        else {
            return Err(denied(
                "restart rebind requires both target and expected binding revision",
            ));
        };
        if target.binding.project != request.project || target.binding.agent != request.agent {
            return Err(denied(
                "foreign native target: project or agent differs from the requested binding",
            ));
        }
        // Validate the caller's key even though this is a read-only reissuance.
        // Its receipt names the original durable bind, never a synthetic commit.
        se_types::IdempotencyKey::from_linked(request.idempotency_key.clone())?;
        for (name, text, cap) in [
            ("provider", &request.model.provider, 256),
            ("model", &request.model.model, 256),
            ("conversation", &request.conversation.0, 512),
        ] {
            se_core::ops::inputs::bounded(name, text, cap, false)?;
        }
        let scope = owner_scope(
            router,
            se_types::ProjectId::from_linked(request.project.clone())?,
        );
        let identity = target.binding.clone();
        let conversation = request.conversation.clone();
        let generation = options.generation;
        let receipt = store::read(router, scope, deadline, move |read| {
            let record = scope::require_present(
                read.session(se_types::SessionId::from_linked(identity.session.clone())?)
                    .map_err(|e| store_error(&e))?,
                "restart binding", "Restore the original session; never bind a replacement as recovery.",
            )?;
            if !matches!(record.current.body, EventBody::SessionActivated { process: None, containment: se_store::ContainmentFact::NotLaunched, .. }) {
                return Err(denied("restart binding is revoked, ended or process-bound"));
            }
            if record.revision.value != revision.0 {
                return Err(denied("stale binding revision: refresh the exact adoption before rebind"));
            }
            let original = record.original.as_deref().unwrap_or(&record.current);
            match &original.body {
                EventBody::SessionPrepared { agent, provider: se_store::Provider::SeCode, native_ref, generation: previous, .. }
                    if agent.to_linked() == identity.agent && *native_ref == conversation.0 && *previous <= generation.0 => (),
                _ => return Err(denied("foreign restart binding: original agent, conversation or generation differs")),
            }
            let committed = scope::require_present(
                read.event_receipt(original.header.event.clone()).map_err(|e| store_error(&e))?,
                "original binding receipt", scope::COMMITTED_READ_RECOVERY,
            )?;
            let key = committed.request_key.clone().ok_or_else(|| denied("original binding has no keyed receipt"))?.to_linked();
            store::receipt(read, committed, key, identity)
        }).await?;
        let (epoch, services) = self.services().map_err(native_error)?;
        if target.epoch != epoch {
            return Err(denied(
                "foreign native target epoch: reattach to this registration before rebind",
            ));
        }
        let observed = services
            .binding_state(
                target,
                self.service_options(&options, deadline)
                    .map_err(native_error)?,
            )
            .await
            .map_err(native_error)?;
        match observed {
            api::Read::Present { value } if value.target == *target => match value.status {
                api::TargetStatus::Eligible | api::TargetStatus::Held => (),
                api::TargetStatus::Revoked => {
                    return Err(denied(
                        "native binding is revoked; restart cannot restore it",
                    ));
                }
            },
            api::Read::Present { .. } => return Err(denied("foreign native adoption observation")),
            api::Read::Absent { .. } => {
                return Err(denied(
                    "native binding is absent; verified reattachment is required",
                ));
            }
            api::Read::Unreadable { source, reason, .. } => {
                return Err(scope::unreadable(&source, &reason));
            }
            api::Read::Unknown { what } => {
                return Err(scope::unreadable("native restart adoption", &what));
            }
        }
        let remaining = api::CallOptions {
            timeout: deadline.remaining()?,
            ..options.clone()
        };
        self.ready(&remaining).await?;
        let session = self.bindings.issue(
            Binding {
                identity: target.binding.clone(),
                model: request.model,
                conversation: request.conversation,
                fenced: false,
            },
            options.generation,
        )?;
        self.register_native(target, remaining)
            .await
            .map_err(native_error)?;
        Ok(api::IssuedSession {
            identity: session.identity.clone(),
            generation: options.generation,
            binding_revision: session.binding_revision,
            session,
            receipt,
        })
    }
}

fn native_error(error: api::ApiError) -> SeError {
    scope::unreadable(
        "native restart adoption",
        &format!("{}: {}", error.code, error.message),
    )
}
