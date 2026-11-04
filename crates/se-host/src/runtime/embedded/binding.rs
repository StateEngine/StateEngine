//! In-process grants are distinct from process capabilities and HTTP credentials.
use super::{EmbeddedHost, store};
use crate::{
    HostedRouter,
    linked::{FromLinked, ToLinked},
};
use hmac::{Hmac, Mac};
use se_core::{scope, store_error::store_error};
use se_store::{Actor, Admission, EventBody, Expected, ReadScope, Snapshot, Visibility};
use se_types::{Read, Result, SeError};
use secode_stateengine_api as api;
use sha2::Sha256;
use std::{collections::BTreeMap, sync::Mutex};

mod recovery;

#[derive(Clone)]
pub(super) struct Binding {
    pub identity: api::SessionIdentity,
    pub model: api::ModelIdentity,
    pub conversation: api::ProviderSessionId,
    fenced: bool,
}
pub(super) struct Bindings {
    key: se_types::Secret,
    values: Mutex<BTreeMap<se_types::SessionId, Binding>>,
}
impl Bindings {
    pub(super) fn current(&self, identity: &api::SessionIdentity) -> Result<Binding> {
        let binding =
            self.for_revoke(&se_types::SessionId::from_linked(identity.session.clone())?)?;
        if binding.fenced || binding.identity != *identity {
            return Err(denied("native target is not a current issued binding"));
        }
        Ok(binding)
    }
    pub(super) fn inventory(&self) -> Result<Vec<Binding>> {
        Ok(self
            .values
            .lock()
            .map_err(|_| scope::unreadable("linked bindings", "registry poisoned"))?
            .values()
            .filter(|binding| !binding.fenced)
            .cloned()
            .collect())
    }
    pub(super) fn new() -> Result<Self> {
        let mut key = vec![0; 32];
        se_proc::fill_entropy(&mut key)
            .map_err(|e| scope::unreadable("linked grant entropy", &e.to_string()))?;
        Ok(Self {
            key: se_types::Secret::new(key)?,
            values: Mutex::new(BTreeMap::new()),
        })
    }
    fn mac(&self, session: &api::BoundSession) -> Result<Hmac<Sha256>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.expose())
            .map_err(|_| SeError::invalid("linked grant", "a protected host key"))?;
        for value in [
            &session.identity.project.0,
            &session.identity.agent.0,
            &session.identity.session.0,
        ] {
            mac.update(&(value.len() as u64).to_le_bytes());
            mac.update(value.as_bytes());
        }
        mac.update(&session.generation.0.to_le_bytes());
        mac.update(&session.binding_revision.0.get().to_le_bytes());
        Ok(mac)
    }
    fn issue(&self, binding: Binding, generation: api::Generation) -> Result<api::BoundSession> {
        let id = se_types::SessionId::from_linked(binding.identity.session.clone())?;
        let mut values = self
            .values
            .lock()
            .map_err(|_| scope::unreadable("linked bindings", "registry poisoned"))?;
        if !values.contains_key(&id) && values.len() >= 128 {
            return Err(SeError::invalid(
                "linked bindings",
                "at most 128 bindings per generation",
            ));
        }
        let mut bound = api::BoundSession {
            grant: Vec::new(),
            identity: binding.identity.clone(),
            generation,
            binding_revision: api::Revision(std::num::NonZeroU64::MIN.saturating_add(1)),
        };
        bound.grant = self.mac(&bound)?.finalize().into_bytes().to_vec();
        values.entry(id).or_insert(binding);
        Ok(bound)
    }
    pub(super) fn verify(&self, session: &api::BoundSession) -> Result<Binding> {
        self.mac(session)?
            .verify_slice(&session.grant)
            .map_err(|_| denied("grant does not match the original binding and generation"))?;
        let id = se_types::SessionId::from_linked(session.identity.session.clone())?;
        let binding = self
            .values
            .lock()
            .map_err(|_| scope::unreadable("linked bindings", "registry poisoned"))?
            .get(&id)
            .cloned()
            .ok_or_else(|| denied("not issued by this host generation"))?;
        if binding.fenced {
            return Err(denied(
                "revoked or replaced; original-key revocation remains retryable",
            ));
        }
        if binding.identity != session.identity {
            return Err(denied("identity differs from its issued binding"));
        }
        Ok(binding)
    }
    pub(super) fn for_revoke(&self, id: &se_types::SessionId) -> Result<Binding> {
        self.values
            .lock()
            .map_err(|_| scope::unreadable("linked bindings", "registry poisoned"))?
            .get(id)
            .cloned()
            .ok_or_else(|| {
                SeError::invalid("linked revoke target", "a session issued by this host")
            })
    }
    pub(super) fn fence(&self, id: &se_types::SessionId) -> Result<()> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| scope::unreadable("linked bindings", "registry poisoned"))?;
        let value = values
            .get_mut(id)
            .ok_or_else(|| SeError::invalid("linked revoke target", "an issued session"))?;
        value.fenced = true;
        Ok(())
    }
    pub(super) fn has_capacity(&self) -> Result<()> {
        if self
            .values
            .lock()
            .map_err(|_| scope::unreadable("linked bindings", "registry poisoned"))?
            .len()
            >= 128
        {
            return Err(SeError::invalid(
                "linked bindings",
                "at most 128 bindings per generation",
            ));
        }
        Ok(())
    }
}

pub(super) fn owner_scope(router: &HostedRouter, project: se_types::ProjectId) -> ReadScope {
    ReadScope {
        admission: Admission {
            scope: se_store::Scope::Project(project),
            actor: Actor::Human(router.context.owner.clone()),
            session: None,
            generation: router.execution.generation.get(),
        },
        visibility: Visibility::Owner,
    }
}
pub(super) fn session_scope(session: &api::BoundSession) -> Result<ReadScope> {
    let agent = se_types::AgentId::from_linked(session.identity.agent.clone())?;
    Ok(ReadScope {
        admission: Admission {
            scope: se_store::Scope::Project(se_types::ProjectId::from_linked(
                session.identity.project.clone(),
            )?),
            actor: Actor::Agent(agent.clone()),
            session: Some(se_types::SessionId::from_linked(
                session.identity.session.clone(),
            )?),
            generation: session.generation.0,
        },
        visibility: Visibility::SelfOnly(agent),
    })
}
pub(super) fn check(
    read: &mut impl Snapshot,
    scope: &ReadScope,
    revision: api::Revision,
) -> Result<()> {
    let session = scope
        .admission
        .session
        .clone()
        .ok_or_else(|| SeError::invalid("linked session", "a session binding"))?;
    let value = scope::require_present(
        read.session(session).map_err(|e| store_error(&e))?,
        "linked session",
        "Rebind the native Session.",
    )?;
    if value.revision.value != revision.0
        || !matches!(value.current.body, EventBody::SessionActivated { .. })
    {
        return Err(denied(
            "revoked or replaced; the stored active binding revision changed",
        ));
    }
    match value.original.as_ref().map(|e| &e.body) {
        Some(EventBody::SessionPrepared {
            agent,
            generation,
            provider: se_store::Provider::SeCode,
            ..
        }) if scope.admission.actor == Actor::Agent(agent.clone())
            && *generation == scope.admission.generation =>
        {
            Ok(())
        }
        _ => Err(SeError::invalid(
            "linked session",
            "the exact admitted SE Code identity and generation",
        )),
    }
}

impl EmbeddedHost {
    pub(super) async fn bind(
        &self,
        authority: &api::BindingAuthority,
        mut request: api::BindingRequest,
        options: api::CallOptions,
    ) -> Result<api::IssuedSession> {
        let (router, deadline, _cancel) = self.ready(&options).await?;
        let _serial = super::super::pool::within(&deadline, self.binding_gate.lock()).await?;
        if !matches!(authority, api::BindingAuthority::Owner(_))
            || request.harness != api::Harness::Secode
        {
            return Err(SeError::invalid(
                "linked bind",
                "native Owner authority and the SE Code harness",
            ));
        }
        if request.target.is_some() || request.expected_binding_revision.is_some() {
            return Err(SeError::invalid(
                "linked takeover",
                "embedded takeover arrives with live handover; stop the linked session, then bind fresh",
            ));
        }
        // Native consent cannot opt back into capture disabled by the owner.
        let home = self.config.state_home.clone();
        let enabled = router
            .execution
            .blocking
            .run(crate::BlockingClass::Foreground, &deadline, move || {
                super::support::load_config(&home).map(|config| config.capture.enabled)
            })
            .await?;
        request.capture_consent &= enabled;
        for (name, text, cap) in [
            ("provider", &request.model.provider, 256),
            ("model", &request.model.model, 256),
            ("conversation", &request.conversation.0, 512),
        ] {
            se_core::ops::inputs::bounded(name, text, cap, false)?;
        }
        let scope = owner_scope(
            &router,
            se_types::ProjectId::from_linked(request.project.clone())?,
        );
        let admission = scope.admission.clone();
        let request_key = request.idempotency_key.clone();
        let identity = store::request(
            "session.bind",
            request_key.clone(),
            serde_json::json!({
                "project":request.project.0,"agent":request.agent.0,"harness":"secode", "provider":request.model.provider,
                "model":request.model.model,"conversation":request.conversation.0,"capture_consent":request.capture_consent,"generation":options.generation.0
            }),
        )?;
        let draft = request.clone();
        // Replays are allowed at capacity; the writer checks the same closed intent.
        let known = store::read(&router, scope.clone(), &deadline, {
            let actor = admission.actor.clone();
            let key = identity.key.clone();
            move |read| {
                read.operation_receipt(actor, key)
                    .map_err(|e| store_error(&e))
            }
        })
        .await?;
        let replay = match known {
            Read::Present { .. } => true,
            Read::Absent { .. } => false,
            Read::Unreadable { source, reason, .. } => {
                return Err(scope::unreadable(&source, &reason));
            }
            Read::Unknown { what } => return Err(scope::unreadable("linked bind receipt", &what)),
        };
        if !replay {
            self.bindings.has_capacity()?;
        }
        let batch = store::read(&router, scope.clone(), &deadline, move |read| {
            let facts = super::super::start::allocate_facts()?;
            let bytes = facts
                .event
                .canonical_bytes()?
                .ok_or_else(|| SeError::invalid("session allocation", "a fresh UUIDv7"))?;
            let session = se_types::SessionId::from_bytes(bytes)?;
            let agent = se_types::AgentId::from_linked(draft.agent)?;
            let previous = if replay {
                None
            } else {
                recovery::previous(read, &admission, agent.clone())?
            };
            let incumbent = previous
                .as_ref()
                .map(|(_, session, revision)| (session.clone(), *revision));

            let prepared = store::event(
                read,
                &admission,
                facts.event.clone(),
                facts.occurred_at_us,
                EventBody::SessionPrepared {
                    session: session.clone(),
                    agent,
                    provider: se_store::Provider::SeCode,
                    surface: Some(se_store::SessionSurface::SeCode),
                    native_ref: draft.conversation.0,
                    consent: if draft.capture_consent {
                        se_store::Consent::Capture
                    } else {
                        se_store::Consent::Suppressed
                    },
                    generation: admission.generation,
                    expected: Expected::Absent,
                },
            );
            let activated = store::event(
                read,
                &admission,
                facts.profile_event,
                facts.occurred_at_us,
                EventBody::SessionActivated {
                    session,
                    expected: Expected::Revision(se_store::Revision {
                        value: std::num::NonZeroU64::MIN,
                    }),
                    incumbent,
                    process: None,
                    containment: se_store::ContainmentFact::NotLaunched,
                    witnesses: Vec::new(),
                },
            );
            let mut events = vec![prepared];
            if let Some((revoked, _, _)) = previous {
                events.push(revoked);
            }
            events.push(activated);
            Ok(se_store::AtomicBatch {
                expected_incarnation: read.info().incarnation,
                admission,
                request: Some(identity),
                events,
                import_checkpoint: None,
            })
        })
        .await?;
        let receipt = store::write(&router, batch, "session.bind", &deadline).await?;
        let committed = store::known("session.bind", &receipt);
        let identity = store::read(&router, scope, &deadline, move |read| {
            let event = scope::require_present(
                read.event(receipt.primary_event.clone())
                    .map_err(|e| store_error(&e))?,
                "linked bind receipt",
                scope::COMMITTED_READ_RECOVERY,
            )?;
            let EventBody::SessionPrepared { session, agent, .. } = event.body else {
                return Err(SeError::invalid(
                    "linked bind receipt",
                    "the committed session preparation",
                ));
            };
            let se_store::Scope::Project(project) = event.header.scope else {
                return Err(SeError::invalid("linked bind receipt", "a project"));
            };
            let identity = api::SessionIdentity {
                project: project.to_linked(),
                agent: agent.to_linked(),
                session: session.to_linked(),
            };
            Ok((
                identity.clone(),
                store::receipt(read, receipt, request_key, identity)?,
            ))
        })
        .await
        .map_err(|e| committed.response_error(e))?;
        let session = self
            .bindings
            .issue(
                Binding {
                    identity: identity.0.clone(),
                    model: request.model,
                    conversation: request.conversation,
                    fenced: false,
                },
                options.generation,
            )
            .map_err(|e| committed.response_error(e))?;
        Ok(api::IssuedSession {
            identity: identity.0,
            generation: options.generation,
            binding_revision: session.binding_revision,
            session,
            receipt: identity.1,
        })
    }
}

pub(super) fn denied(reason: &str) -> SeError {
    SeError::new(se_types::Detail::CapabilityInvalid(
        se_types::details::CapabilityInvalid {
            subject: "linked in-process session grant".into(),
            reason: reason.into(),
            next_step:
                "Rebind the native SE Code Session against its current host; no owner fallback."
                    .into(),
        },
    ))
}
