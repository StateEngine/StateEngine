//! Continuity comes from the bound principal's checked store snapshot.
use super::{EmbeddedHost, binding, store};
use crate::linked::FromLinked;
use se_core::{scope, store_error::store_error};
use se_store::{Actor, EventBody, Snapshot, StoredText};
use se_types::{Read, Result, SeError};
use secode_stateengine_api as api;
use std::num::NonZeroU32;

struct PrincipalSummary {
    name: String,
    role: String,
}

fn build_page_request(
    request: api::ContinuityRequest,
    limits: &api::Limits,
) -> Result<se_types::PageRequest> {
    Ok(se_types::PageRequest {
        after: request
            .page
            .after
            .map(se_types::Cursor::from_linked)
            .transpose()?,
        limit: NonZeroU32::new(request.page.limit.min(limits.page_items.get()).min(1000))
            .ok_or_else(|| SeError::invalid("continuity limit", "a positive page limit"))?,
        max_bytes: NonZeroU32::new(
            request
                .page
                .max_bytes
                .min(limits.payload_bytes.get())
                .min(2 * 1024 * 1024),
        )
        .ok_or_else(|| SeError::invalid("continuity bytes", "a positive byte budget"))?,
    })
}

fn read_principal_summary(
    read: &mut impl Snapshot,
    agent: &se_types::AgentId,
) -> Result<PrincipalSummary> {
    let principal = scope::require_present(
        read.principal(Actor::Agent(agent.clone()))
            .map_err(|e| store_error(&e))?,
        "linked principal",
        "Restore this agent's registration before binding.",
    )?;
    let original = principal.original.as_deref().unwrap_or(&principal.current);
    let (mut name, role) = match &original.body {
        EventBody::PrincipalRegistered { name, role, .. } => (name.clone(), role.clone()),
        _ => {
            return Err(SeError::invalid(
                "linked principal",
                "an original agent registration",
            ));
        }
    };
    if let EventBody::PrincipalRenamed { name: current, .. } = &principal.current.body {
        name = current.clone();
    }
    Ok(PrincipalSummary { name, role })
}

fn read_working_state(
    read: &mut impl Snapshot,
    agent: &se_types::AgentId,
) -> Result<Option<String>> {
    match read
        .working_state(agent.clone())
        .map_err(|e| store_error(&e))?
    {
        Read::Present { value } => match value.current.body {
            EventBody::WorkingStateSet {
                text: StoredText::Present(text),
                ..
            } => Ok(Some(text)),
            _ => Err(scope::unreadable(
                "linked working state",
                "the saved note is erased or unreadable",
            )),
        },
        Read::Absent { .. } => Ok(None),
        Read::Unreadable { source, reason, .. } => Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => Err(scope::unreadable("linked working state", &what)),
    }
}

fn encode_bounded_input(text: String, maximum: usize) -> Result<api::BoundedText> {
    // BoundedText describes this complete prompt, while the separate
    // source window and omission summary describe the history excerpt.
    if text.len() <= maximum {
        Ok(api::BoundedText {
            utf8_bytes: text.len() as u64,
            text,
            complete: true,
            omitted_bytes: Some(0),
        })
    } else {
        Err(SeError::too_large("linked continuity", maximum, text.len()))
    }
}

impl EmbeddedHost {
    pub(super) async fn context(
        &self,
        session: &api::BoundSession,
        request: api::ContinuityRequest,
        options: api::CallOptions,
    ) -> Result<api::SessionContext> {
        let binding = self.bindings.verify(session)?;
        let (router, deadline, _cancel) = self.ready(&options).await?;
        if session.generation != options.generation || request.acknowledge_packet.is_some() {
            return Err(SeError::invalid(
                "linked continuity",
                "the current generation and no packet acknowledgement before a packet is issued",
            ));
        }
        let page = build_page_request(request, &self.config.limits)?;
        let maximum = page.max_bytes.get() as usize;
        let read_deadline = deadline.clone();
        let scope = binding::session_scope(session)?;
        let checked = scope.clone();
        let revision = session.binding_revision;
        let atlas = router.execution.atlas.clone();
        let ticket = atlas.records.ticket().unwrap_or(None);
        store::read(&router, scope, &deadline, move |read| {
            binding::check(read, &checked, revision)?;
            let agent = se_types::AgentId::from_linked(binding.identity.agent.clone())?;
            let principal = read_principal_summary(read, &agent)?;
            let working = read_working_state(read, &agent)?;
            // Queue time consumes the caller's clock. The store also has its
            // own five-second read ceiling, independent of the API timeout.
            let budget = se_store::ReadBudget {
                page,
                deadline: read_deadline
                    .remaining()?
                    .min(std::time::Duration::from_secs(5)),
            };
            let turns = read.turns(agent, budget).map_err(|e| store_error(&e))?;
            let mut latest = None;
            let mut rows = Vec::new();
            for turn in turns.items() {
                let EventBody::SessionTurn {
                    role,
                    text: StoredText::Present(text),
                    ..
                } = &turn.body
                else {
                    return Err(scope::unreadable(
                        "linked continuity turn",
                        "visible text is erased or unreadable",
                    ));
                };
                let time = u64::try_from(turn.header.occurred_at_us)
                    .map_err(|_| SeError::invalid("turn time", "nonnegative Unix microseconds"))?;
                latest = Some(latest.unwrap_or(0).max(time));
                rows.push(serde_json::json!({"event":turn.header.event,"role":role,"text":text}));
            }
            let mut text = serde_json::to_string(&serde_json::json!({
                "agent":binding.identity.agent.0,"name":principal.name,"role":principal.role,
                "working_state":working,"recent_turns":rows,
                "recent_turns_complete":turns.window().complete(),
                "recent_turns_omitted":turns.window().omitted()
            }))
            .map_err(|e| scope::unreadable("linked continuity encoding", &e.to_string()))?;
            crate::atlas_continuity::attach_model(
                &atlas,
                ticket,
                read,
                &checked.admission,
                &mut text,
                maximum as u32,
            )?;
            let model_input = encode_bounded_input(text, maximum)?;
            Ok(api::SessionContext {
                schema: "secode.session-context-v1".into(),
                identity: binding.identity.clone(),
                display_identity: api::ContextDisplayIdentity {
                    agent: binding.identity.agent,
                    display_name: Some(principal.name),
                    role: Some(principal.role),
                    neutral: false,
                },
                generated_at: api::UnixMicros(super::super::start::now_unix_micros()? as u64),
                source_cli: "secode".into(),
                harness: api::Harness::Secode,
                model: binding.model,
                conversation: binding.conversation,
                packet: api::Read::Absent {
                    checked: "No boot packet is issued by this linked W3 binding.".into(),
                },
                model_input,
                continuity: crate::linked::window(turns.window())?,
                continuity_summary: api::ContinuitySummary {
                    rows: turns.items().len() as u64,
                    latest_at: latest.map(api::UnixMicros),
                },
                warnings: Vec::new(),
                failures: Vec::new(),
            })
        })
        .await
    }
}
