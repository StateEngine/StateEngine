//! Saved identity and known session absence from the caller's store snapshot.
use super::{AgentRow, AgentShow, AgentStatusOutput};
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{Actor, EventBody, ProjectionRecord, Snapshot};
use se_types::{
    AgentId,
    OmissionReason::{Budget, Limit},
    Read, Result, StopReason,
};

/// Saved agents in a finite principal page; never starts or resumes a process.
pub fn page<R: Snapshot>(
    budget: se_store::ReadBudget,
    cx: &mut Cx<'_, R>,
) -> Result<se_types::Page<AgentRow>> {
    page_with_temp(budget, false, cx)
}

/// Agents in a finite principal page; hides retired ephemeral agents unless `include_temp` is set.
/// Principals are read in short chunks, each record once. A chunk's last row keeps the store
/// cursor after the chunk, so this page and its observed rows can be cut at their final bytes.
pub fn page_with_temp<R: Snapshot>(
    budget: se_store::ReadBudget,
    include_temp: bool,
    cx: &mut Cx<'_, R>,
) -> Result<se_types::Page<AgentRow>> {
    let (limit, max) = (budget.page.limit, u64::from(budget.page.max_bytes.get()));
    let (mut request, mut window, mut rows, mut bytes, mut read) =
        (budget, None::<se_types::WindowFields>, Vec::new(), 1, 0);
    let next = loop {
        // Each chunk fills at most half the remaining budget at the mean row size so far.
        let rest = max.saturating_sub(bytes) * rows.len() as u64 / (2 * bytes);
        let chunk = u32::try_from(rest).unwrap_or(CHUNK).clamp(1, CHUNK);
        request.page.limit =
            std::num::NonZeroU32::new(chunk.min(limit.get() - read)).unwrap_or(limit);
        let page = principals(request.clone(), include_temp, cx)?;
        let mut fields = page.window().fields().cloned().ok_or_else(|| {
            scope::unreadable(
                "agent status page",
                "store window accounting is unavailable",
            )
        })?;
        let next = page.next().cloned();
        read += page.items().len() as u32;
        for record in page.into_items() {
            let visible =
                |agent: &AgentId| !matches!(&cx.admission.actor, Actor::Agent(own) if own != agent);
            let Some(agent) = record_agent(&record).filter(visible) else {
                continue;
            };
            let row = expand(agent, record, cx)?;
            bytes += se_types::Page::item_bytes(&row)?;
            rows.push(row);
        }
        if let Some(row) = rows.last_mut() {
            // Principals after this row in its chunk are not listed rows.
            row.resume_after.clone_from(&next);
        }
        if let Some(first) = window.take() {
            (fields.from, fields.start_cursor) = (first.from, first.start_cursor);
            (fields.omitted_before, fields.unreadable) =
                (first.omitted_before, fields.unreadable + first.unreadable);
        }
        window = Some(fields);
        if next.is_none() || read >= limit.get() || bytes > max {
            break next;
        }
        request.page.after = next;
    };
    let mut fields =
        window.ok_or_else(|| scope::unreadable("agent status page", "no principal read"))?;
    fields.limit = limit;
    // Principal omissions cannot be relabelled as an exact count of agents.
    if next.is_some() {
        let by_bytes = fields.stop_reason == StopReason::ByteLimit;
        let reason = if by_bytes { Budget } else { Limit };
        fields.omitted_after = se_types::Omission::Unknown { reason };
    }
    se_types::Page::fit(rows, fields, next, |row| row.resume_after.clone())
}

/// Most principals per chunk; chunks shrink to one as rows near the byte budget, and
/// a cut inside a chunk returns fewer rows than fit, never a skipped agent.
const CHUNK: u32 = 32;

fn expand<R: Snapshot>(
    agent: AgentId,
    record: ProjectionRecord,
    cx: &mut Cx<'_, R>,
) -> Result<AgentRow> {
    let saved = if matches!(cx.admission.actor, Actor::Human(_)) {
        // Enumeration and row expansion share this immutable read pin.
        from_principal(agent, record, None, cx)?
    } else {
        let target_agent_id = Some(agent.clone());
        show(AgentShow { target_agent_id }, cx)?
    };
    scope::require_present(
        saved.agent,
        "saved agent page row",
        "Read the saved agent by its exact ID in this project, then refresh the agent list.",
    )
}

fn record_agent(record: &ProjectionRecord) -> Option<AgentId> {
    match &record.current.body {
        EventBody::PrincipalRegistered {
            principal: Actor::Agent(agent),
            ..
        }
        | EventBody::PrincipalRenamed {
            principal: Actor::Agent(agent),
            ..
        } => Some(agent.clone()),
        _ => None,
    }
}

fn principals<R: Snapshot>(
    budget: se_store::ReadBudget,
    include_temp: bool,
    cx: &mut Cx<'_, R>,
) -> Result<se_types::Page<ProjectionRecord>> {
    if include_temp {
        cx.read.principals(budget)
    } else {
        cx.read.active_principals(budget)
    }
    .map_err(|e| store_error(&e))
}

pub fn show<R: Snapshot>(input: AgentShow, cx: &mut Cx<'_, R>) -> Result<AgentStatusOutput> {
    let agent = scope::working_agent(cx.admission, input.target_agent_id.as_ref(), "agent.show")?;
    // Read saved identity through the target-bound control port without granting
    // access to the owner's other session history.
    let mut controlled_profile = None;
    let principal = if matches!(&cx.admission.actor, Actor::Agent(_)) {
        match cx
            .read
            .control_target(agent.clone())
            .map_err(|error| store_error(&error))?
        {
            Read::Present { value } => {
                controlled_profile = Some(value.profile);
                Read::Present {
                    value: value.principal,
                }
            }
            other => other.map(|target| target.principal),
        }
    } else {
        cx.read
            .principal(Actor::Agent(agent.clone()))
            .map_err(|error| store_error(&error))?
    };
    let principal = match principal.into_present() {
        Ok(value) => value,
        Err(agent) => return Ok(AgentStatusOutput { agent }),
    };
    from_principal(agent, principal, controlled_profile, cx)
}

fn from_principal<R: Snapshot>(
    agent: AgentId,
    principal: ProjectionRecord,
    controlled_profile: Option<Read<ProjectionRecord>>,
    cx: &mut Cx<'_, R>,
) -> Result<AgentStatusOutput> {
    let (name, role) = principal_name_role(&principal)?;
    let (ephemeral, created_by) = principal_ephemeral_creator(&principal);
    let retired = cx
        .read
        .principal_retired(agent.clone())
        .map_err(|error| store_error(&error))?;
    let profile = match controlled_profile {
        Some(profile) => profile,
        None => cx
            .read
            .profile(agent.clone())
            .map_err(|e| store_error(&e))?,
    };
    let saved = match profile.into_present() {
        Ok(value) => value,
        Err(Read::Absent { checked }) => {
            return Ok(AgentStatusOutput {
                agent: Read::Unknown {
                    what: format!("saved agent exists but its profile is absent: {checked}"),
                },
            });
        }
        Err(agent) => return Ok(AgentStatusOutput { agent }),
    };
    let profile = profile_saved(saved)?;
    let provider = se_types::Provider::from(profile.provider);
    let (session, conversation, mut resume) = super::agent_session::read(&agent, cx)?;
    let never_launched = session.state == "never-launched" && session.session_id.is_none();
    let (secode_binding, secode_runtime) = if provider == se_types::Provider::SeCode {
        secode_views(&session, &mut resume, cx)?
    } else {
        (None, None)
    };
    let external_seat = external_seat_view(profile.external, &session, &mut resume);
    let unread = unread_count(&agent, cx)?;
    // The open question is a stored fact; the state itself is settled once the
    // runtime's observations are merged.
    let waiting_on = super::agent_state::open_question(&agent, cx)?;
    let review = super::agent_state::open_review(&agent, cx)?;
    let working_note = super::agent_state::working_note(&agent, cx)?;
    let published = published_context(
        &agent,
        &session,
        profile.provider_settings.context_window,
        cx,
    )?;
    Ok(AgentStatusOutput {
        agent: Read::Present {
            value: AgentRow {
                provider_settings: profile.provider_settings.clone(),
                harness: profile.harness.clone(),
                // The owning runtime replaces this with its live reading;
                // published usage stands in until it has one.
                context: published.or_else(|| (provider != se_types::Provider::SeCode).then(|| if never_launched {
                    Read::Absent { checked: "This agent has no launched provider session".into() }
                } else {
                    Read::Unknown { what: "Token usage is read by the owning runtime from a live session".into() }
                })),
                provider_activity: matches!(provider, se_types::Provider::Claude | se_types::Provider::Codex).then(|| if never_launched {
                    Read::Absent { checked: "This agent has no launched provider session".into() }
                } else {
                    Read::Unknown { what: "Provider turn activity requires the owning runtime; native liveness does not prove a reply. Check provider sign-in and saved history before resubmitting input.".into() }
                }),
                codex_login: (provider == se_types::Provider::Codex).then(|| Read::Unknown {
                    what: "The Codex login is read by the owning runtime".into(),
                }),
                acp_runtime: (provider == se_types::Provider::Acp).then(|| if never_launched {
                    Read::Absent { checked: "This agent has no launched protocol session".into() }
                } else {
                    Read::Unknown { what: "The native protocol connection has not been observed".into() }
                }),
                harness_policy_notice: (provider == se_types::Provider::Acp)
                    .then(|| se_types::ACP_NO_SANDBOX_NOTICE.into()),
                secode_binding,
                secode_runtime,
                external_seat,
                id: agent,
                name,
                role,
                provider,
                model: profile.model,
                profile: profile.named_profile,
                session,
                conversation,
                resume,
                unread: Some(unread),
                last_activity_at: None,
                state: Some(super::AgentStateView {
                    state: "unknown".into(),
                    since: None,
                    elapsed_seconds: None,
                    waiting_on,
                    review,
                }),
                working_note: Some(working_note),
                background: None,
                ephemeral,
                retired,
                created_by,
                resume_after: None,
            },
        },
    })
}

fn external_seat_view(
    eligible: bool,
    session: &super::SessionView,
    resume: &mut super::ResumeCommand,
) -> Option<super::ExternalSeatView> {
    let is_external_session = session.surface.as_deref() == Some("external");
    if is_external_session {
        resume.ready = false;
        resume.mode = "unavailable".into();
        resume.reason = Some(
            "external seat cannot be resumed by StateEngine; reconnect your external bridge and approve with `se external approve`"
                .into(),
        );
        resume.command = None;
        resume.argv = None;
    }
    (eligible || is_external_session).then(|| {
        let state = if !is_external_session {
            "idle"
        } else {
            match session.recorded_state.as_deref() {
                Some("activated") => "active",
                Some("revoked")
                    if session.end_reason.as_deref() == Some("external seat lease expired") =>
                {
                    "expired"
                }
                Some("revoked") => "revoked",
                Some("ended") => "ended",
                Some("prepared") => "pending",
                _ => "idle",
            }
        };
        super::ExternalSeatView {
            eligible,
            state: state.into(),
            session_id: is_external_session
                .then(|| session.session_id.clone())
                .flatten(),
            lease_generation: None,
            expires_at: None,
            revocation_reason: matches!(state, "revoked" | "expired")
                .then(|| session.end_reason.clone())
                .flatten(),
        }
    })
}

fn principal_ephemeral_creator(principal: &ProjectionRecord) -> (bool, Option<String>) {
    let first = principal.original.as_deref().unwrap_or(&principal.current);
    match &first.body {
        EventBody::PrincipalRegistered {
            ephemeral,
            created_by,
            ..
        } => (
            ephemeral.is_some(),
            created_by.as_ref().map(|actor| actor.wire().to_owned()),
        ),
        _ => (false, None),
    }
}

fn principal_name_role(principal: &ProjectionRecord) -> Result<(String, Option<String>)> {
    match &principal.current.body {
        EventBody::PrincipalRegistered { name, role, .. } => {
            Ok((name.clone(), (!role.is_empty()).then_some(role.clone())))
        }
        EventBody::PrincipalRenamed { name, .. } => {
            let role = principal
                .original
                .as_deref()
                .and_then(|original| match &original.body {
                    EventBody::PrincipalRegistered { role, .. } if !role.is_empty() => {
                        Some(role.clone())
                    }
                    _ => None,
                });
            Ok((name.clone(), role))
        }
        _ => Err(scope::unreadable(
            "saved agent identity",
            "current registration/name unavailable",
        )),
    }
}

fn profile_saved(saved: ProjectionRecord) -> Result<se_store::Profile> {
    let EventBody::ProfileSaved { profile, .. } = saved.current.body else {
        return Err(scope::unreadable(
            "saved agent profile",
            "current immutable profile unavailable",
        ));
    };
    Ok(profile)
}

type SecodeViews = (
    Option<Read<super::SecodeBindingView>>,
    Option<Read<super::SecodeRuntimeView>>,
);

fn secode_views<R: Snapshot>(
    session: &super::SessionView,
    resume: &mut super::ResumeCommand,
    cx: &mut Cx<'_, R>,
) -> Result<SecodeViews> {
    resume.ready = false;
    resume.mode = "compatible-service-required".into();
    resume.reason = Some(super::AgentCommand::SECODE_RESUME_UNAVAILABLE.into());
    resume.command = None;
    resume.argv = None;
    let secode_binding = Some(retained_secode_binding(session.session_id.as_ref(), cx)?);
    let secode_runtime = secode_binding
        .as_ref()
        .map(|binding| secode_runtime_view(binding, session));
    Ok((secode_binding, secode_runtime))
}

fn secode_runtime_view(
    binding: &Read<super::SecodeBindingView>,
    session: &super::SessionView,
) -> Read<super::SecodeRuntimeView> {
    match binding {
        Read::Absent { checked } if session.session_id.is_none() => Read::Absent {
            checked: checked.clone(),
        },
        Read::Unknown { what } => Read::Unknown { what: what.clone() },
        Read::Unreadable { source, reason, error } => Read::Unreadable {
            source: source.clone(),
            reason: reason.clone(),
            error: error.clone(),
        },
        _ => Read::Unknown {
            what: "Current service and execution observations require the owning runtime; retained custody is shown separately.".into(),
        },
    }
}

fn unread_count<R: Snapshot>(agent: &AgentId, cx: &mut Cx<'_, R>) -> Result<u64> {
    cx.read
        .message_count(se_store::MessageQuery {
            recipient: Some(Actor::Agent(agent.clone())),
            sender: None,
            kind: None,
            unread_only: true,
            full_body: false,
            direction: se_store::MailDirection::OldestFirst,
        })
        .map_err(|error| store_error(&error))
}

fn retained_secode_binding<R: Snapshot>(
    session: Option<&se_types::SessionId>,
    cx: &mut Cx<'_, R>,
) -> Result<Read<super::SecodeBindingView>> {
    let Some(session) = session else {
        return Ok(Read::Absent {
            checked: "this agent has no saved session".into(),
        });
    };
    let source = super::process_commit::session_credential_id(session, "capture-source")?;
    let record = match cx
        .read
        .capture_source(source)
        .map_err(|error| store_error(&error))?
        .into_present()
    {
        Ok(value) => value,
        Err(other) => return Ok(other),
    };
    let EventBody::CaptureSource {
        session: found,
        native_ref,
        incarnation,
        ..
    } = &record.original.as_deref().unwrap_or(&record.current).body
    else {
        return Ok(Read::Unreadable {
            source: "retained SE Code binding".into(),
            reason: "the source has no original binding".into(),
            error: None,
        });
    };
    Ok(
        match serde_json::from_slice::<super::SecodeBindingView>(incarnation) {
            Ok(binding)
                if found == session
                    && binding.schema == "se.secode-binding/v1"
                    && binding.session_id == *native_ref =>
            {
                Read::Present { value: binding }
            }
            _ => Read::Unreadable {
                source: "retained SE Code binding".into(),
                reason: "the original source is not a matching managed service binding".into(),
                error: None,
            },
        },
    )
}

/// Context fill from the newest main-conversation turn a harness published for
/// this session, read as the provider counts it: everything the model read.
fn published_context<R: Snapshot>(
    agent: &AgentId,
    session: &super::outputs::SessionView,
    configured: Option<u64>,
    cx: &mut Cx<'_, R>,
) -> Result<Option<Read<super::outputs::ContextWindowView>>> {
    let Some(id) = session.session_id.clone() else {
        return Ok(None);
    };
    let latest = cx
        .read
        .published_usage(agent.clone(), id)
        .map_err(|e| store_error(&e))?;
    let Read::Present { value } = latest else {
        return Ok(None);
    };
    let usage = value.usage;
    let used = usage
        .input_tokens
        .saturating_add(usage.cache_read_tokens)
        .saturating_add(usage.cache_write_tokens);
    // A time this platform's clock cannot hold is reported as unknown.
    let observed = u64::try_from(value.occurred_at_us)
        .ok()
        .and_then(|us| std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_micros(us)));
    Ok(Some(Read::Present {
        value: super::outputs::ContextWindowView::new(used, None, configured, observed),
    }))
}
