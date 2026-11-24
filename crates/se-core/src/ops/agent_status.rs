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
/// Rows past the byte budget end the page early with a store-minted `next` cursor.
pub fn page_with_temp<R: Snapshot>(
    budget: se_store::ReadBudget,
    include_temp: bool,
    cx: &mut Cx<'_, R>,
) -> Result<se_types::Page<AgentRow>> {
    let principals = principals(budget.clone(), include_temp, cx)?;
    let mut fields = principals.window().fields().cloned().ok_or_else(|| {
        scope::unreadable(
            "agent status page",
            "store window accounting is unavailable",
        )
    })?;
    let mut next = principals.next().cloned();
    let (mut rows, mut ends) = (Vec::new(), Vec::new());
    for (index, record) in principals.into_items().into_iter().enumerate() {
        let agent = match &record.current.body {
            EventBody::PrincipalRegistered {
                principal: Actor::Agent(agent),
                ..
            }
            | EventBody::PrincipalRenamed {
                principal: Actor::Agent(agent),
                ..
            } => agent.clone(),
            _ => continue,
        };
        if matches!(&cx.admission.actor,Actor::Agent(bound) if bound!=&agent) {
            continue;
        }
        let saved = if matches!(cx.admission.actor, Actor::Human(_)) {
            // Enumeration and row expansion share this immutable read pin.
            from_principal(agent, record, None, cx)?
        } else {
            show(
                AgentShow {
                    target_agent_id: Some(agent.clone()),
                },
                cx,
            )?
        };
        rows.push(scope::require_present(
            saved.agent,
            "saved agent page row",
            "Read the saved agent by its exact ID in this project, then refresh the agent list.",
        )?);
        ends.push(index + 1);
    }
    let (fit, bytes) = fitting(&rows, fields.max_bytes)?;
    if fit < rows.len() {
        let Some(&consumed) = fit.checked_sub(1).and_then(|last| ends.get(last)) else {
            return Err(scope::unreadable(
                "agent status page",
                "one expanded saved row exceeds the finite response byte budget",
            ));
        };
        (fields, next) = prefix(budget, include_temp, consumed, cx)?;
        rows.truncate(fit);
    }
    (fields.returned, fields.bytes) = (rows.len() as u64, bytes);
    // Principal omissions cannot be relabelled as an exact count of agents.
    if next.is_some() {
        let by_bytes = fields.stop_reason == StopReason::ByteLimit;
        let reason = if by_bytes { Budget } else { Limit };
        fields.omitted_after = se_types::Omission::Unknown { reason };
    }
    se_types::Page::new(rows, se_types::Window::new(fields)?, next)
}

/// How many leading rows fit the byte budget as one JSON array, and its size.
fn fitting(rows: &[AgentRow], max: std::num::NonZeroU32) -> Result<(usize, u64)> {
    let (mut fit, mut bytes) = (0, 1);
    for row in rows {
        // Each row brings its separator or the closing bracket.
        let size = serde_json::to_vec(row)
            .map_err(|e| scope::unreadable("agent status page encoding", &e.to_string()))?
            .len() as u64
            + 1;
        if bytes + size > u64::from(max.get()) {
            break;
        }
        (fit, bytes) = (fit + 1, bytes + size);
    }
    Ok((fit, bytes.max(2)))
}

/// Re-read the first `consumed` principals from the same read pin, so the
/// store mints the cursor that resumes after the last row that fit.
fn prefix<R: Snapshot>(
    mut budget: se_store::ReadBudget,
    include_temp: bool,
    consumed: usize,
    cx: &mut Cx<'_, R>,
) -> Result<(se_types::WindowFields, Option<se_types::Cursor>)> {
    let requested = budget.page.limit;
    budget.page.limit = std::num::NonZeroU32::new(consumed as u32).unwrap_or(requested);
    let page = principals(budget, include_temp, cx)?;
    match (page.window().fields().cloned(), page.next().cloned()) {
        (Some(mut fields), Some(next)) if page.items().len() == consumed => {
            fields.limit = requested;
            fields.stop_reason = StopReason::ByteLimit;
            Ok((fields, Some(next)))
        }
        _ => Err(scope::unreadable(
            "agent status page",
            "the shortened principal page changed within one read pin",
        )),
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
    let unread = unread_count(&agent, cx)?;
    // The open question is a stored fact; the state itself is settled once the
    // runtime's observations are merged.
    let waiting_on = super::agent_state::open_question(&agent, cx)?;
    let review = super::agent_state::open_review(&agent, cx)?;
    let working_note = super::agent_state::working_note(&agent, cx)?;
    Ok(AgentStatusOutput {
        agent: Read::Present {
            value: AgentRow {
                provider_settings: profile.provider_settings.clone(),
                harness: profile.harness.clone(),
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
            },
        },
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
