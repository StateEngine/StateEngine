//! Composite temporary agent delegation (`delegate.start`, `delegate.cancel`)
//! and atomic post-`SessionEnded` completion notice + retirement batch builder.
use crate::{
    commit::{Cx, OpStep},
    dispatch::{Kernel, admitted},
    ops::{
        AnyOutput,
        continuity::handoff::{HandoffExport, export as export_handoff},
        inputs::{Validate, bounded},
        process_commit, receipt,
    },
    ports::{CustodyPlan, Then},
    scope,
    store_error::store_error,
};
use schemars::JsonSchema;
use se_config::config_policy::{ConfigFile, EffectiveSandbox, MAX_TTL_SECONDS, Provider};
use se_store::{
    Actor, AtomicBatch, EphemeralSpec, EventBody, EventKind, Expected, GrantKey, HistoryDirection,
    HistoryQuery, InputText, PermissionProfile, PrincipalKind, Profile, ReadBudget,
    RetirementReason, Role, Snapshot, StoredText, TranscriptFilter,
};
use se_types::{
    AgentId, Cursor, Detail, IdempotencyKey, Named, NativePath, PageRequest, ProjectId, Read,
    Result, SeError, SessionId, details,
};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU32, time::Duration};

const MAX_TASK_BYTES: usize = 16 * 1024;
const MAX_HANDOFF_BYTES: u32 = 8 * 1024;
const DEFAULT_HANDOFF_BYTES: u32 = 8 * 1024;
const MAX_EXCERPT_BYTES: usize = 1_500;

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DelegateHandoff {
    /// Agent name or ID to export context from (optional for bound agents; required for owner).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Maximum UTF-8 bytes in the handoff packet (256..=8192, default 8192).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<u32>,
    /// Optional continuity cursor for incremental export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<Cursor>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DelegateStart {
    /// Initial task prompt delivered to the temporary agent.
    pub task: String,
    /// Short role label used in the temporary name `tmp-<role>-<4hex>` (default: `helper`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Target provider (defaults to configured launch provider).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
    /// Optional native provider or named declarative ACP harness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    /// Optional model override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Named permission profile (validated against `[delegation].allow` for agent callers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Optional cross-model context handoff prepended to `task`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff: Option<Box<DelegateHandoff>>,
    /// Optional TTL backstop in seconds (1..=86400; capped at configured `[delegation].ttl_seconds`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u32>,
    pub idempotency_key: IdempotencyKey,
}

impl Validate for DelegateStart {
    fn validate(&self) -> Result<()> {
        bounded("task", &self.task, MAX_TASK_BYTES, true)?;
        if let Some(role) = &self.role {
            bounded("role", role, 32, false)?;
            if !role
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(SeError::invalid(
                    "role",
                    "ASCII letters, digits, hyphen or underscore (1..=32 chars)",
                ));
            }
        }
        if let Some(harness) = &self.harness {
            se_config::config_policy::harness::validate_name(harness)?;
        }
        if let Some(model) = &self.model {
            bounded("model", model, 256, false)?;
        }
        if let Some(profile) = &self.profile {
            bounded("profile", profile, 64, false)?;
        }
        if let Some(handoff) = &self.handoff
            && let Some(budget) = handoff.budget
            && !(256..=MAX_HANDOFF_BYTES).contains(&budget)
        {
            return Err(SeError::invalid(
                "handoff.budget",
                "expected 256..=8192 bytes",
            ));
        }
        if let Some(ttl) = self.ttl_seconds
            && !(1..=MAX_TTL_SECONDS).contains(&ttl)
        {
            return Err(SeError::invalid(
                "ttl_seconds",
                "expected 1..=86400 seconds",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DelegateStartOutput {
    pub agent_id: AgentId,
    pub name: String,
    pub session_id: SessionId,
    pub provider: Provider,
    pub model: Option<String>,
    pub profile: String,
    pub ttl_seconds: u32,
    pub handoff_included: bool,
}

#[derive(Clone)]
pub struct DelegateStartPlan {
    pub project: Named<ProjectId>,
    pub owner: se_types::HumanId,
    pub creator: Actor,
    pub cwd: NativePath,
    pub agent_id: AgentId,
    pub name: String,
    pub role: String,
    pub provider: Provider,
    pub stored_provider: se_store::Provider,
    pub harness: Option<String>,
    pub model: Option<String>,
    pub named_profile: String,
    pub permission: PermissionProfile,
    pub resolved: se_config::config_policy::ResolvedProfile,
    pub ephemeral: EphemeralSpec,
    pub composed_task: String,
    pub handoff_included: bool,
    pub idempotency_key: IdempotencyKey,
    pub normalized_intent: serde_json::Value,
    pub existing_agent: Option<(AgentId, String)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DelegateCancel {
    /// Temporary agent ID or name to stop and terminally retire.
    pub agent: String,
    pub idempotency_key: IdempotencyKey,
}

impl Validate for DelegateCancel {
    fn validate(&self) -> Result<()> {
        bounded("agent", &self.agent, 128, false)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DelegateCancelOutput {
    pub agent_id: AgentId,
    pub name: String,
    pub retired: bool,
    pub stopped_lifecycle: bool,
}

#[derive(Clone)]
pub struct DelegateCancelPlan {
    pub project: ProjectId,
    pub agent: Named<AgentId>,
    pub already_retired: bool,
    pub final_session: Option<SessionId>,
    pub idempotency_key: IdempotencyKey,
}

pub fn step_start<R: Snapshot>(
    kernel: &Kernel,
    input: DelegateStart,
    configuration: Option<&ConfigFile>,
    cx: &mut Cx<'_, R>,
) -> Result<OpStep<AnyOutput, Then, CustodyPlan>> {
    Ok(OpStep::Custody(CustodyPlan::DelegateStart(Box::new(
        plan_start(kernel, input, configuration, cx)?,
    ))))
}

pub fn step_cancel<R: Snapshot>(
    input: DelegateCancel,
    cx: &mut Cx<'_, R>,
) -> Result<OpStep<AnyOutput, Then, CustodyPlan>> {
    Ok(OpStep::Custody(CustodyPlan::DelegateCancel(plan_cancel(
        input, cx,
    )?)))
}

pub fn plan_start<R: Snapshot>(
    kernel: &Kernel,
    input: DelegateStart,
    configuration: Option<&ConfigFile>,
    cx: &mut Cx<'_, R>,
) -> Result<DelegateStartPlan> {
    let configuration = configuration.ok_or_else(|| {
        scope::unreadable(
            "delegation configuration",
            "adapter-resolved ConfigFile is not bound",
        )
    })?;
    input.validate()?;
    configuration.validate()?;
    admitted(cx)?;
    let (project_id, owner, project_name, cwd) = project_facts(cx)?;
    require_delegate_authority(cx)?;
    let binding =
        crate::harness_selection::resolve(configuration, input.provider, input.harness.as_deref())?;
    let provider = binding.provider;
    let defaults = configuration.provider(provider);
    let named_profile = input
        .profile
        .clone()
        .unwrap_or_else(|| defaults.profile.clone());
    if matches!(cx.admission.actor, Actor::Agent(_)) {
        configuration
            .delegation
            .require_allowed(provider, &named_profile)?;
    }
    let resolved = configuration.resolve_profile(&named_profile, provider, true)?;
    let permission = match resolved.sandbox {
        EffectiveSandbox::ReadOnly => PermissionProfile::ReadOnly,
        EffectiveSandbox::WorkspaceWrite => PermissionProfile::WorkspaceWrite,
        EffectiveSandbox::Bypass => PermissionProfile::NamedFullBypass,
    };
    let configured_ttl = configuration.delegation.ttl_seconds();
    let ttl_seconds = input
        .ttl_seconds
        .map_or(configured_ttl, |requested| requested.min(configured_ttl));
    let existing_agent = find_replayed_agent(&input.idempotency_key, cx)?;
    if existing_agent.is_none() {
        enforce_active_child_cap(configuration.delegation.max_active_per_parent(), cx)?;
    }
    let (composed_task, handoff_included) = compose_task(&input, cx)?;
    let model = input
        .model
        .clone()
        .or_else(|| (!defaults.model.is_empty()).then(|| defaults.model.clone()));
    let role = input
        .role
        .clone()
        .unwrap_or_else(|| "helper".to_owned())
        .to_ascii_lowercase();
    let agent_id = kernel.facts()?.agent.clone();
    let suffix = short_hex(&agent_id);
    let name = format!("tmp-{role}-{suffix}");
    let normalized_intent = serde_json::to_value(&input)
        .map_err(|error| scope::unreadable("delegate intent", &error.to_string()))?;
    Ok(DelegateStartPlan {
        project: Named {
            id: project_id,
            name: project_name,
        },
        owner,
        creator: cx.admission.actor.clone(),
        cwd,
        agent_id,
        name,
        role,
        provider,
        stored_provider: to_stored_provider(provider),
        harness: binding.harness,
        model,
        named_profile,
        permission,
        resolved,
        ephemeral: EphemeralSpec {
            one_shot: true,
            ttl_seconds,
        },
        composed_task,
        handoff_included,
        idempotency_key: input.idempotency_key,
        normalized_intent,
        existing_agent,
    })
}

pub fn plan_cancel<R: Snapshot>(
    input: DelegateCancel,
    cx: &mut Cx<'_, R>,
) -> Result<DelegateCancelPlan> {
    input.validate()?;
    admitted(cx)?;
    let project = scope::project(cx.admission)?;
    let target = match scope::selected_actor(cx, &input.agent)? {
        Actor::Agent(agent) => agent,
        _ => {
            return Err(SeError::invalid(
                "delegate cancel target",
                "a temporary agent ID or name in this project",
            ));
        }
    };
    let control = scope::require_present(
        cx.read
            .control_target(target.clone())
            .map_err(|error| store_error(&error))?,
        "temporary agent",
        "Choose a temporary agent in this project that you own or created.",
    )?;
    let registration = control
        .principal
        .original
        .as_deref()
        .unwrap_or(&control.principal.current);
    let is_ephemeral = matches!(
        registration.body,
        EventBody::PrincipalRegistered {
            ephemeral: Some(_),
            ..
        }
    );
    if !is_ephemeral {
        return Err(SeError::invalid(
            "delegate.cancel",
            "only ephemeral temporary agents can be cancelled; saved seats use se stop",
        ));
    }
    let name = match &control.principal.current.body {
        EventBody::PrincipalRegistered { name, .. } | EventBody::PrincipalRenamed { name, .. } => {
            name.clone()
        }
        _ => target.as_str().to_owned(),
    };
    let final_session = match control.latest_session {
        Read::Present { value } => match &value.current.body {
            EventBody::SessionPrepared { session, .. }
            | EventBody::SessionActivated { session, .. }
            | EventBody::SessionEnded { session, .. }
            | EventBody::SessionRevoked { session, .. } => Some(session.clone()),
            _ => None,
        },
        _ => None,
    };
    Ok(DelegateCancelPlan {
        project,
        agent: Named { id: target, name },
        already_retired: control.retired,
        final_session,
        idempotency_key: input.idempotency_key,
    })
}

/// Build the atomic `PrincipalRegistered { ephemeral: Some(..) } + ProfileSaved`
/// batch for a qualified `DelegateStartPlan`.
pub fn create_ephemeral_batch<R: Snapshot>(
    kernel: &Kernel,
    plan: &DelegateStartPlan,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let identity = EventBody::PrincipalRegistered {
        principal: Actor::Agent(plan.agent_id.clone()),
        kind: PrincipalKind::Agent,
        owner: plan.owner.clone(),
        created_by: Some(plan.creator.clone()),
        name: plan.name.clone(),
        role: plan.role.clone(),
        ephemeral: Some(plan.ephemeral),
        expected: Expected::Absent,
    };
    let profile = EventBody::ProfileSaved {
        agent: plan.agent_id.clone(),
        profile: Profile {
            provider_settings: Default::default(),
            provider: plan.stored_provider,
            model: plan.model.clone(),
            permission: plan.permission,
            harness: plan.harness.clone(),
            named_profile: plan.named_profile.clone(),
            effort: None,
        },
        expected: Expected::Absent,
    };
    process_commit::batch(
        kernel,
        "delegate.start",
        plan.idempotency_key.clone(),
        plan.normalized_intent.clone(),
        vec![identity, profile],
        cx,
    )
}

/// Metadata required to build the single atomic post-`SessionEnded` batch
/// containing both the automated completion notice (`MessageSent`) and
/// terminal retirement (`AgentRetired { Completed }`).
pub struct CompletionNoticeInput {
    pub agent: Named<AgentId>,
    pub owner: se_types::HumanId,
    pub created_by: Option<Actor>,
    pub child_session: SessionId,
    pub provider: se_store::Provider,
    pub model: Option<String>,
    pub outcome: String,
    pub capture_verified: bool,
}

/// Build one atomic `Door::Host` / owner batch committing both `MessageSent`
/// (automated completion notice) and `AgentRetired { Completed }`, keyed
/// deterministically on `child_session`. Returns `(batch, notify_agent)`.
pub fn completion_notice_batch<R: Snapshot>(
    kernel: &Kernel,
    input: CompletionNoticeInput,
    cx: &mut Cx<'_, R>,
) -> Result<(AtomicBatch, Option<AgentId>)> {
    let recipient = match input.created_by {
        Some(Actor::Agent(parent)) => {
            if cx
                .read
                .principal_retired(parent.clone())
                .map_err(|error| store_error(&error))?
            {
                Actor::Human(input.owner.clone())
            } else {
                Actor::Agent(parent)
            }
        }
        Some(Actor::Human(human)) => Actor::Human(human),
        _ => Actor::Human(input.owner.clone()),
    };
    let notify_agent = match &recipient {
        Actor::Agent(agent) => Some(agent.clone()),
        _ => None,
    };
    let excerpt = if input.capture_verified {
        latest_assistant_excerpt(&input.child_session, cx)?
    } else {
        None
    };
    let capture_label = if input.capture_verified {
        "verified"
    } else {
        "incomplete"
    };
    let model_label = input.model.as_deref().unwrap_or("default");
    let mut text = format!(
        "[StateEngine automated notice] Temporary agent {} ({}) finished.\nProvider: {} ({})\nOutcome: {}\nCapture: {}\nHistory: se history --agent {}",
        input.agent.name,
        input.agent.id,
        stored_provider_label(input.provider),
        model_label,
        input.outcome,
        capture_label,
        input.agent.id
    );
    if let Some(excerpt) = excerpt {
        text.push_str("\n\nFinal response excerpt:\n");
        text.push_str(&excerpt);
    }
    let key: IdempotencyKey = format!("ephemeral-complete-{}", input.child_session).parse()?;
    let notice = EventBody::MessageSent {
        message: kernel.facts()?.message.clone(),
        recipient,
        kind: "done".into(),
        body: InputText::Inline(text),
        refs: Vec::new(),
        reply_to: None,
        quiet: false,
    };
    let retire = EventBody::AgentRetired {
        agent: input.agent.id.clone(),
        reason: RetirementReason::Completed,
        final_session: Some(input.child_session.clone()),
    };
    let batch = process_commit::batch(
        kernel,
        "delegate.complete",
        key,
        serde_json::json!({
            "agent": input.agent.id,
            "session": input.child_session,
            "reason": "completed",
        }),
        vec![notice, retire],
        cx,
    )?;
    Ok((batch, notify_agent))
}

fn latest_assistant_excerpt<R: Snapshot>(
    session: &SessionId,
    cx: &mut Cx<'_, R>,
) -> Result<Option<String>> {
    let budget = ReadBudget {
        page: PageRequest {
            after: None,
            limit: NonZeroU32::new(64).ok_or_else(|| SeError::invalid("limit", "positive"))?,
            max_bytes: NonZeroU32::new(256 * 1024)
                .ok_or_else(|| SeError::invalid("bytes", "positive"))?,
        },
        deadline: Duration::from_secs(2),
    };
    let page = cx
        .read
        .history(
            HistoryQuery {
                agent: None,
                kinds: vec![EventKind::SessionTurn],
                families: Vec::new(),
                session: Some(session.clone()),
                transcript: TranscriptFilter::All,
                since: None,
                direction: HistoryDirection::NewestFirst,
            },
            budget,
        )
        .map_err(|error| store_error(&error))?;
    for event in page.into_items() {
        if let EventBody::SessionTurn {
            role: Role::Assistant,
            text: StoredText::Present(text),
            ..
        } = event.body
        {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Ok(Some(clip_utf8(trimmed, MAX_EXCERPT_BYTES)));
            }
        }
    }
    Ok(None)
}

fn clip_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes.saturating_sub(3);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

fn require_delegate_authority<R: Snapshot>(cx: &mut Cx<'_, R>) -> Result<()> {
    let Actor::Agent(creator) = &cx.admission.actor else {
        return Ok(());
    };
    // Depth-1 invariant: temporary agents cannot spawn grandchildren.
    if let Read::Present { value } = cx
        .read
        .principal(Actor::Agent(creator.clone()))
        .map_err(|error| store_error(&error))?
    {
        let original = value.original.as_deref().unwrap_or(&value.current);
        if matches!(
            original.body,
            EventBody::PrincipalRegistered {
                ephemeral: Some(_),
                ..
            }
        ) {
            return Err(SeError::new(Detail::StateConflict(
                details::StateConflict {
                    subject: "delegate.start".into(),
                    reason: "temporary agents cannot delegate grandchildren (depth limit is 1)"
                        .into(),
                    next_step:
                        "Return your result to the parent agent instead of delegating further."
                            .into(),
                },
            )));
        }
    }
    let grant = cx
        .read
        .grant(
            Actor::Agent(creator.clone()),
            GrantKey::AgentCanCreate(creator.clone()),
        )
        .map_err(|error| store_error(&error))?;
    match grant {
        Read::Present { value }
            if matches!(
                value.current.body,
                EventBody::GrantRecorded { active: true, .. }
            ) =>
        {
            Ok(())
        }
        Read::Absent { .. } | Read::Present { .. } => Err(SeError::new(Detail::OwnerRequired(
            details::OwnerRequired {
                op: "delegate.start without an active agent create grant (set via se config set agent.<name>.can-create true)".into(),
            },
        ))),
        Read::Unreadable { source, reason, .. } => Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => Err(scope::unreadable("delegate create grant", &what)),
    }
}

fn enforce_active_child_cap<R: Snapshot>(cap: u32, cx: &mut Cx<'_, R>) -> Result<()> {
    let budget = ReadBudget {
        page: PageRequest {
            after: None,
            limit: NonZeroU32::new(256).ok_or_else(|| SeError::invalid("limit", "positive"))?,
            max_bytes: NonZeroU32::new(512 * 1024)
                .ok_or_else(|| SeError::invalid("bytes", "positive"))?,
        },
        deadline: Duration::from_secs(2),
    };
    let page = cx
        .read
        .active_principals(budget)
        .map_err(|error| store_error(&error))?;
    let mut active_children: u32 = 0;
    for record in page.into_items() {
        let original = record.original.as_deref().unwrap_or(&record.current);
        if let EventBody::PrincipalRegistered {
            created_by,
            ephemeral: Some(_),
            ..
        } = &original.body
            && created_by.as_ref() == Some(&cx.admission.actor)
        {
            active_children = active_children.saturating_add(1);
        }
    }
    if active_children >= cap {
        return Err(SeError::new(Detail::StateConflict(
            details::StateConflict {
                subject: "delegate.start".into(),
                reason: format!(
                    "parent already has {active_children} active temporary agents (cap is {cap})"
                ),
                next_step: "Wait for an active temporary agent to finish or cancel one with se delegate cancel <agent>.".into(),
            },
        )));
    }
    Ok(())
}

fn find_replayed_agent<R: Snapshot>(
    key: &IdempotencyKey,
    cx: &mut Cx<'_, R>,
) -> Result<Option<(AgentId, String)>> {
    let record = match cx
        .read
        .operation_receipt(cx.admission.actor.clone(), key.clone())
        .map_err(|error| store_error(&error))?
    {
        Read::Present { value } => value,
        Read::Absent { .. } => return Ok(None),
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => return Err(scope::unreadable("delegate idempotency", &what)),
    };
    let event = receipt::committed_event(cx.read, &record)?;
    match event.body {
        EventBody::PrincipalRegistered {
            principal: Actor::Agent(agent),
            name,
            ..
        } => Ok(Some((agent, name))),
        _ => Err(scope::unreadable(
            "delegated agent registration",
            "idempotency record does not point to a principal registration",
        )),
    }
}

fn compose_task<R: Snapshot>(input: &DelegateStart, cx: &mut Cx<'_, R>) -> Result<(String, bool)> {
    let Some(handoff) = &input.handoff else {
        return Ok((input.task.clone(), false));
    };
    let exported = export_handoff(
        HandoffExport {
            from: handoff.from.clone(),
            budget: handoff.budget.unwrap_or(DEFAULT_HANDOFF_BYTES),
            since: handoff.since.clone(),
        },
        cx,
    )?;
    let composed = format!("{}\n\n---\n\n{}", exported.text, input.task);
    if composed.len() > MAX_TASK_BYTES {
        return Err(SeError::too_large(
            "delegate task with handoff",
            MAX_TASK_BYTES,
            composed.len(),
        ));
    }
    Ok((composed, true))
}

fn project_facts<R: Snapshot>(
    cx: &mut Cx<'_, R>,
) -> Result<(ProjectId, se_types::HumanId, String, NativePath)> {
    let id = scope::project(cx.admission)?;
    let project = scope::require_present(
        cx.read
            .project(id.clone())
            .map_err(|error| store_error(&error))?,
        "delegation project",
        "Select an initialized project in this data home before delegating.",
    )?;
    let owner = match &project.original.as_deref().unwrap_or(&project.current).body {
        EventBody::ProjectRegistered { owner, .. } => owner.clone(),
        _ => {
            return Err(scope::unreadable(
                "delegation project",
                "original owner registration is unavailable",
            ));
        }
    };
    let (name, roots) = match project.current.body {
        EventBody::ProjectRegistered { name, roots, .. }
        | EventBody::ProjectUpdated { name, roots, .. } => (name, roots),
        EventBody::ProjectMoved { name, to, .. } => (name, vec![to]),
        _ => {
            return Err(scope::unreadable(
                "delegation project",
                "project projection has the wrong event kind",
            ));
        }
    };
    let cwd = roots
        .first()
        .ok_or_else(|| scope::unreadable("delegation project", "project has no registered root"))?
        .path
        .clone();
    Ok((id, owner, name, cwd))
}

fn short_hex(agent: &AgentId) -> String {
    let raw = agent.as_str();
    let hex: String = raw
        .chars()
        .rev()
        .filter(char::is_ascii_hexdigit)
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    if hex.len() == 4 {
        hex.to_ascii_lowercase()
    } else {
        "0000".to_owned()
    }
}

fn to_stored_provider(provider: Provider) -> se_store::Provider {
    match provider {
        Provider::Claude => se_store::Provider::Claude,
        Provider::Codex => se_store::Provider::Codex,
        Provider::SeCode => se_store::Provider::SeCode,
        Provider::Acp => se_store::Provider::Acp,
    }
}

fn stored_provider_label(provider: se_store::Provider) -> &'static str {
    match provider {
        se_store::Provider::Claude => "claude",
        se_store::Provider::Codex => "codex",
        se_store::Provider::SeCode => "secode",
        se_store::Provider::Acp => "acp",
    }
}
