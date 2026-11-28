//! Checks verified adapter observations. DTOs never supply actor or terminal authority.
use crate::registry::{Auth, Effect, Feature, OpMeta, Scope as OpScope};
use se_store::{Actor, Admission, Scope};
use se_types::{Detail, Result, SeError, details};

/// Produced by native same-user/ancestor inspection, not by isatty or an argv flag.
#[derive(Clone, Debug)]
pub enum HumanTerminal {
    OutsideAgentTree,
    Refused { reason: String },
}

/// Exact Phase 1 operation allowlist for owner-approved external seats.
/// Enforced at host admission independently of MCP tool listing.
pub const EXTERNAL_SEAT_ALLOWLIST: &[&str] = &[
    "identity.whoami",
    "message.list",
    "message.read",
    "message.ack",
    "message.dismiss",
    "message.send",
    "working_state.get",
    "working_state.set",
    "session.publish_turn",
];

/// Enforce the narrow Phase 1 command allowlist for an external seat lease.
pub fn authorize_external_seat(meta: &OpMeta, admission: &Admission) -> Result<()> {
    authorize(meta, admission)?;
    if !matches!(
        (&admission.actor, &admission.scope, &admission.session),
        (Actor::Agent(_), Scope::Project(_), Some(_))
    ) {
        return Err(SeError::invalid(
            "external seat authority",
            "an active project-scoped external agent session",
        ));
    }
    if !EXTERNAL_SEAT_ALLOWLIST.contains(&meta.name) {
        return Err(SeError::invalid(
            "external seat operation",
            &format!(
                "an operation permitted for external seats (whoami, inbox list/read/ack/dismiss, send, working_state, publish_turn); `{}` is refused for external leases",
                meta.name
            ),
        ));
    }
    Ok(())
}

/// Check principal, session and scope binding. Kernel::plan separately applies
/// the operation's presence policy to the verified HumanTerminal observation.
pub fn authorize(meta: &OpMeta, admission: &Admission) -> Result<()> {
    if matches!(admission.actor, Actor::Guest)
        && !(meta.effect == Effect::Read
            && (meta.anonymous
                || (meta.feature == Feature::Atlas && meta.auth == Auth::Either)
                || matches!(
                    meta.name,
                    "project.status" | "captain.show" | "history.event_read"
                )))
    {
        return Err(SeError::new(Detail::SessionRequired(
            details::SessionRequired {
                op: meta.name.into(),
            },
        )));
    }
    if matches!(admission.actor, Actor::Remote(_)) {
        return Err(SeError::invalid(
            "delegated authority",
            "the closed remote list/watch/send exposure, never local Owner or session operations",
        ));
    }
    match (&admission.actor, meta.auth) {
        (Actor::Agent(_), Auth::Owner) => {
            return Err(SeError::new(Detail::OwnerRequired(
                details::OwnerRequired {
                    op: meta.name.into(),
                },
            )));
        }
        (Actor::Human(_), Auth::Session) => {
            return Err(SeError::new(Detail::SessionRequired(
                details::SessionRequired {
                    op: meta.name.into(),
                },
            )));
        }
        _ => (),
    }
    match (&admission.actor, &admission.scope, &admission.session) {
        (Actor::Agent(_), Scope::Project(_), Some(_)) => (),
        (Actor::Guest, Scope::Project(_), None) => (),
        (Actor::Human(_), _, None) => (),
        _ => return Err(SeError::new(Detail::CapabilityInvalid(details::CapabilityInvalid {subject:"admitted principal".into(),reason:"actor, project scope and session binding disagree".into(),next_step:"Reconnect with the launched session credential; owner commands require a verified owner terminal.".into()}))),
    }
    if matches!(meta.scope, OpScope::Project | OpScope::Session)
        && !matches!(admission.scope, Scope::Project(_))
    {
        return Err(SeError::new(Detail::ProjectRequired(
            details::ProjectRequired { choices: vec![] },
        )));
    }
    Ok(())
}

pub fn require_human_terminal(
    op: &str,
    admission: &Admission,
    terminal: &HumanTerminal,
) -> Result<()> {
    if !matches!(admission.actor, Actor::Human(_)) {
        return Err(SeError::new(Detail::OwnerRequired(
            details::OwnerRequired { op: op.into() },
        )));
    }
    match terminal {
        HumanTerminal::OutsideAgentTree => Ok(()),
        HumanTerminal::Refused { reason } => Err(SeError::new(Detail::HumanTerminalRequired(
            details::HumanTerminalRequired {
                op: op.into(),
                reason: reason.clone(),
            },
        ))),
    }
}

pub fn read_scope(admission: &Admission) -> se_store::ReadScope {
    let visibility = match &admission.actor {
        Actor::Human(_) => se_store::Visibility::Owner,
        Actor::Agent(agent) => se_store::Visibility::SelfOnly(agent.clone()),
        Actor::Remote(_) => se_store::Visibility::None,
        Actor::Guest => se_store::Visibility::Guest,
    };
    se_store::ReadScope {
        admission: admission.clone(),
        visibility,
    }
}

/// Native observations for file-only owner work before a product HumanId exists.
/// There is no serde implementation: these are adapter facts, never CLI arguments.
#[derive(Clone, Debug)]
pub enum AgentTreeCheck {
    Outside,
    Inside { record: String },
    Unreadable { reason: String },
}
#[derive(Clone, Debug)]
pub struct OwnerObservations {
    pub os_owner: String,
    pub agent_tree: AgentTreeCheck,
    pub stdin_console: bool,
    pub stdout_console: bool,
    pub provider_marker: bool,
}
pub fn authorize_file_owner(
    op: &str,
    expected_owner: &str,
    session_present: bool,
    human_only: bool,
    observed: &OwnerObservations,
) -> Result<()> {
    if session_present {
        return Err(SeError::new(Detail::OwnerRequired(
            details::OwnerRequired { op: op.into() },
        )));
    }
    if observed.os_owner.is_empty() {
        return Err(SeError::new(Detail::SourceUnreadable(
            details::SourceUnreadable {
                subject: "native OS owner".into(),
                reason: "owner identity was not established".into(),
                next_step: "Retry in your own terminal after restoring native identity access."
                    .into(),
            },
        )));
    }
    if observed.os_owner != expected_owner {
        return Err(SeError::new(Detail::OsUserMismatch(
            details::OsUserMismatch {
                expected: expected_owner.into(),
                actual: observed.os_owner.clone(),
            },
        )));
    }
    match &observed.agent_tree {
        AgentTreeCheck::Inside {..}=>return Err(SeError::new(Detail::OwnerRequired(details::OwnerRequired {op:op.into()}))),
        AgentTreeCheck::Unreadable {reason}=>return Err(SeError::new(Detail::SourceUnreadable(details::SourceUnreadable {subject:"native agent ancestry".into(),reason:reason.clone(),next_step:"Restore access or let the runtime resolve its recorded custody; missing endpoint information is not proof of no agents.".into()}))),
        AgentTreeCheck::Outside=>(),
    }
    if human_only
        && !(observed.stdin_console && observed.stdout_console && !observed.provider_marker)
    {
        return Err(SeError::new(Detail::HumanTerminalRequired(
            details::HumanTerminalRequired {
                op: op.into(),
                reason: format!(
                    "stdin_console={}, stdout_console={}, provider_marker={}; this operation requires a human terminal outside any coding-agent environment",
                    observed.stdin_console, observed.stdout_console, observed.provider_marker
                ),
            },
        )));
    }
    Ok(())
}
