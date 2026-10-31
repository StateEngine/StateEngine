//! Checks verified adapter observations. DTOs never supply actor or terminal authority.
use crate::registry::{Auth, HumanPolicy, OpMeta, Scope as OpScope};
use se_store::{Actor, Admission, Scope};
use se_types::{Detail, Result, SeError, details};

/// Produced by native same-user/ancestor inspection, not by isatty or an argv flag.
#[derive(Clone, Debug)]
pub enum HumanTerminal {
    OutsideAgentTree,
    Refused { reason: String },
}

pub fn authorize(meta: &OpMeta, admission: &Admission, terminal: &HumanTerminal) -> Result<()> {
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
    if meta.human_only == HumanPolicy::Always {
        require_human_terminal(meta.name, admission, terminal)?;
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
    if session_present || observed.provider_marker {
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
    if human_only && !(observed.stdin_console && observed.stdout_console) {
        return Err(SeError::new(Detail::HumanTerminalRequired(details::HumanTerminalRequired {op:op.into(),reason:"stdin and stdout must both be real consoles/TTYs outside every recorded agent tree".into()})));
    }
    Ok(())
}
