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
