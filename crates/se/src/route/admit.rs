//! One protected inventory establishes owner identity; a supplied session never
//! falls back to it. Project selection cannot widen a session's scope.
use super::{files::Files, owner};
use crate::bootstrap::Bootstrap;
use se_core::{admission::HumanTerminal, scope, store_error::store_error};
use se_store::{Actor, Admission, CredentialState, ReadPhase, Scope};
use se_types::{Read, Result, SeError};
use sha2::{Digest, Sha256};

pub struct Caller {
    pub admission: Admission,
    pub terminal: HumanTerminal,
    pub owner: Option<owner::FileOwner>,
}
pub fn observe(cx: &Bootstrap, phase: &ReadPhase, files: &Files) -> Result<Caller> {
    if let Some(secret) = &cx.session {
        let record = scope::require_present(
            phase
                .credential(Sha256::digest(secret.expose()).into())
                .map_err(|e| store_error(&e))?,
            "session credential",
            "Use the active session credential issued for this agent, or launch a new authenticated session; do not fall back to owner authority.",
        )?;
        if record.state != CredentialState::Active
            || record.purpose != "session"
            || record.expires_at_us <= super::execute::now_us()?
        {
            return Err(SeError::invalid(
                "session credential",
                "an active unexpired session-purpose credential; no owner fallback",
            ));
        }
        let generation = match phase.runtime_owner().map_err(|e| store_error(&e))? {
            Read::Present { value } => value.generation.get(),
            _ => {
                return Err(scope::unreadable(
                    "session runtime generation",
                    "the protected runtime owner is unavailable",
                ));
            }
        };
        return Ok(Caller {
            admission: Admission {
                actor: Actor::Agent(record.agent),
                scope: Scope::Project(record.project),
                session: Some(record.session),
                generation,
            },
            terminal: HumanTerminal::Refused {
                reason: "session authority cannot become an owner terminal".into(),
            },
            owner: None,
        });
    }
    let inventory = phase
        .owner_guard(files, owner::budget()?)
        .map_err(|error| store_error(&error))?;
    let [human] = inventory.owners.as_slice() else {
        return Err(scope::unreadable(
            "store owner",
            "expected exactly one protected owner registration; empty or ambiguous identity cannot grant authority",
        ));
    };
    let observed = owner::from_inventory(&inventory)?;
    observed.authorize("CLI owner admission", observed.os_owner(), false, false)?;
    let terminal = match observed.authorize("human presence", observed.os_owner(), false, true) {
        Ok(()) => HumanTerminal::OutsideAgentTree,
        Err(error) => HumanTerminal::Refused {
            reason: error.to_string(),
        },
    };
    Ok(Caller {
        admission: Admission {
            scope: Scope::Registry,
            actor: Actor::Human(human.clone()),
            session: None,
            generation: 1,
        },
        terminal,
        owner: Some(observed),
    })
}
