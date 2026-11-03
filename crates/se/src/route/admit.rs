//! One protected inventory establishes owner identity; a supplied session never
//! falls back to it. Project selection cannot widen a session's scope.
use super::{files::Files, owner};
use crate::bootstrap::Bootstrap;
use se_core::{admission::HumanTerminal, scope, store_error::store_error};
use se_store::{Actor, Admission, CredentialState, ReadPhase, Scope};
use se_types::{Read, Result, SeError};
use sha2::{Digest, Sha256};

/// A hook may reach C3 with a prepared credential, but a retired or superseded
/// session must not start a host. This read grants no operation authority: the
/// host still authenticates and admits the request on its own current pin.
pub fn hook_session(cx: &Bootstrap, phase: ReadPhase) -> Result<()> {
    use se_store::{EventBody, Snapshot};
    let secret = cx.session.as_ref().ok_or_else(|| {
        SeError::new(se_types::Detail::SessionRequired(
            se_types::details::SessionRequired { op: "hook.claude".into() },
        ))
    })?;
    let hash = Sha256::digest(secret.expose()).into();
    let record = scope::require_present(
        phase.credential(hash).map_err(|e| store_error(&e))?,
        "hook session credential",
        "Launch a new authenticated session; retired credentials cannot start a host.",
    )?;
    let now = super::execute::now_us()?;
    if !matches!(record.state, CredentialState::Prepared | CredentialState::Active)
        || record.purpose != "session"
        || record.expires_at_us <= now
        || (record.state == CredentialState::Prepared && record.activation_deadline_us <= now)
        || phase.credential_superseded(hash).map_err(|e| store_error(&e))?
        || phase.credential_stop_unproved(hash).map_err(|e| store_error(&e))?
    {
        return Err(SeError::invalid(
            "hook session credential",
            "a current prepared or active unexpired session-purpose credential with no unresolved stop",
        ));
    }
    let owner = scope::require_present(
        phase.runtime_owner().map_err(|e| store_error(&e))?,
        "hook runtime generation",
        "Restore the protected runtime owner before starting capture.",
    )?;
    let admission = Admission {
        actor: Actor::Agent(record.agent),
        scope: Scope::Project(record.project),
        session: Some(record.session.clone()),
        generation: owner.generation.get(),
    };
    let mut read = phase
        .into_snapshot(se_core::admission::read_scope(&admission))
        .map_err(|e| store_error(&e))?;
    let result = (|| {
        let session = scope::require_present(
            read.session(record.session.clone()).map_err(|e| store_error(&e))?,
            "hook session",
            "Launch a new authenticated session; absent sessions cannot start a host.",
        )?;
        if !matches!(
            (record.state, &session.current.body),
            (CredentialState::Prepared, EventBody::SessionPrepared { session, .. })
                | (CredentialState::Active, EventBody::SessionActivated { session, .. })
                if session == &record.session
        ) {
            return Err(SeError::invalid("hook session", "the credential's current prepared or active session"));
        }
        Ok(())
    })();
    match (result, read.close().map_err(|e| store_error(&e))) {
        (result, Ok(())) => result,
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(close)) => Err(error.with_cause(close)),
    }
}

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
