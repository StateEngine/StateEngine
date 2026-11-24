//! Planning for `delegate.cancel`.
use super::{DelegateCancel, DelegateCancelPlan};
use crate::{
    commit::Cx, dispatch::admitted, ops::inputs::Validate, scope, store_error::store_error,
};
use se_store::{Actor, EventBody, Snapshot};
use se_types::{Named, Read, Result, SeError};

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
