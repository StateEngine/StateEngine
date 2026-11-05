//! Reopening one native conversation re-observes its old tools, not executions.
//! Keep the original event; the new capture progress retains the new source proof.
use super::*;

/// A final replay preserves the ended session and uses the existing owner-only
/// historical write path. Live hooks retain their ordinary agent admission.
pub(crate) fn admission<R: Snapshot>(
    recovery_owner: Option<&se_types::HumanId>,
    session: &se_store::ProjectionRecord,
    cx: &mut Cx<'_, R>,
) -> Result<(se_store::Admission, Door)> {
    if matches!(session.current.body, EventBody::SessionActivated { .. }) {
        return Ok((cx.admission.clone(), Door::Hook));
    }
    let Some(owner) =
        recovery_owner.filter(|_| matches!(session.current.body, EventBody::SessionEnded { .. }))
    else {
        return Err(scope::unreadable(
            "capture session",
            "session is not active; final replay requires the coordinator's owner admission",
        ));
    };
    let project = scope::project(cx.admission)?;
    let registered = scope::require_present(
        cx.read
            .project(project)
            .map_err(|error| store_error(&error))?,
        "final capture owner",
        "Restore the original project registration.",
    )?;
    if !matches!(&registered.original.as_deref().unwrap_or(&registered.current).body,
        EventBody::ProjectRegistered { owner: expected, .. } if owner == expected)
    {
        return Err(SeError::invalid(
            "final capture owner",
            "the registered project owner",
        ));
    }
    let mut admission = cx.admission.clone();
    admission.actor = Actor::Human(owner.clone());
    admission.session = None;
    Ok((admission, Door::Import))
}

pub(super) fn canonicalize_tool<R: Snapshot>(
    input: &mut CaptureRequest,
    cx: &mut Cx<'_, R>,
) -> Result<()> {
    if input.provider != Provider::Codex {
        return Ok(());
    }
    let mut observed = super::super::transcript::Record::decode(input.text.as_str())?;
    let Some(tool) = &mut observed.captured_tool else {
        return Ok(());
    };
    let session = tool.session.clone();
    let prior = match cx
        .read
        .native_turn(session.clone(), input.provider, &input.vendor_turn)
        .map_err(|error| store_error(&error))?
    {
        Read::Absent { .. } => return Ok(()),
        value => scope::require_present(
            value,
            "replayed Codex tool",
            "Restore the original immutable native item; preserve the source cursor.",
        )?,
    };
    let EventBody::SessionTurn {
        session: original_session,
        agent,
        provider: Provider::Codex,
        role: Role::System,
        vendor_ref,
        text: StoredText::Present(text),
        evidence,
        ..
    } = prior.body
    else {
        return Err(SeError::invalid(
            "replayed Codex tool",
            "the original native tool record",
        ));
    };
    if original_session == session {
        return Ok(());
    }
    let original = super::super::transcript::Record::decode(&text)?;
    original.validate_evidence(&evidence)?;
    let original_tool = original
        .captured_tool
        .as_ref()
        .ok_or_else(|| SeError::invalid("replayed Codex tool", "the retained native tool facts"))?;
    original_tool.validate_binding(
        &original_session,
        &agent,
        Provider::Codex,
        original_tool.source,
        &evidence,
    )?;
    tool.session = original_session;
    tool.source = original_tool.source;
    tool.position = original_tool.position.clone();
    if matches!(
        tool.target,
        super::super::transcript::tool::Target::Unknown(_)
    ) || matches!(
        original_tool.target,
        super::super::transcript::tool::Target::Unknown(_)
    ) {
        tool.target = original_tool.target.clone();
    }
    observed.position = original.position.clone();
    if observed.body()?.as_str() != original.body()?.as_str() {
        return Err(SeError::invalid(
            "replayed Codex tool",
            "unchanged native identity, phase, tool, target and outcome",
        ));
    }
    input.vendor_turn = vendor_ref;
    input.text = Body::new(text)?;
    Ok(())
}
