//! Interpret native launch receipts through a finite approved snapshot.
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{Actor, CommitReceipt, EventBody, Snapshot, remote::LaunchAttribution};
use se_types::{
    IdempotencyKey, Result, SeError,
    remote::{RemoteAttribution, RemoteLaunchStarted},
};

pub fn read_launch_receipt<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    native_key: IdempotencyKey,
    launched: RemoteLaunchStarted,
    expected: &RemoteAttribution,
) -> Result<(CommitReceipt, LaunchAttribution)> {
    let receipt = scope::require_present(
        cx.read
            .operation_receipt(cx.admission.actor.clone(), native_key)
            .map_err(|e| store_error(&e))?,
        "remote launch reservation receipt",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    // The closed C1 producer appends attribution last. Other C1 events
    // can contain credential hashes, which this view never exposes.
    let id = receipt.events.last().cloned().ok_or_else(|| {
        SeError::invalid("remote launch receipt", "a nonempty native reservation")
    })?;
    let event = scope::require_present(
        cx.read.event(id).map_err(|e| store_error(&e))?,
        "remote launch attribution event",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    let EventBody::RemoteLaunchAttributed { record: origin } = event.body else {
        return Err(SeError::invalid(
            "remote launch origin",
            "the committed native reservation attribution",
        ));
    };
    if origin.target != launched.target
        || origin.session != launched.session
        || origin.lifecycle != launched.lifecycle
        || origin.attribution.grant != expected.grant
        || origin.attribution.principal != expected.principal
        || origin.attribution.source.as_ref().map(|s| s.address())
            != expected.source.as_ref().map(|s| s.address())
    {
        return Err(SeError::invalid(
            "remote launch origin",
            "the exact original source, destination, session and native lifecycle",
        ));
    }
    Ok((receipt, origin))
}

/// C1 reserves custody; only atomic native activation proves a witnessed start.
/// The original receipt remains authoritative after process stop or host restart.
pub fn launch_activated<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    native_key: IdempotencyKey,
    launch: RemoteLaunchStarted,
) -> Result<bool> {
    let key = crate::ops::process_commit::phase_key(&native_key, "activate")?;
    let read = cx
        .read
        .operation_receipt(cx.admission.actor.clone(), key)
        .map_err(|e| store_error(&e))?;
    if matches!(read, se_types::Read::Absent { .. }) {
        return Ok(false);
    }
    let receipt = scope::require_present(
        read,
        "remote launch activation receipt",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    // The closed native producer writes the lifecycle transition first
    // and session activation second. Credential facts remain private.
    let [process, session, ..] = receipt.events.as_slice() else {
        return Err(SeError::invalid(
            "remote launch activation",
            "the complete original activation batch",
        ));
    };
    let process = scope::require_present(
        cx.read
            .event(process.clone())
            .map_err(|e| store_error(&e))?,
        "remote launch process activation",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    let session = scope::require_present(
        cx.read
            .event(session.clone())
            .map_err(|e| store_error(&e))?,
        "remote launch session activation",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    let process_matches = matches!(process.body,
        EventBody::ProcessTransition { process, to: se_store::ProcessState::Running, identity, .. }
        if process == launch.lifecycle && identity.session.as_ref() == Some(&launch.session)
            && identity.principal == Actor::Agent(launch.target.agent.clone()));
    let session_matches = matches!(session.body,
        EventBody::SessionActivated { session, process: Some(process), .. }
        if session == launch.session && process == launch.lifecycle);
    if !process_matches || !session_matches {
        return Err(SeError::invalid(
            "remote launch activation",
            "the exact original destination, session and lifecycle",
        ));
    }
    Ok(true)
}
