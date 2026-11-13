//! Read native C1 back before exposing a launch receipt to its authenticated origin.
use super::*;
use se_core::{scope, store_error::store_error};
use se_store::{CommitReceipt, EventBody, Snapshot, remote::LaunchAttribution};

pub(super) async fn read_back(
    store: &crate::runtime::store::Store,
    admission: Admission,
    native_key: se_types::IdempotencyKey,
    launched: RemoteLaunchStarted,
    expected: &RemoteAttribution,
    deadline: &crate::client::lease::Deadline,
) -> Result<(CommitReceipt, LaunchAttribution)> {
    let expected = expected.clone();
    store
        .read(admission, deadline, move |cx| {
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
        })
        .await
}

pub(super) fn seal(
    service: &Service,
    receipt: &CommitReceipt,
    origin: &LaunchAttribution,
) -> Result<se_types::Cursor> {
    let associated = serde_json::to_vec(&serde_json::json!({
        "schema":"stateengine.remote-launch-receipt/v1",
        "store":origin.attribution.store,
        "grant":origin.attribution.grant,
        "source":origin.attribution.source.as_ref().map(|s|s.address()),
        "target":origin.target,
        "session":origin.session,
        "lifecycle":origin.lifecycle,
    }))
    .map_err(|_| SeError::invalid("remote launch receipt", "encodable exact origin"))?;
    let position =
        se_store::remote::position_payload(&receipt.first).map_err(|e| store_error(&e))?;
    service.cursors.sealed_receipt(&position, &associated)
}

// C1 reserves native custody; only the atomic activation phase proves that the
// original start succeeded. Its receipt survives process stop and host restart.
pub(super) async fn activated(
    store: &crate::runtime::store::Store,
    admission: Admission,
    native_key: se_types::IdempotencyKey,
    launch: RemoteLaunchStarted,
    deadline: &crate::client::lease::Deadline,
) -> Result<bool> {
    let key = se_core::ops::process_commit::phase_key(&native_key, "activate")?;
    store
        .read(admission, deadline, move |cx| {
            let read = cx.read.operation_receipt(cx.admission.actor.clone(), key)
                .map_err(|e| store_error(&e))?;
            if matches!(read, se_types::Read::Absent { .. }) {
                return Ok(false);
            }
            let receipt = scope::require_present(
                read, "remote launch activation receipt", scope::COMMITTED_READ_RECOVERY,
            )?;
            // The closed native producer writes the lifecycle transition first
            // and session activation second. Credential facts remain private.
            let [process, session, ..] = receipt.events.as_slice() else {
                return Err(SeError::invalid("remote launch activation", "the complete original activation batch"));
            };
            let process = scope::require_present(
                cx.read.event(process.clone()).map_err(|e| store_error(&e))?,
                "remote launch process activation", scope::COMMITTED_READ_RECOVERY,
            )?;
            let session = scope::require_present(
                cx.read.event(session.clone()).map_err(|e| store_error(&e))?,
                "remote launch session activation", scope::COMMITTED_READ_RECOVERY,
            )?;
            let process_matches = matches!(process.body,
                EventBody::ProcessTransition { process, to: se_store::ProcessState::Running, identity, .. }
                if process == launch.lifecycle && identity.session.as_ref() == Some(&launch.session)
                    && identity.principal == Actor::Agent(launch.target.agent.clone()));
            let session_matches = matches!(session.body,
                EventBody::SessionActivated { session, process: Some(process), .. }
                if session == launch.session && process == launch.lifecycle);
            if !process_matches || !session_matches {
                return Err(SeError::invalid("remote launch activation", "the exact original destination, session and lifecycle"));
            }
            Ok(true)
        })
        .await
}
