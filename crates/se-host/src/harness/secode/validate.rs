use crate::linked::FromLinked;
use secode_stateengine_api as api;

pub(super) fn error(kind: api::ApiFailure, code: &str, message: &str) -> api::ApiError {
    api::ApiError {
        kind, code: code.into(), message: message.into(),
        remedy: api::ApiRemedy { text: "Preserve the original target and request identity; query its native status before retrying. Reopen against the current host after a generation change.".into(), command: None },
        retry: api::ApiRetry::AfterRefresh,
    }
}
pub(super) fn invalid() -> api::ApiError {
    error(
        api::ApiFailure::Unreadable,
        "native-invalid-observation",
        "The native observation does not match its original target, identity or bounds.",
    )
}
pub(super) fn uncertain() -> api::ApiError {
    error(
        api::ApiFailure::Unknown,
        "native-outcome-unknown",
        "The callback did not finish within its cancellation/deadline bound; its native effect may already be committed.",
    )
}
pub(super) fn conversion(value: se_types::SeError) -> api::ApiError {
    crate::linked::api_error(&value)
}
pub(super) fn same(condition: bool) -> api::Result<()> {
    if condition { Ok(()) } else { Err(invalid()) }
}
pub(super) fn target(value: &api::HostSessionTarget) -> api::Result<()> {
    se_types::HostEpoch::from_linked(value.epoch.clone()).map_err(conversion)?;
    se_types::HostSessionId::from_linked(value.session.clone()).map_err(conversion)?;
    se_types::ProjectId::from_linked(value.binding.project.clone()).map_err(conversion)?;
    se_types::AgentId::from_linked(value.binding.agent.clone()).map_err(conversion)?;
    se_types::SessionId::from_linked(value.binding.session.clone()).map_err(conversion)?;
    Ok(())
}
pub(super) fn key(value: &api::IdempotencyKey) -> api::Result<()> {
    se_types::IdempotencyKey::from_linked(value.clone()).map_err(conversion)?;
    Ok(())
}
pub(super) fn event(value: &api::HostEventRef) -> api::Result<()> {
    se_types::HostEventId::from_linked(value.id.clone()).map_err(conversion)?;
    Ok(())
}
pub(super) fn hold(value: &api::HoldReceipt, target: &api::HostSessionTarget) -> api::Result<()> {
    same(value.target == *target)?;
    event(&value.committed)?;
    key(&value.idempotency_key)
}
pub(super) fn binding(
    value: &api::Read<api::BindingObservation>,
    target: &api::HostSessionTarget,
) -> api::Result<()> {
    if let api::Read::Present { value } = value {
        same(value.target == *target)?;
        event(&value.last_transition)?;
    }
    Ok(())
}
pub(super) fn notice(value: &api::MailNotice) -> api::Result<()> {
    se_types::NoticeId::from_linked(value.id.clone()).map_err(conversion)?;
    se_types::Cursor::from_linked(value.through.clone()).map_err(conversion)?;
    same(!value.messages.is_empty() && value.messages.len() <= 32)?;
    let mut seen = std::collections::BTreeSet::new();
    for id in &value.messages {
        se_types::MessageId::from_linked(id.clone()).map_err(conversion)?;
        same(seen.insert(&id.0))?;
    }
    // Include the complete target, with lossless native path encoding. This is
    // a size measurement only; never recompute/rewrite the caller's digest.
    let epoch = se_types::HostEpoch::from_linked(value.target.epoch.clone()).map_err(conversion)?;
    let bytes = serde_json::to_vec(&serde_json::json!({
        "notice":value.id.0,"epoch":epoch,"target":value.target.session.0,
        "binding":[value.target.binding.project.0,value.target.binding.agent.0,value.target.binding.session.0],
        "fingerprint":value.target.binding_fingerprint.0,
        "messages":value.messages.iter().map(|id| &id.0).collect::<Vec<_>>(),
        "through":value.through.0,"dedupe":value.dedupe_sha256.0,
    })).map_err(|_| invalid())?;
    same(bytes.len() <= 8192)?;
    same(crate::linked::native_notice_digest(value).map_err(conversion)? == value.dedupe_sha256)
}
pub(super) fn page_request(value: &api::PageRequest) -> api::Result<()> {
    same(value.limit > 0 && value.max_bytes > 0)?;
    if let Some(cursor) = &value.after {
        se_types::Cursor::from_linked(cursor.clone()).map_err(conversion)?;
    }
    Ok(())
}
pub(super) fn page<T>(
    value: &api::Page<T>,
    request: &api::PageRequest,
    epoch: &api::HostEpoch,
) -> api::Result<()> {
    same(
        value.items.len() <= request.limit as usize
            && value.window.returned == value.items.len() as u64
            && value.window.bytes <= u64::from(request.max_bytes)
            && value.window.limit == request.limit
            && value.window.max_bytes == request.max_bytes
            && value.window.start_cursor == request.after
            && matches!(&value.window.source, api::Source::Host { epoch: actual } if actual == epoch),
    )?;
    for cursor in [&value.next, &value.window.end_cursor]
        .into_iter()
        .flatten()
    {
        se_types::Cursor::from_linked(cursor.clone()).map_err(conversion)?;
    }
    if let Some(next) = &value.next {
        same(Some(next) != request.after.as_ref() && !value.window.complete)?;
    }
    Ok(())
}
