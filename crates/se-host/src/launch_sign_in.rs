//! A launching terminal's provider sign-in, carried to the host for that launch only.
//! It rides under its own key in the CLI selections, which the host removes before
//! the core decodes them; it lives for the one awaited call in a task local and is
//! never logged, persisted, echoed in an error or put in a receipt. A launch no
//! owner terminal started carries none.
pub use se_harness::SignIn;
use se_harness::sign_in::CLAUDE;
use serde_json::Value;

const KEY: &str = "launch_sign_in";

#[cfg(feature = "listener")]
tokio::task_local! {
    static CURRENT: Option<SignIn>;
}

/// Client: add this terminal's Claude sign-in to a launch's selections. Absent or
/// non-Unicode values are left out, and the host's own values apply instead.
pub(crate) fn attach(selections: &mut Value) {
    let value = |name: &str| {
        std::env::var(name)
            .ok()
            .map(|text| (name.to_owned(), text.into()))
    };
    let values: serde_json::Map<String, Value> =
        CLAUDE.iter().filter_map(|name| value(name)).collect();
    if let Some(object) = selections.as_object_mut() {
        object.insert(KEY.into(), values.into());
    }
}

#[cfg(feature = "listener")]
/// Host: take a launch's sign-in off its selections before the core decodes them,
/// keeping it only when the owner's own connection presents the call.
pub(crate) fn take(
    connection: &crate::PresentedAuthority,
    wire: &mut crate::IpcEnvelope,
) -> se_types::Result<Option<SignIn>> {
    let refused = || {
        se_types::SeError::invalid(
            "launch sign-in",
            "Claude sign-in variable names mapped to text",
        )
    };
    let selections = wire.cli_selections.as_mut().and_then(Value::as_object_mut);
    let Some(value) = selections.and_then(|map| map.remove(KEY)) else {
        return Ok(None);
    };
    let owner = |authority: &crate::PresentedAuthority| {
        matches!(authority, crate::PresentedAuthority::OwnerProof { .. })
    };
    if !owner(connection) || !wire.authority.as_ref().is_none_or(owner) {
        return Ok(None);
    }
    let Value::Object(map) = value else {
        return Err(refused());
    };
    let named = |(name, value): (String, Value)| match value {
        Value::String(text) if CLAUDE.contains(&name.as_str()) => Ok((name, text)),
        _ => Err(refused()),
    };
    map.into_iter()
        .map(named)
        .collect::<se_types::Result<_>>()
        .map(|values| Some(SignIn::from_pairs(values)))
}

/// Run one call with its launching terminal's sign-in in scope.
#[cfg(feature = "listener")]
pub(crate) async fn scope<F: std::future::Future>(sign_in: Option<SignIn>, work: F) -> F::Output {
    CURRENT.scope(sign_in, work).await
}

/// The sign-in of the terminal launching this call; `None` when no terminal did.
#[cfg(feature = "listener")]
pub(crate) fn current() -> Option<SignIn> {
    CURRENT.try_with(Clone::clone).ok().flatten()
}
