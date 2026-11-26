//! Atlas context for a provider the owner started in an adopted project. The
//! installed hook names its provider, and the lookup travels the adoption
//! route, so the host checks that provider's ancestry and conversation as it
//! does for capture, and answers only for that registered project.
use crate::{bootstrap::Bootstrap, route};
use se_core::ops::AtlasHookTarget;
use se_host::{
    adoption::{Action, Input, Kind},
    client::ClientOptions,
};
use se_types::{NativePath, Read, Result};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Instant,
};

/// The context text, or `None` when the folder is not an adopted project, the
/// payload names another folder, no host runs, or Atlas has no answer. A
/// payload without its conversation is an error, which the hook keeps silent.
pub(crate) fn lookup(
    cx: &Bootstrap,
    kind: Kind,
    payload: &serde_json::Value,
    target: AtlasHookTarget,
    end: Instant,
) -> Result<Option<String>> {
    let cwd = se_proc::canonicalize_path(&cx.cwd).map_err(super::failure)?;
    let Some(registration) = se_host::adoption::read_for(&cx.home, kind)? else {
        return Ok(None);
    };
    let Some(project) = registration.project(&cwd)?.map(|p| p.project.clone()) else {
        return Ok(None);
    };
    let Some((conversation, transcript)) = super::conversation(payload, &cwd)? else {
        return Ok(None);
    };
    let input = Input {
        kind,
        project,
        cwd: NativePath::from_local(cwd)?,
        conversation,
        transcript,
        action: Action::Context,
        cursor: None,
        offered: vec![],
        context: Some(target),
    };
    let files =
        route::files::Files::open(&cx.home).map_err(|e| se_core::store_error::store_error(&e))?;
    let Read::Present { value: endpoint } = route::execute::endpoint(&files)? else {
        return Ok(None);
    };
    let remaining = || {
        end.checked_duration_since(Instant::now()).ok_or_else(|| {
            se_types::SeError::invalid("Atlas hook", "time left before its deadline")
        })
    };
    let options = ClientOptions {
        expected_generation: Some(endpoint.generation),
        timeout: remaining()?,
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    let bound = se_host::client::lease::Deadline::from_options(&options)?;
    se_proc::native_ipc::restore_image_cache(
        &cx.home,
        endpoint.image_sha256,
        &bound.native_bound(),
    )
    .map_err(|e| se_core::scope::unreadable("native hook image cache", &e.to_string()))?;
    let output = crate::ipc::exchange_output(
        &endpoint,
        route::execute::credential(cx, &files)?,
        se_host::IpcEnvelope {
            version: se_types::API_VERSION,
            request_id: 1,
            generation: endpoint.generation,
            authority: None,
            presence: None,
            cli_selections: None,
            request: se_host::IpcRequest::Adopt(input),
        },
        &ClientOptions {
            timeout: remaining()?,
            ..options
        },
    )?;
    if output.schema != "se.adoption/1" {
        return Ok(None);
    }
    Ok(output
        .value
        .get("context")
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned))
}
