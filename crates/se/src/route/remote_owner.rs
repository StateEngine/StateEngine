//! Human presence is observed before stdin secrets, startup, keys or networking.
use super::*;
use crate::{bootstrap::Bootstrap, remote_owner::Input};
use se_core::{scope, store_error::store_error};
use se_host::client::{ClientOptions, lease::Deadline};
use se_types::{Result, SeError};
use std::sync::Arc;
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(crate) fn execute(cx: &Bootstrap, input: Input) -> Result<se_host::OperationOutput> {
    if cx.session.is_some() {
        return Err(SeError::invalid(
            "remote authority control",
            "native human presence; session authority cannot pair or expose a listener",
        ));
    }
    let mut setup = setup::inspect_phase(
        &cx.home,
        se_core::ops::receipt::timestamp(execute::now_us()?)?,
    )?;
    if matches!(setup, setup::Setup::Absent(_)) && input.is_bootstrap() {
        let workspace = cx.home.join("workspaces/default");
        let observed = owner::observe(&[])?;
        observed.authorize("SSH initial setup", observed.os_owner(), false, false)?;
        let files = files::Files::create(&cx.home).map_err(|e| store_error(&e))?;
        let workspace_root = cx.home.join("workspaces");
        files
            .0
            .prepare_directory(&workspace_root)
            .map_err(|e| scope::unreadable("remote workspace", &e.to_string()))?;
        se_proc::NativeStateFiles::open(&workspace_root)
            .and_then(|native| native.prepare_directory(&workspace))
            .map_err(|e| scope::unreadable("remote workspace", &e.to_string()))?;
        init::execute(
            cx,
            se_core::ops::ProjectInit {
                harness: None,
                repo: Some(
                    workspace
                        .to_str()
                        .ok_or_else(|| SeError::invalid("remote workspace", "a native UTF-8 path"))?
                        .to_owned(),
                ),
                name: Some("default".into()),
                agent: "main".into(),
                provider: None,
                model: None,
                launch: false,
                adopt: false,
                idempotency_key: se_types::IdempotencyKey::new("remote-initial-setup")?,
            },
        )?;
        setup = setup::inspect_phase(
            &cx.home,
            se_core::ops::receipt::timestamp(execute::now_us()?)?,
        )?;
    }
    let setup::Setup::Present((files, (reader, mut phase))) = setup else {
        return Err(setup::required(cx));
    };
    let caller = admit::observe(cx, &mut phase, &files);
    let closed = phase.close().map_err(|error| store_error(&error));
    let caller = match (caller, closed) {
        (Ok(caller), Ok(())) => caller,
        (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
        (Err(error), Err(close)) => return Err(error.with_cause(close)),
    };
    if input.requires_terminal() {
        se_core::admission::require_human_terminal(
            "remote authority control",
            &caller.admission,
            &caller.terminal,
        )?;
    }
    let owner = caller.owner.as_ref().ok_or_else(|| {
        SeError::invalid(
            "remote authority control",
            "an independently observed native human Owner",
        )
    })?;
    let bootstrap = input.is_bootstrap();
    let input = input.resolve();
    input.validate()?;
    drop(reader);
    let options = execute::options();
    let bound = Deadline::from_options(&options)?;
    #[cfg(any(target_os = "linux", windows))]
    let mut diagnostic = |_: &str| Ok(());
    #[cfg(any(target_os = "linux", windows))]
    let endpoint = autostart::endpoint(cx, &files, &bound, &mut diagnostic)?;
    #[cfg(not(any(target_os = "linux", windows)))]
    let endpoint = scope::require_present(
        execute::endpoint(&files)?,
        "remote control host",
        "Start the existing native host before remote setup on this platform.",
    )?;
    se_proc::native_ipc::restore_image_cache(
        &cx.home,
        endpoint.image_sha256,
        &bound.native_bound(),
    )
    .map_err(|error| {
        scope::unreadable("protected executable cache", &error.to_string()).with_cause(error)
    })?;
    se_proc::native_ipc::restore_remote_image_cache(
        &cx.home,
        endpoint.image_sha256,
        &bound.native_bound(),
    )
    .map_err(|error| {
        scope::unreadable("protected remote executable cache", &error.to_string()).with_cause(error)
    })?;
    let output = crate::ipc::forward_owner(
        &endpoint,
        execute::credential(cx, &files)?,
        input,
        owner.native_observation(),
        &ClientOptions {
            expected_generation: Some(endpoint.generation),
            timeout: bound.remaining()?,
            cancelled: Arc::clone(&bound.native_bound().cancelled),
        },
    )?;
    if bootstrap
        && let Err(error) = se_proc::native_ipc::publish_remote_image_cache(
            &cx.home,
            endpoint.image_sha256,
            &bound.native_bound(),
        )
    {
        eprintln!(
            "Remote setup completed; the optional executable proof cache could not be saved: {error}"
        );
    }
    Ok(output)
}
