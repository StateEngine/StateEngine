//! Registry-declared host operations never acquire a direct writer lease.
//! Bootstrap can run once before submission; the keyed call itself is never retried.
use super::{admit::Caller, execute, files::Files};
use crate::bootstrap::Bootstrap;
use se_core::{
    ops::{AnyOp, AnyOutput, CliSelections},
    registry::RuntimeNeed,
    scope,
};
use se_host::client::{ClientOptions, lease::Deadline};
use se_types::{Read, Result, SeError};
use std::sync::Arc;

fn forward_once<R: se_store::ReadStore>(
    cx: &Bootstrap,
    files: &Files,
    reader: &R,
    caller: &Caller,
    operation: AnyOp,
    selections: &CliSelections,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<AnyOutput> {
    let options = execute::options();
    let bound = Deadline::from_options(&options)?;
    let automatic = operation.meta().runtime == RuntimeNeed::HostAutoStart;
    let target = if automatic {
        #[cfg(any(target_os = "linux", windows))]
        {
            super::autostart::endpoint(cx, files, &bound, diagnostic)?
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = diagnostic;
            return Err(SeError::new(se_types::Detail::RuntimeNotRunning(
                se_types::details::RuntimeNotRunning {
                    op: operation.meta().name.into(),
                    reason: "native automatic host startup is unavailable on this platform".into(),
                },
            )));
        }
    } else {
        match execute::endpoint(files)? {
            Read::Present { value } => value,
            Read::Absent { .. } => {
                return Err(SeError::new(se_types::Detail::RuntimeNotRunning(
                    se_types::details::RuntimeNotRunning {
                        op: operation.meta().name.into(),
                        reason:
                            "no live authenticated host endpoint is published in this data home"
                                .into(),
                    },
                )));
            }
            Read::Unreadable { source, reason, .. } => {
                return Err(scope::unreadable(&source, &reason));
            }
            Read::Unknown { what } => return Err(scope::unreadable("runtime endpoint", &what)),
        }
    };
    // Bootstrap has its own se-up budget before any operation is submitted.
    // The ensuing call still gets the ordinary bounded IPC budget; a slow
    // but successful bootstrap must not leave just milliseconds for custody.
    let bound = if automatic {
        Deadline::from_options(&options)?
    } else {
        bound
    };
    se_proc::native_ipc::restore_image_cache(&cx.home, target.image_sha256, &bound.native_bound())
        .map_err(|error| {
            scope::unreadable("protected executable cache", &error.to_string()).with_cause(error)
        })?;
    let remove_all = matches!(&operation, AnyOp::ProjectRemove(input) if input.all);
    let output = crate::ipc::forward(
        &target,
        execute::credential(cx, files)?,
        operation,
        selections,
        caller
            .owner
            .as_ref()
            .map(|owner| owner.native_observation()),
        &ClientOptions {
            expected_generation: Some(target.generation),
            timeout: bound.remaining()?,
            cancelled: Arc::clone(&bound.native_bound().cancelled),
        },
    )?;
    if remove_all {
        Ok(super::remove::complete(
            files,
            reader,
            &caller.admission,
            &target,
            output,
            &bound,
        ))
    } else {
        Ok(output)
    }
}

/// Human confirmation changes only explicit takeover consent and binds the
/// second request to the inventory that was shown before the answer.
pub fn forward<R: se_store::ReadStore>(
    cx: &Bootstrap,
    files: &Files,
    reader: &R,
    caller: &Caller,
    operation: AnyOp,
    selections: &CliSelections,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<AnyOutput> {
    let retry = match &operation {
        AnyOp::AgentLaunch(input) if !input.override_live => Some(input.clone()),
        _ => None,
    };
    let result = forward_once(cx, files, reader, caller, operation, selections, diagnostic);
    let (Some(mut input), Err(failure)) = (retry, &result) else {
        return result;
    };
    let se_types::Detail::LaunchConfirmationRequired(inventory) = failure.body.detail() else {
        return result;
    };
    use std::io::IsTerminal;
    if cx.json
        || !std::io::stdin().is_terminal()
        || !std::io::stderr().is_terminal()
        || !matches!(
            caller.terminal,
            se_core::admission::HumanTerminal::OutsideAgentTree
        )
    {
        return result;
    }
    diagnostic(&failure.body.message())
        .map_err(|error| scope::unreadable("launch inventory output", &error.to_string()))?;
    diagnostic("Stop these sessions and all their managed jobs, then relaunch? [y/N]")
        .map_err(|error| scope::unreadable("launch confirmation output", &error.to_string()))?;
    use std::io::{BufRead, Read};
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .take(32)
        .read_line(&mut answer)
        .map_err(|error| scope::unreadable("launch confirmation input", &error.to_string()))?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        return Err(se_types::SeError::new(se_types::Detail::Cancelled(
            se_types::details::Cancelled {
                op: "launch confirmation".into(),
            },
        )));
    }
    input.override_live = true;
    input.force_selection = Some(se_core::ops::agent_launch::ForceSelection {
        lifecycles: inventory.lifecycles.clone(),
        sessions: inventory.sessions.clone(),
    });
    forward_once(
        cx,
        files,
        reader,
        caller,
        AnyOp::AgentLaunch(input),
        selections,
        diagnostic,
    )
}
