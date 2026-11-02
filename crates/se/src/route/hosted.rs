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
#[cfg(any(target_os = "linux", windows))]
use std::time::Duration;

pub fn forward(
    cx: &Bootstrap,
    files: &Files,
    caller: &Caller,
    operation: AnyOp,
    selections: &CliSelections,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<AnyOutput> {
    let options = execute::options();
    let bound = Deadline::from_options(&options)?;
    let target = if operation.meta().runtime == RuntimeNeed::HostAutoStart {
        #[cfg(any(target_os = "linux", windows))]
        {
            super::autostart::endpoint(
                cx,
                files,
                &bound.stage(Duration::from_secs(10))?,
                diagnostic,
            )?
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
    se_proc::native_ipc::restore_image_cache(&cx.home, target.image_sha256, &bound.native_bound())
        .map_err(|error| {
            scope::unreadable("protected executable cache", &error.to_string()).with_cause(error)
        })?;
    crate::ipc::forward(
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
    )
}
