mod bootstrap;
mod compat;
mod config;
mod grammar;
mod hook;
mod installer;
mod ipc;
mod private_entry;
mod render;
mod route;
mod runtime;

use se_core::ops::{AnyOp, AnyOutput, metadata_output};
use se_types::RenderCx;
use std::{
    ffi::OsString,
    io::{self, Write},
};

/// The binary supplies B03's concrete route once its native/store joins exist.
/// Metadata completes here before environment, configuration or state access.
pub fn run(
    args: Vec<OsString>,
    mut dispatch: impl FnMut(
        &bootstrap::Bootstrap,
        AnyOp,
        &mut dyn FnMut(&str) -> io::Result<()>,
    ) -> se_types::Result<AnyOutput>,
) -> io::Result<u8> {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let invocation = match grammar::parse(args) {
        Ok(invocation) => invocation,
        Err(failure) => {
            return render::error::write(
                &failure.error,
                &RenderCx::default(),
                failure.json,
                &mut stdout,
                &mut stderr,
            );
        }
    };
    let hook_event = match &invocation.operation {
        AnyOp::HookClaude(value) => Some(value.event),
        _ => None,
    };
    let common = invocation.common;
    let mut operation = invocation.operation;
    match metadata_output(&operation) {
        Ok(Some(output)) => return render::output(&output, common.json, common.quiet, &mut stdout),
        Ok(None) => (),
        Err(error) => {
            return render::error::write(
                &error,
                &RenderCx::default(),
                common.json,
                &mut stdout,
                &mut stderr,
            )
            .map(|code| {
                if hook_event.is_some() && !common.json {
                    0
                } else {
                    code
                }
            });
        }
    }
    if let Err(error) = operation.resolve_stdin(&mut bootstrap::text_input) {
        return render::error::write(
            &error,
            &RenderCx::default(),
            common.json,
            &mut stdout,
            &mut stderr,
        )
        .map(|code| {
            if hook_event.is_some() && !common.json {
                0
            } else {
                code
            }
        });
    }
    let mut context =
        match bootstrap::Bootstrap::resolve(common.home, common.project, common.no_color) {
            Ok(context) => context,
            Err(error) => {
                return render::error::write(
                    &error,
                    &RenderCx::default(),
                    common.json,
                    &mut stdout,
                    &mut stderr,
                )
                .map(|code| {
                    if hook_event.is_some() && !common.json {
                        0
                    } else {
                        code
                    }
                });
            }
        };
    context.selections = common.selections;
    if context.legacy_environment_present {
        writeln!(
            stderr,
            "warning[w-legacy-env-present]: legacy STATEENGINE_* variables are present and ignored"
        )?;
    }
    let result = {
        let mut diagnostic = |message: &str| {
            writeln!(stderr, "{message}")?;
            stderr.flush()
        };
        dispatch(&context, operation, &mut diagnostic)
    };
    if let Some(event) = hook_event
        && !common.json
    {
        match result {
            Ok(AnyOutput::HookClaude(value)) => {
                if let Err(error) =
                    hook::write_native(event, &value.value, &mut stdout, &mut stderr)
                {
                    writeln!(stderr, "capture failed: {error}")?;
                    stderr.flush()?;
                }
            }
            Ok(_) => {
                writeln!(
                    stderr,
                    "capture failed: host returned a different operation family"
                )?;
                stderr.flush()?;
            }
            Err(error) => {
                render::error::write(
                    &error,
                    &RenderCx::default(),
                    false,
                    &mut stdout,
                    &mut stderr,
                )?;
            }
        }
        return Ok(0);
    }
    match result {
        Ok(output) => render::output(&output, common.json, common.quiet, &mut stdout),
        Err(error) => render::error::write(
            &error,
            &RenderCx::default(),
            common.json,
            &mut stdout,
            &mut stderr,
        ),
    }
}

fn finish(result: se_types::Result<u8>, args: &[OsString]) -> std::process::ExitCode {
    let code = match result {
        Ok(code) => code,
        Err(error) => render::error::write(
            &error,
            &RenderCx::default(),
            grammar::json_requested(args),
            &mut io::stdout().lock(),
            &mut io::stderr().lock(),
        )
        .unwrap_or(70),
    };
    std::process::ExitCode::from(code)
}

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    if let Err(error) = bootstrap::initialize_file_owner() {
        return finish(Err(error), &args);
    }
    if let Some(result) = runtime::host::dispatch(&args) {
        return finish(result, &args);
    }
    if let Some(result) = private_entry::dispatch_install_hold(&args) {
        match result {
            // run_child has returned and dropped its holder. Preserve every
            // native exit-status bit, including Windows values above 255.
            Ok(code) => std::process::exit(code),
            Err(error) => return finish(Err(error), &args),
        }
    }
    if let Some(result) = private_entry::dispatch(&args, private_entry::receive_uninstall_handoff) {
        return finish(result, &args);
    }
    std::process::ExitCode::from(run(args, route::execute::dispatch).unwrap_or(70))
}
