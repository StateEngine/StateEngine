mod adoption;
mod atlas_hook;
mod bootstrap;
mod compat;
mod config;
#[cfg(any(target_os = "linux", windows))]
mod foreground;
mod grammar;
mod hook;
mod installation_error;
mod installer;
mod ipc;
mod mcp;
mod mcp_stdio;
mod private_entry;
mod remote;
#[cfg(feature = "remote")]
mod remote_owner;
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
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub fn run(
    args: Vec<OsString>,
    mut dispatch: impl FnMut(
        &bootstrap::Bootstrap,
        AnyOp,
        &mut dyn FnMut(&str) -> io::Result<()>,
    ) -> se_types::Result<AnyOutput>,
) -> io::Result<u8> {
    #[cfg(feature = "remote")]
    if let Some(result) = remote_owner::entry(&args) {
        return result;
    }
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let original_args = args.clone();
    let invocation = match grammar::parse(args) {
        Ok(invocation) => invocation,
        Err(failure) => {
            if let Some(remote) = failure.remote {
                return remote::parse_refusal(
                    &failure.error,
                    failure.json,
                    remote.key.as_ref(),
                    &mut stderr,
                );
            }
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
    let retry_invocation = route::startup_retry::Invocation::new(original_args, &common);
    let mut operation = invocation.operation;
    #[cfg(feature = "remote")]
    if let Some(output) = remote_owner::help(&operation) {
        return render::output(&output, common.json, common.quiet, &mut stdout);
    }
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
    if let Err(error) = operation
        .resolve_stdin(&mut bootstrap::text_input)
        .and_then(|()| operation.validate())
    {
        if operation.is_client() {
            return remote::refusal(&error, &operation, common.json, &mut stderr);
        }
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
    let mut context = match bootstrap::check_session_route(&operation).and_then(|()| {
        bootstrap::Bootstrap::resolve(
            common.home,
            common.project,
            common.no_color,
            common.json,
            &operation,
        )
    }) {
        Ok(context) => context,
        Err(error) => {
            if operation.is_client() {
                return remote::refusal(&error, &operation, common.json, &mut stderr);
            }
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
    context.retry_invocation = Some(retry_invocation);
    // Remote structured stderr is reserved for keyed status/error records.
    // Legacy variables never contribute input or authority to these calls.
    if context.legacy_environment_present && !(operation.is_client() && common.json) {
        writeln!(
            stderr,
            "warning[w-legacy-env-present]: legacy STATEENGINE_* variables are present and ignored"
        )?;
    }
    if operation.is_client() {
        return remote::run(
            &context,
            operation,
            common.json,
            common.quiet,
            &mut stdout,
            &mut stderr,
            &mut dispatch,
        );
    }
    if let AnyOp::MessageSend(input) = &operation {
        remote::pending_native(&context, input, common.json, &mut stderr)?;
    }
    #[cfg(any(target_os = "linux", windows))]
    if matches!(&operation, AnyOp::RuntimeUp(input) if input.foreground) {
        // The Windows host loop uses its own bounded stack. Do not hold a
        // main-thread stream lock while that loop prints startup or shutdown.
        drop(stdout);
        drop(stderr);
        return foreground::run(&context, common.json, common.quiet);
    }
    #[cfg(windows)]
    let foreground_fallback = matches!(&operation, AnyOp::RuntimeUp(_));
    let atlas_presentation = operation.atlas_options().cloned();
    let result = {
        let mut diagnostic = |message: &str| {
            writeln!(stderr, "{message}")?;
            stderr.flush()
        };
        dispatch(&context, operation, &mut diagnostic)
            .map_err(|error| route::setup::with_recovery_remedy(error, &context.home))
    };
    #[cfg(windows)]
    if foreground_fallback
        && result
            .as_ref()
            .is_err_and(|error| error.code() == se_types::Code::JobBreakawayRefused)
    {
        writeln!(
            stderr,
            "Windows prevented detached startup; starting in the foreground. Keep this terminal open; use se down with the same home from another terminal to stop the host."
        )?;
        stderr.flush()?;
        drop(stdout);
        drop(stderr);
        return foreground::run(&context, common.json, common.quiet);
    }
    let setup_remedy = route::setup::InitRemedy {
        home: &context.home,
        workspace: &context.cwd,
    };
    let render_context = RenderCx {
        commands: Some(&setup_remedy),
        ..RenderCx::default()
    };
    if result.as_ref().is_ok_and(AnyOutput::maintenance_pending) {
        // The commit is known to have succeeded. Diagnostic delivery cannot
        // change its receipt or turn that success into an uncertain outcome.
        let _ = writeln!(
            stderr,
            "warning: the operation committed successfully, but database maintenance failed and remains pending"
        )
        .and_then(|()| stderr.flush());
    }
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
                render::error::write(&error, &render_context, false, &mut stdout, &mut stderr)?;
            }
        }
        return Ok(0);
    }
    let handoff = runtime::uninstall_completion::take_started();
    if let Some(receiver) = handoff {
        if let Err(error) = &result {
            writeln!(
                stderr,
                "Uninstall parent post-authorization observation: {}; final outcome awaits the helper",
                error.body.message()
            )?;
            stderr.flush()?;
        }
        if common.json && !receiver {
            // Structured effects remain explicitly pending, never complete.
            if let Ok(output) = &result {
                render::output(output, true, common.quiet, &mut stdout)?;
            }
        } else if !common.json {
            if let Ok(AnyOutput::Uninstall(value)) = &result {
                render::uninstall_deferred(&value.value, &mut stdout)?;
            }
            stdout.flush()?;
        }
        writeln!(
            stderr,
            "Finishing uninstall after this process exits (exit 75). Completion is pending."
        )?;
        if !receiver {
            writeln!(
                stderr,
                "For a final exit status, start with the matching archive's uninstall.ps1. This handoff has already started: use PowerShell Get-Item -LiteralPath on each printed image, record and helper path to check absence; access errors remain unresolved."
            )?;
        }
        stderr.flush()?;
        // The installed image must exit before its helper can remove it. This
        // code means delegation, not success; uninstall.ps1 returns the verdict.
        return Ok(runtime::uninstall_completion::DEFERRED_EXIT);
    }
    match result {
        Ok(output) => render::output_at(
            &output,
            common.json,
            common.quiet,
            &context.home,
            atlas_presentation.as_ref(),
            &mut stdout,
        ),
        Err(error) => render::error::write(
            &error,
            &render_context,
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
    #[cfg(windows)]
    let args = match private_entry::retain_package_parent(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("Cannot retain package wrapper: {error}. Retry through @stateengine/cli.");
            return std::process::ExitCode::FAILURE;
        }
    };
    #[cfg(target_os = "macos")]
    if let Some(result) = se_proc::process_attach_entry(&args) {
        return std::process::ExitCode::from(if result.is_ok() { 0 } else { 126 });
    }
    if let Err(error) = bootstrap::initialize_file_owner() {
        return finish(Err(error), &args);
    }
    #[cfg(windows)]
    if let Some(result) = private_entry::dispatch_console_interrupt(&args) {
        return finish(result, &args);
    }
    if args
        .get(1)
        .is_some_and(|arg| arg == se_proc::atlas_worker::ENTRY)
    {
        #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
        {
            return finish(
                if args.len() == 2 {
                    se_host::atlas_cold::private_entry()
                } else {
                    Err(se_types::SeError::invalid(
                        "Atlas private entry",
                        "no public arguments",
                    ))
                },
                &args,
            );
        }
        #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
        {
            return finish(
                Err(se_types::SeError::invalid(
                    "Atlas cold worker",
                    "native containment on this platform",
                )),
                &args,
            );
        }
    }
    if let Some(code) = adoption::entry(&args) {
        return std::process::ExitCode::from(code);
    }
    if let Some(code) = atlas_hook::entry(&args) {
        return code;
    }
    if let Some(result) = mcp::entry(&args) {
        return finish(result, &args);
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
    std::process::ExitCode::from(run(args, route::execute::dispatch).unwrap_or(70))
}

#[cfg(test)]
#[test]
fn invalid_flag_assignments_stay_private_in_both_renderers()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for flag in ["--help", "--version", "--quiet", "--no-color", "--json"] {
        let args = vec![
            std::ffi::OsString::from("se"),
            std::ffi::OsString::from(format!("{flag}=private-renderer-capability")),
        ];
        let error = match grammar::parse(args) {
            Err(failure) => failure.error,
            Ok(_) => return Err("boolean assignment unexpectedly accepted".into()),
        };
        for json in [false, true] {
            let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
            let exit = render::error::write(
                &error,
                &se_types::RenderCx::default(),
                json,
                &mut stdout,
                &mut stderr,
            )?;
            assert_eq!(exit, 64);
            assert!(!String::from_utf8(stdout)?.contains("private-renderer-capability"));
            assert!(!String::from_utf8(stderr)?.contains("private-renderer-capability"));
        }
    }
    Ok(())
}
