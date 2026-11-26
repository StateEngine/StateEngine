mod adoption;
mod atlas_hook;
mod bootstrap;
mod compat;
mod config;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
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
use se_render as render;
mod repository;
mod route;
mod runtime;

use se_cli_spec::CommonArgs;
use se_core::ops::{AnyOp, AnyOutput, HookEvent};
use se_types::{RenderCx, SeError};
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
    #[cfg(feature = "remote")]
    if let Some(result) = remote_owner::entry(&args) {
        return result;
    }
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let original_args = args.clone();
    let invocation = match parse_invocation(args, &mut stdout, &mut stderr) {
        Ok(invocation) => invocation,
        Err(exit) => return exit,
    };
    let hook_event = match &invocation.operation {
        AnyOp::HookClaude(value) => Some(value.event),
        _ => None,
    };
    let common = invocation.common;
    let retry_invocation = route::startup_retry::Invocation::new(original_args, &common);
    let mut operation = invocation.operation;
    if let Some(code) = fast_exit_output(&operation, hook_event, &common, &mut stdout, &mut stderr)?
    {
        return Ok(code);
    }
    let prepared = operation
        .resolve_stdin(&mut bootstrap::text_input)
        .and_then(|()| operation.validate());
    if let Err(error) = prepared {
        return refuse(
            &error,
            &operation,
            hook_event,
            common.json,
            &mut stdout,
            &mut stderr,
        );
    }
    let (json, quiet, selections) = (common.json, common.quiet, common.selections.clone());
    let mut context =
        match bootstrap_context(&mut operation, hook_event, common, &mut stdout, &mut stderr) {
            Ok(context) => context,
            Err(exit) => return exit,
        };
    context.selections = selections;
    context.retry_invocation = Some(retry_invocation);
    // Remote structured stderr is reserved for keyed status/error records.
    // Legacy variables never contribute input or authority to these calls.
    if context.legacy_environment_present && !(operation.is_client() && json) {
        writeln!(
            stderr,
            "warning[w-legacy-env-present]: legacy STATEENGINE_* variables are present and ignored"
        )?;
    }
    if context.selections.mail_follow {
        return route::mail_follow::run(&context, operation, &mut stdout, &mut stderr);
    }
    if operation.is_client() {
        return remote::run(
            &context,
            operation,
            json,
            quiet,
            &mut stdout,
            &mut stderr,
            &mut dispatch,
        );
    }
    let pending_send = remote::PendingSend::before(&context, &operation, json, &mut stderr)?;
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    if matches!(&operation, AnyOp::RuntimeUp(input) if input.foreground) {
        return foreground_takeover(&context, json, quiet, stdout, stderr);
    }
    let atlas_presentation = operation.atlas_options().cloned();
    #[cfg(windows)]
    let foreground_fallback = matches!(&operation, AnyOp::RuntimeUp(_));
    let result = dispatch_operation(&context, operation, &mut stderr, &mut dispatch);
    #[cfg(windows)]
    if foreground_fallback && job_breakaway_to_foreground(&result, &mut stderr)? {
        return foreground_takeover(&context, json, quiet, stdout, stderr);
    }
    pending_send.after(&context, &result, &mut stderr)?;
    warn_maintenance_pending(&result, &mut stderr);
    if let Some(event) = hook_event
        && !json
    {
        return finish_hook_capture(event, &result, &context, &mut stdout, &mut stderr);
    }
    if let Some(receiver) = runtime::uninstall_completion::take_started() {
        render_uninstall_handoff(receiver, &result, json, quiet, &mut stdout, &mut stderr)?;
        // The installed image must exit before its helper can remove it. This
        // code means delegation, not success; uninstall.ps1 returns the verdict.
        return Ok(runtime::uninstall_completion::DEFERRED_EXIT);
    }
    render_final(
        result,
        &context,
        json,
        quiet,
        atlas_presentation.as_ref(),
        &mut stdout,
        &mut stderr,
    )
}

fn parse_invocation(
    args: Vec<OsString>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<grammar::Invocation, io::Result<u8>> {
    match grammar::parse(args) {
        Ok(invocation) => Ok(invocation),
        Err(failure) => {
            if let Some(remote) = failure.remote {
                return Err(remote::parse_refusal(
                    &failure.error,
                    failure.json,
                    remote.key.as_ref(),
                    stderr,
                ));
            }
            Err(render::error::write(
                &failure.error,
                &RenderCx::default(),
                failure.json,
                stdout,
                stderr,
            ))
        }
    }
}
fn fast_exit_output(
    operation: &AnyOp,
    hook_event: Option<HookEvent>,
    common: &CommonArgs,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<Option<u8>> {
    #[cfg(feature = "remote")]
    if let Some(output) = remote_owner::help(operation) {
        return render::output(&output, common.json, common.quiet, stdout).map(Some);
    }
    match se_cli_spec::metadata_output(operation) {
        Ok(Some(output)) => render::output(&output, common.json, common.quiet, stdout).map(Some),
        Ok(None) => Ok(None),
        Err(error) => {
            render::error::write(&error, &RenderCx::default(), common.json, stdout, stderr)
                .map(|code| {
                    if hook_event.is_some() && !common.json {
                        0
                    } else {
                        code
                    }
                })
                .map(Some)
        }
    }
}
fn refuse(
    error: &SeError,
    operation: &AnyOp,
    hook_event: Option<HookEvent>,
    json: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<u8> {
    if operation.is_client() {
        return remote::refusal(error, operation, json, stderr);
    }
    render::error::write(error, &RenderCx::default(), json, stdout, stderr).map(|code| {
        if hook_event.is_some() && !json {
            0
        } else {
            code
        }
    })
}
fn bootstrap_context(
    operation: &mut AnyOp,
    hook_event: Option<HookEvent>,
    common: CommonArgs,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<bootstrap::Bootstrap, io::Result<u8>> {
    match bootstrap::check_session_route(operation).and_then(|()| {
        bootstrap::Bootstrap::resolve(
            common.home,
            common.project,
            common.no_color,
            common.json,
            operation,
        )
    }) {
        Ok(context) => Ok(context),
        Err(error) => Err(refuse(
            &error,
            operation,
            hook_event,
            common.json,
            stdout,
            stderr,
        )),
    }
}
fn dispatch_operation(
    context: &bootstrap::Bootstrap,
    operation: AnyOp,
    stderr: &mut io::StderrLock<'_>,
    dispatch: &mut impl FnMut(
        &bootstrap::Bootstrap,
        AnyOp,
        &mut dyn FnMut(&str) -> io::Result<()>,
    ) -> se_types::Result<AnyOutput>,
) -> se_types::Result<AnyOutput> {
    let mut diagnostic = |message: &str| {
        writeln!(stderr, "{message}")?;
        stderr.flush()
    };
    dispatch(context, operation, &mut diagnostic)
        .map_err(|error| route::setup::with_recovery_remedy(error, &context.home))
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn foreground_takeover(
    context: &bootstrap::Bootstrap,
    json: bool,
    quiet: bool,
    stdout: io::StdoutLock<'_>,
    stderr: io::StderrLock<'_>,
) -> io::Result<u8> {
    // The Windows host loop uses its own bounded stack. Do not hold a
    // main-thread stream lock while that loop prints startup or shutdown.
    drop(stdout);
    drop(stderr);
    foreground::run(context, json, quiet)
}
#[cfg(windows)]
fn job_breakaway_to_foreground(
    result: &se_types::Result<AnyOutput>,
    stderr: &mut io::StderrLock<'_>,
) -> io::Result<bool> {
    if result
        .as_ref()
        .is_err_and(|error| error.code() == se_types::Code::JobBreakawayRefused)
    {
        writeln!(
            stderr,
            "Windows prevented detached startup; starting in the foreground. Keep this terminal open; use se down with the same home from another terminal to stop the host."
        )?;
        stderr.flush()?;
        return Ok(true);
    }
    Ok(false)
}
fn warn_maintenance_pending(result: &se_types::Result<AnyOutput>, stderr: &mut impl Write) {
    if result.as_ref().is_ok_and(AnyOutput::maintenance_pending) {
        // The commit is known to have succeeded. Diagnostic delivery cannot
        // change its receipt or turn that success into an uncertain outcome.
        let _ = writeln!(
            stderr,
            "warning: the operation committed successfully, but database maintenance failed and remains pending"
        )
        .and_then(|()| stderr.flush());
    }
}
fn finish_hook_capture(
    event: HookEvent,
    result: &se_types::Result<AnyOutput>,
    context: &bootstrap::Bootstrap,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<u8> {
    let setup_remedy = route::setup::InitRemedy {
        home: &context.home,
        workspace: &context.cwd,
    };
    let render_context = RenderCx {
        commands: Some(&setup_remedy),
        ..RenderCx::default()
    };
    match result {
        Ok(AnyOutput::HookClaude(value)) => {
            if let Err(error) = hook::write_native(event, &value.value, stdout, stderr) {
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
            render::error::write(error, &render_context, false, stdout, stderr)?;
        }
    }
    Ok(0)
}
fn render_uninstall_handoff(
    receiver: bool,
    result: &se_types::Result<AnyOutput>,
    json: bool,
    quiet: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<()> {
    if let Err(error) = result {
        writeln!(
            stderr,
            "Uninstall parent post-authorization observation: {}; final outcome awaits the helper",
            error.body.message()
        )?;
        stderr.flush()?;
    }
    if json && !receiver {
        // Structured effects remain explicitly pending, never complete.
        if let Ok(output) = result {
            render::output(output, true, quiet, stdout)?;
        }
    } else if !json {
        if let Ok(AnyOutput::Uninstall(value)) = result {
            render::uninstall_deferred(&value.value, stdout)?;
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
    Ok(())
}
fn render_final(
    result: se_types::Result<AnyOutput>,
    context: &bootstrap::Bootstrap,
    json: bool,
    quiet: bool,
    atlas: Option<&se_core::ops::AtlasOptions>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<u8> {
    let setup_remedy = route::setup::InitRemedy {
        home: &context.home,
        workspace: &context.cwd,
    };
    let render_context = RenderCx {
        commands: Some(&setup_remedy),
        ..RenderCx::default()
    };
    match result {
        Ok(output) => render::output_at(&output, json, quiet, &context.home, atlas, stdout),
        Err(error) => render::error::write(&error, &render_context, json, stdout, stderr),
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
    if args
        .get(1)
        .is_some_and(|arg| arg == se_proc::UNINSTALL_CARRIER_ENTRY)
    {
        return std::process::ExitCode::from(if args.len() == 2 {
            se_proc::uninstall_carrier_entry() as u8
        } else {
            78
        });
    }
    #[cfg(windows)]
    if let Some(result) = private_entry::dispatch_console_interrupt() {
        return finish(result, &args);
    }
    if args
        .get(1)
        .is_some_and(|arg| arg == se_local_socket::forward::ENTRY)
    {
        // Stdout may be the forwarded channel, so a failure is reported on stderr only.
        return match se_local_socket::forward::private_entry(&args) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                let _ = writeln!(io::stderr(), "codex forwarder: {error}");
                std::process::ExitCode::from(1)
            }
        };
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
