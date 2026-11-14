//! Native human controls use a separate IPC branch, never a core/MCP data verb.
#![cfg(feature = "remote")]
use clap::ArgMatches;
use se_core::ops::{AnyOp, AnyOutput, HelpOutput, Validate};
use se_host::remote::OwnerInput;
use se_types::{IdempotencyKey, Result, SeError};
use std::{
    ffi::OsString,
    io::{self, Write},
};
mod grammar;
mod ports;
mod progress;
pub use ports::{OwnerCommands, Presentation};
mod launch_permissions;
mod permissions;
mod source_permissions;
pub enum Input {
    Ready(OwnerInput),
}
impl Input {
    pub fn is_bootstrap(&self) -> bool {
        matches!(self, Self::Ready(OwnerInput::Bootstrap { .. }))
    }
    pub fn requires_terminal(&self) -> bool {
        match self {
            Self::Ready(input) => input.requires_terminal(),
        }
    }
    pub fn resolve(self) -> OwnerInput {
        match self {
            Self::Ready(input) => input,
        }
    }
}
pub fn help(operation: &AnyOp) -> Option<AnyOutput> {
    let AnyOp::MetaHelp(input) = operation else {
        return None;
    };
    input.validate().ok()?;
    if input.path.first().is_some_and(|part| part != "remote") {
        return None;
    }
    let mut command = grammar::command();
    command.build();
    for part in &input.path {
        command = command.find_subcommand(part)?.clone();
    }
    Some(
        HelpOutput {
            path: input.path.clone(),
            usage: command.render_long_help().to_string(),
        }
        .into(),
    )
}
pub fn entry<H: OwnerCommands + Presentation>(
    args: &[OsString],
    host: &H,
) -> Option<io::Result<u8>> {
    // A cheap candidate filter avoids constructing optional control grammar
    // for ordinary local CLI reads. Only the full parse below selects a route.
    if !args.iter().any(|word| word == "remote") {
        return None;
    }
    let command = if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        host.help_grammar(grammar::command())
    } else {
        grammar::command()
    };
    match command.clone().try_get_matches_from(args) {
        Ok(matches) => selected_control(&matches).map(|(name, selected)| run(name, selected, host)),
        Err(error) => {
            // Only a refused invocation needs diagnostic recognition. Parsed
            // option values cannot select a privileged control route.
            let matches = command
                .ignore_errors(true)
                .try_get_matches_from(args)
                .ok()?;
            selected_control(&matches)?;
            Some(host.write_error(
                &host.usage_error(error, args),
                &se_types::RenderCx::default(),
                host.json_requested(args),
                &mut io::stdout().lock(),
                &mut io::stderr().lock(),
            ))
        }
    }
}
fn selected_control(matches: &ArgMatches) -> Option<(&str, &ArgMatches)> {
    let (name, selected) = matches.subcommand_matches("remote")?.subcommand()?;
    grammar::CONTROLS
        .contains(&name)
        .then_some((name, selected))
}
fn run<H: OwnerCommands + Presentation>(name: &str, m: &ArgMatches, host: &H) -> io::Result<u8> {
    let (mut stdout, mut stderr) = (io::stdout().lock(), io::stderr().lock());
    // Saved bindings from earlier releases omit the flag, but this private
    // pipe always owes the source a structured native refusal.
    let json = m.get_flag("json") || name == "__authorize";
    if name == "permissions" && !m.get_flag("help") {
        return permissions::command(m, json, &mut stdout, &mut stderr, host);
    }
    let result = (|| {
        if m.get_flag("help") {
            let mut command = grammar::command();
            command.build();
            let command = command
                .find_subcommand("remote")
                .and_then(|c| c.find_subcommand(name))
                .ok_or_else(|| invalid("known control help"))?;
            return Ok((
                Some(
                    HelpOutput {
                        path: vec!["remote".into(), name.into()],
                        usage: command.clone().render_long_help().to_string(),
                    }
                    .into(),
                ),
                None,
            ));
        }
        if m.get_flag("version") || m.get_one::<String>("project").is_some() {
            return Err(invalid(
                "remote controls accept --home, not --project or --version",
            ));
        }
        if name == "__accept" && !json {
            return Err(invalid(
                "protected SSH bootstrap requires structured pipe output",
            ));
        }
        let input = grammar::decode(name, m)?;
        let cx = host.resolve_owner(
            text(m, "home").map(Into::into),
            m.get_flag("no_color"),
            json,
        )?;
        let output = host.execute_owner(&cx, input, &mut |event| {
            progress::write(event, json, &mut stderr)
        })?;
        Ok((None, Some(output)))
    })();
    match result {
        Ok((Some(help), _)) => host.write_output(&help, json, false, &mut stdout),
        Ok((_, Some(mut output))) => {
            if name == "__authorize" {
                return authorize(m, &output.value, &mut stdout, host);
            }
            if json && name == "add" {
                output.value["permission_review"] = serde_json::json!({
                    "state":"skipped",
                    "reason":"Launch permission review requires a native Owner terminal.",
                    "launch_command":["se","remote","permissions","--name",required(m,"name").map_err(io::Error::other)?,"--launch"],
                });
            }
            if json {
                serde_json::to_writer(
                    &mut stdout,
                    &serde_json::json!({"schema":output.schema,"value":output.value}),
                )
                .map_err(io::Error::other)?;
                writeln!(stdout)?;
            } else if name == "add" {
                writeln!(
                    stdout,
                    "Connected to {} ({}).",
                    output.value["name"].as_str().unwrap_or("machine"),
                    if output.value["reused"].as_bool() == Some(true) {
                        "reused"
                    } else {
                        "saved"
                    }
                )?;
            } else {
                serde_json::to_writer_pretty(&mut stdout, &output.value)
                    .map_err(io::Error::other)?;
                writeln!(stdout)?;
            }
            stdout.flush()?;
            if name == "add" && !json {
                permissions::review(m, &mut stdout, host)?;
            }
            Ok(0)
        }
        Ok(_) => Err(io::Error::other("remote control produced no result")),
        Err(error) => host.write_error(
            &error,
            &se_types::RenderCx::default(),
            json,
            &mut stdout,
            &mut stderr,
        ),
    }
}
fn text(m: &ArgMatches, name: &str) -> Option<String> {
    m.get_one::<String>(name).cloned()
}
fn required(m: &ArgMatches, name: &str) -> Result<String> {
    text(m, name).ok_or_else(|| invalid(name))
}
fn invalid(expected: &str) -> SeError {
    SeError::invalid("remote control", expected)
}

/// This SSH command exits after authorizing one native application channel.
/// The shared forward and native host retain all persistent connection state.
fn authorize<H: OwnerCommands + Presentation>(
    m: &ArgMatches,
    identity: &serde_json::Value,
    stdout: &mut impl Write,
    host: &H,
) -> io::Result<u8> {
    let cx = host
        .resolve_owner(
            text(m, "home").map(Into::into),
            m.get_flag("no_color"),
            true,
        )
        .map_err(io::Error::other)?;
    let mut input = io::stdin().lock();
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let mut limited = std::io::Read::take(&mut input, 32769);
    let count = std::io::BufRead::read_until(&mut limited, b'\n', &mut bytes)?;
    if count == 0 || count > 32768 || bytes.last() != Some(&b'\n') {
        return Err(io::Error::other(
            "SSH authorization requires one bounded input frame",
        ));
    }
    let request: se_host::remote::ssh::SshRequest = serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::other("SSH authorization input is malformed"))?;
    let request = match request {
        se_host::remote::ssh::SshRequest::Authorize(request) => request,
        se_host::remote::ssh::SshRequest::Start(request) => {
            let actual: se_host::remote::ssh::StartResult =
                serde_json::from_value(identity.clone())
                    .map_err(|_| io::Error::other("native SSH restart identity is malformed"))?;
            if request.start != actual.host {
                return Err(io::Error::other(
                    "native SSH restart refused a different saved machine",
                ));
            }
            serde_json::to_writer(&mut *stdout, &actual).map_err(io::Error::other)?;
            writeln!(stdout)?;
            stdout.flush()?;
            return Ok(0);
        }
        se_host::remote::ssh::SshRequest::Permissions(request) => {
            let destination = request.permissions;
            let result = host
                .execute_owner(
                    &cx,
                    Input::Ready(OwnerInput::SourcePermissions(request)),
                    &mut |_| Ok(()),
                )
                .map(|output| output.value)
                .map_err(|error| error.body);
            serde_json::to_writer(
                &mut *stdout,
                &se_host::remote::ssh::PermissionsResult {
                    host: destination,
                    result,
                },
            )
            .map_err(io::Error::other)?;
            writeln!(stdout)?;
            stdout.flush()?;
            return Ok(0);
        }
        se_host::remote::ssh::SshRequest::LaunchPermissions(request) => {
            let destination = request.launch_permissions;
            let result = host
                .execute_owner(
                    &cx,
                    Input::Ready(OwnerInput::LaunchPermissions(request)),
                    &mut |_| Ok(()),
                )
                .map(|output| output.value)
                .map_err(|error| error.body);
            serde_json::to_writer(
                &mut *stdout,
                &se_host::remote::ssh::PermissionsResult {
                    host: destination,
                    result,
                },
            )
            .map_err(io::Error::other)?;
            writeln!(stdout)?;
            stdout.flush()?;
            return Ok(0);
        }
    };
    let channel = request.channel;
    let result = host
        .execute_owner(
            &cx,
            Input::Ready(OwnerInput::Authorize(request)),
            &mut |_| Ok(()),
        )
        .and_then(|output| {
            serde_json::from_value(output.value)
                .map_err(|_| invalid("native SSH authorization result"))
        })
        .map_err(|error| error.body);
    let response = se_host::remote::ssh::AuthorizationResult { channel, result };
    serde_json::to_writer(&mut *stdout, &response).map_err(io::Error::other)?;
    writeln!(stdout)?;
    stdout.flush()?;
    Ok(0)
}
