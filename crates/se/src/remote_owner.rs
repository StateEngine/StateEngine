//! Native human controls use a separate IPC branch, never a core/MCP data verb.
use clap::ArgMatches;
use se_core::ops::{AnyOp, AnyOutput, HelpOutput, Validate};
use se_host::remote::OwnerInput;
use se_types::{IdempotencyKey, Result, SeError};
use std::{
    ffi::OsString,
    io::{self, Write},
};
mod grammar;
pub(crate) enum Input {
    Ready(OwnerInput),
}
impl Input {
    pub(crate) fn is_bootstrap(&self) -> bool {
        matches!(self, Self::Ready(OwnerInput::Bootstrap { .. }))
    }
    pub(crate) fn requires_terminal(&self) -> bool {
        match self {
            Self::Ready(input) => input.requires_terminal(),
        }
    }
    pub(crate) fn resolve(self) -> OwnerInput {
        match self {
            Self::Ready(input) => input,
        }
    }
}
pub(crate) fn help(operation: &AnyOp) -> Option<AnyOutput> {
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
pub(crate) fn entry(args: &[OsString]) -> Option<io::Result<u8>> {
    // A cheap candidate filter avoids constructing optional control grammar
    // for ordinary local CLI reads. Only the full parse below selects a route.
    if !args.iter().any(|word| word == "remote") {
        return None;
    }
    let command = if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        crate::grammar::help_grammar(grammar::command())
    } else {
        grammar::command()
    };
    match command.clone().try_get_matches_from(args) {
        Ok(matches) => selected_control(&matches).map(|(name, selected)| run(name, selected)),
        Err(error) => {
            // Only a refused invocation needs diagnostic recognition. Parsed
            // option values cannot select a privileged control route.
            let matches = command
                .ignore_errors(true)
                .try_get_matches_from(args)
                .ok()?;
            selected_control(&matches)?;
            Some(crate::render::error::write(
                &crate::grammar::usage_error(error, args),
                &se_types::RenderCx::default(),
                crate::grammar::json_requested(args),
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
fn run(name: &str, m: &ArgMatches) -> io::Result<u8> {
    let (mut stdout, mut stderr) = (io::stdout().lock(), io::stderr().lock());
    let json = m.get_flag("json");
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
        let cx = crate::bootstrap::Bootstrap::resolve_remote_owner(
            text(m, "home").map(Into::into),
            m.get_flag("no_color"),
            json,
        )?;
        let output = crate::route::remote_owner::execute(&cx, input)?;
        Ok((None, Some(output)))
    })();
    match result {
        Ok((Some(help), _)) => crate::render::output(&help, json, false, &mut stdout),
        Ok((_, Some(output))) => {
            if name == "__authorize" {
                return authorize(m, &mut stdout);
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
            Ok(0)
        }
        Ok(_) => Err(io::Error::other("remote control produced no result")),
        Err(error) => crate::render::error::write(
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
fn authorize(m: &ArgMatches, stdout: &mut impl Write) -> io::Result<u8> {
    let cx = crate::bootstrap::Bootstrap::resolve_remote_owner(
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
    let request: se_host::remote::ssh::Authorization = serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::other("SSH authorization input is malformed"))?;
    let channel = request.channel;
    let result =
        crate::route::remote_owner::execute(&cx, Input::Ready(OwnerInput::Authorize(request)))
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
