//! Presentation parsing over core's generated grammar. No state is accessed.
use clap::{
    Command,
    error::{ContextKind, ContextValue, ErrorKind},
};
use se_core::ops::{self, AnyOp, CommonArgs};
use se_types::{Detail, IdempotencyKey, SeError, details};
use std::ffi::{OsStr, OsString};

pub struct Invocation {
    pub operation: AnyOp,
    pub common: CommonArgs,
}

pub struct Failure {
    pub error: Box<SeError>,
    pub json: bool,
}

/// Includes argv[0]. Compatibility refuses before clap or any state consumer.
pub fn parse(args: Vec<OsString>) -> std::result::Result<Invocation, Failure> {
    let arguments = args.get(1..).unwrap_or_default();
    let json = json_requested(&args);
    let parse = || -> se_types::Result<Invocation> {
        if let Some(error) = crate::compat::refusal(arguments) {
            return Err(error);
        }
        let mut command = ops::cli_command();
        let matches = match command.try_get_matches_from_mut(&args) {
            Ok(matches) => matches,
            Err(error)
                if error.kind() == ErrorKind::MissingRequiredArgument
                    && has_flag(arguments, &["--help", "-h"]) =>
            {
                // The generated help selector is an operation, rather than
                // clap's early-exit action. Required input is irrelevant to it.
                help_grammar(command)
                    .try_get_matches_from(&args)
                    .map_err(|error| usage_error(error, &args))?
            }
            Err(error) => return Err(usage_error(error, &args)),
        };
        let common = CommonArgs::from_matches(&matches)?;
        let generated = if ops::selected_meta(&matches)?.mutates() && common.key.is_none() {
            Some(IdempotencyKey::new(uuid::Uuid::new_v4().to_string())?)
        } else {
            None
        };
        let operation = ops::from_matches_with_key(&matches, generated)?;
        Ok(Invocation { operation, common })
    };
    parse().map_err(|error| Failure {
        error: Box::new(error),
        json,
    })
}

pub fn json_requested(args: &[OsString]) -> bool {
    has_flag(args.get(1..).unwrap_or_default(), &["--json"])
}

fn has_flag(args: &[OsString], names: &[&str]) -> bool {
    args.iter()
        .take_while(|arg| arg.as_os_str() != OsStr::new("--"))
        .any(|arg| names.iter().any(|name| arg.as_os_str() == OsStr::new(name)))
}

fn help_grammar(command: Command) -> Command {
    command
        .mut_args(|arg| arg.required(false))
        .mut_subcommands(help_grammar)
}

fn context(error: &clap::Error, kind: ContextKind) -> String {
    error.get(kind).map(ToString::to_string).unwrap_or_default()
}

fn usage_error(error: clap::Error, args: &[OsString]) -> SeError {
    let argument = ops::diagnostic_word(&context(&error, ContextKind::InvalidArg)).to_owned();
    let command = error_command(args);
    let flag = argument.split_whitespace().next().unwrap_or_default();
    let missing_value = error.kind() == ErrorKind::InvalidValue
        && context(&error, ContextKind::InvalidValue).is_empty()
        && flag.starts_with('-')
        && args
            .iter()
            .position(|arg| arg == flag)
            .is_some_and(|index| {
                args.get(index + 1)
                    .is_none_or(|next| next.to_string_lossy().starts_with('-'))
            });
    if missing_value {
        return SeError::new(Detail::UsageMissingArgument(
            details::UsageMissingArgument {
                command,
                argument: format!("a value for {argument}"),
            },
        ));
    }
    let detail = match error.kind() {
        ErrorKind::UnknownArgument if argument.starts_with('-') => Detail::UsageUnknownFlag(details::UsageUnknownFlag {
            reason: match argument.as_str() {
                "--registry-root" => "use --home DIR for the StateEngine state directory",
                "--project-root" | "--repo-root" | "--root" => "use se init --repo DIR to register a folder; --home selects StateEngine state",
                "--actor" | "--agent-id" | "--user-id" | "--human-actor" => "identity comes from the verified owner or launched session",
                _ => "unknown or inapplicable flag; inspect this command's --help",
            }.into(),
            flag: ops::diagnostic_word(&argument).into(),
            command,
        }),
        ErrorKind::InvalidSubcommand | ErrorKind::UnknownArgument => {
            let got = if argument.is_empty() { ops::diagnostic_word(&context(&error, ContextKind::InvalidSubcommand)).to_owned() } else { argument };
            let suggestion = match error.get(ContextKind::ValidSubcommand) {
                Some(ContextValue::Strings(commands)) => spelling(&got, commands),
                _ => None,
            };
            Detail::UsageUnknownCommand(details::UsageUnknownCommand { got, suggestion })
        }
        ErrorKind::ArgumentConflict => Detail::UsageConflictingFlags(details::UsageConflictingFlags {
            flags: vec![argument, ops::diagnostic_word(&context(&error, ContextKind::PriorArg)).into()],
        }),
        ErrorKind::MissingRequiredArgument => Detail::UsageMissingArgument(details::UsageMissingArgument {
            command, argument,
        }),
        _ => Detail::UsageInvalidValue(details::UsageInvalidValue {
            argument: argument.clone(),
            got: context(&error, ContextKind::InvalidValue),
            expected: {
                let expected = context(&error, ContextKind::ValidValue);
                if expected.is_empty() { format!("a valid value for {argument}") } else { expected }
            },
        }),
    };
    SeError::new(detail)
}

/// A second, diagnostics-only parse retains the recognized command prefix.
/// It consumes option values through Clap, so a home or task named after a
/// subcommand cannot be mistaken for the help target. Its matches never execute.
fn error_command(args: &[OsString]) -> String {
    let mut path = vec!["se".to_owned()];
    if let Ok(matches) = ops::cli_command()
        .ignore_errors(true)
        .try_get_matches_from(args)
    {
        let mut current = &matches;
        while let Some((name, child)) = current.subcommand() {
            path.push(name.to_owned());
            current = child;
        }
    }
    path.join(" ")
}

/// Suggestions are selected only from clap's generated live siblings.
fn spelling(got: &str, commands: &[String]) -> Option<String> {
    if got.len() > 128 {
        return None;
    }
    commands
        .iter()
        .filter(|command| command.len() <= 128)
        .map(|command| (edit_distance(got, command), command))
        .filter(|(distance, _)| *distance <= 2)
        .min_by_key(|(distance, command)| (*distance, command.as_str()))
        .map(|(_, command)| command.clone())
}

fn edit_distance(left: &str, right: &str) -> usize {
    let right: Vec<_> = right.chars().collect();
    let mut row: Vec<_> = (0..=right.len()).collect();
    for (index, character) in left.chars().enumerate() {
        let mut diagonal = row[0];
        row[0] = index + 1;
        for (column, other) in right.iter().enumerate() {
            let previous = row[column + 1];
            row[column + 1] = (row[column + 1] + 1)
                .min(row[column] + 1)
                .min(diagonal + usize::from(character != *other));
            diagonal = previous;
        }
    }
    row[right.len()]
}

/// Streaming transport entry uses the same generated clap tree and global
/// syntax. Metadata/help stays on the ordinary store-free presentation path.
pub fn mcp_options(args: &[OsString]) -> Option<se_types::Result<Option<std::path::PathBuf>>> {
    let matches = ops::cli_command().try_get_matches_from(args).ok()?;
    let m = matches.subcommand_matches("mcp")?;
    if m.get_flag("help") || m.get_flag("version") {
        return None;
    }
    let result = (|| {
        for (id, long) in [("project", "--project"), ("key", "--key")] {
            if m.get_one::<String>(id).is_some() {
                return Err(SeError::invalid(
                    long,
                    "MCP session identity and request keys come from each protocol call",
                ));
            }
        }
        if m.get_flag("json") || m.get_flag("quiet") {
            return Err(SeError::invalid(
                "MCP output flags",
                "MCP owns its JSON-RPC stdout; use se mcp --stdio",
            ));
        }
        Ok(m.get_one::<String>("home").map(std::path::PathBuf::from))
    })();
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_help_never_retains_option_values() {
        for (path, expected) in [
            (vec!["--token=private-inline-capability"], "--token"),
            (vec!["-tprivate-inline-capability"], "-t"),
            (vec!["foo", "--x=private-inline-capability"], "foo --x"),
            (vec!["msg", "-tprivate-inline-capability"], "msg -t"),
        ] {
            let args = ["se", "help", "--"]
                .into_iter()
                .chain(path)
                .map(OsString::from)
                .collect();
            let invocation = match parse(args) {
                Ok(invocation) => invocation,
                Err(_) => panic!("explicit help must reach the metadata reader"),
            };
            let error = ops::metadata_output(&invocation.operation)
                .err()
                .unwrap_or_else(|| panic!("unknown help target must refuse"));
            let Detail::UsageUnknownCommand(detail) = error.body.detail() else {
                panic!("unknown help target must retain its command diagnostic");
            };
            assert_eq!(detail.got, expected);
            assert!(
                !serde_json::to_string(&error.body)
                    .unwrap()
                    .contains("private-inline-capability")
            );
        }
    }
    #[test]
    fn unknown_options_never_retain_values() {
        for prefix in [
            vec!["se"],
            vec!["se", "doctor"],
            vec!["se", "msg", "send"],
            vec!["se", "--"],
            vec!["se", "doctor", "--"],
        ] {
            for (option, expected) in [
                ("--token=private-inline-capability", "--token"),
                ("-tprivate-inline-capability", "-t"),
                ("-t=private-inline-capability", "-t"),
            ] {
                let args = prefix
                    .iter()
                    .copied()
                    .chain([option])
                    .map(OsString::from)
                    .collect();
                let Err(failure) = parse(args) else {
                    panic!("an unknown option must refuse");
                };
                match failure.error.body.detail() {
                    Detail::UsageUnknownFlag(detail) => assert_eq!(detail.flag, expected),
                    Detail::UsageUnknownCommand(detail) => assert_eq!(detail.got, expected),
                    _ => panic!("the option must retain its diagnostic"),
                }
                assert!(
                    !serde_json::to_string(&failure.error.body)
                        .unwrap()
                        .contains("private-inline-capability")
                );
            }
        }
    }
}
