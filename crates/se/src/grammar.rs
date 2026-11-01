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
        let command = ops::cli_command();
        let matches = match command.clone().try_get_matches_from(&args) {
            Ok(matches) => matches,
            Err(error)
                if error.kind() == ErrorKind::MissingRequiredArgument
                    && has_flag(arguments, &["--help", "-h"]) =>
            {
                // The generated help selector is an operation, rather than
                // clap's early-exit action. Required input is irrelevant to it.
                help_grammar(command)
                    .try_get_matches_from(&args)
                    .map_err(usage_error)?
            }
            Err(error) => return Err(usage_error(error)),
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

fn usage_error(error: clap::Error) -> SeError {
    let argument = context(&error, ContextKind::InvalidArg);
    let detail = match error.kind() {
        ErrorKind::UnknownArgument if argument.starts_with('-') => Detail::UsageUnknownFlag(details::UsageUnknownFlag {
            reason: match argument.split('=').next().unwrap_or(&argument) {
                "--registry-root" => "use --home DIR for the StateEngine state directory",
                "--project-root" | "--repo-root" | "--root" => "use se init --repo DIR to register a folder; --home selects StateEngine state",
                "--actor" | "--agent-id" | "--user-id" | "--human-actor" => "identity comes from the verified owner or launched session",
                _ => "unknown or inapplicable flag; inspect this command's --help",
            }.into(),
            flag: argument,
            command: "se".into(),
        }),
        ErrorKind::InvalidSubcommand | ErrorKind::UnknownArgument => {
            let got = if argument.is_empty() { context(&error, ContextKind::InvalidSubcommand) } else { argument };
            let suggestion = match error.get(ContextKind::ValidSubcommand) {
                Some(ContextValue::Strings(commands)) => spelling(&got, commands),
                _ => None,
            };
            Detail::UsageUnknownCommand(details::UsageUnknownCommand { got, suggestion })
        }
        ErrorKind::ArgumentConflict => Detail::UsageConflictingFlags(details::UsageConflictingFlags {
            flags: vec![argument, context(&error, ContextKind::PriorArg)],
        }),
        ErrorKind::MissingRequiredArgument => Detail::UsageMissingArgument(details::UsageMissingArgument {
            command: "se".into(), argument,
        }),
        _ => Detail::UsageInvalidValue(details::UsageInvalidValue {
            argument,
            got: context(&error, ContextKind::InvalidValue),
            expected: context(&error, ContextKind::ValidValue),
        }),
    };
    SeError::new(detail)
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
