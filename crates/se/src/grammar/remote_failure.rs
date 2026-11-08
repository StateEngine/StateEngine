//! Failure-channel annotations only; no operation, store or remote admission.
use super::RemoteFailure;
use clap::{ArgMatches, Command};
use se_core::ops;
use se_types::IdempotencyKey;
use std::ffi::OsString;

pub(super) fn classify(args: &[OsString]) -> Option<RemoteFailure> {
    let command = ops::cli_command();
    let matches = command
        .clone()
        .ignore_errors(true)
        .try_get_matches_from(args)
        .ok()?;
    if !matches!(
        ops::selected_meta(&matches).ok()?.name,
        "remote.list" | "remote.watch" | "remote.send"
    ) {
        return None;
    }
    Some(RemoteFailure {
        key: supplied_key(args, &command, &matches),
    })
}

// Clap stops at the first syntax error. Recover a later supplied key without
// mistaking another option's value or text after `--` for a key. Value-taking
// flags come from the same generated command scope, rather than a second list.
fn supplied_key(
    args: &[OsString],
    command: &Command,
    matches: &ArgMatches,
) -> Option<IdempotencyKey> {
    let mut flags = Vec::new();
    let (mut current, mut selected) = (command, matches);
    loop {
        for arg in current.get_arguments() {
            for name in arg
                .get_long()
                .map(|name| format!("--{name}"))
                .into_iter()
                .chain(arg.get_short().map(|name| format!("-{name}")))
            {
                flags.push((
                    name,
                    arg.get_action().takes_values(),
                    arg.is_allow_hyphen_values_set(),
                ));
            }
        }
        let Some((name, child)) = selected.subcommand() else {
            break;
        };
        current = current.find_subcommand(name)?;
        selected = child;
    }
    let mut words = args.iter().skip(1).peekable();
    let mut key = None;
    while let Some(word) = words.next() {
        let Some(word) = word.to_str() else { continue };
        if word == "--" {
            break;
        }
        let (name, inline) = word
            .split_once('=')
            .map_or((word, None), |(name, value)| (name, Some(value)));
        let Some((_, takes_value, hyphens)) = flags.iter().find(|(flag, ..)| flag == name) else {
            continue;
        };
        if !takes_value {
            continue;
        }
        let value = inline.or_else(|| {
            let next = words.peek()?;
            if !hyphens && next.to_string_lossy().starts_with('-') {
                return None;
            }
            words.next()?.to_str()
        });
        if name == "--key"
            && let Some(candidate) =
                value.and_then(|value| IdempotencyKey::new(value.to_owned()).ok())
        {
            if key.as_ref().is_some_and(|prior| prior != &candidate) {
                return None;
            }
            key = Some(candidate);
        }
    }
    key
}
