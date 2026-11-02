//! Clap consumes the operation catalogue; no filesystem or ambient configuration is read here.
use super::*;
use crate::registry::{CliExposure, Scope};
use clap::{Arg, ArgAction, ArgMatches, Command};
use se_types::{Cursor, Detail, IdempotencyKey, Result, SeError, details};
use std::path::PathBuf;

mod decode;
mod selections;
pub use decode::{from_matches, from_matches_with_key};
pub use selections::CliSelections;

#[derive(Clone, Debug, Default)]
pub struct CommonArgs {
    pub home: Option<PathBuf>,
    pub project: Option<String>,
    pub json: bool,
    pub quiet: bool,
    pub no_color: bool,
    pub key: Option<IdempotencyKey>,
    pub selections: CliSelections,
}
impl CommonArgs {
    pub fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let (path, m) = deepest(matches);
        let name = selected_meta(matches)?.name;
        let selections = match name {
            "project.status" => CliSelections {
                status_all: !path.is_empty() && flag(m, "all"),
                ..CliSelections::default()
            },
            "working_state.get" | "working_state.set" | "agent.show" | "history.list" => {
                CliSelections {
                    agent: text(m, "agent"),
                    ..CliSelections::default()
                }
            }
            "message.list" => CliSelections {
                mail_to: text(m, "to"),
                mail_list: true,
                ..CliSelections::default()
            },
            _ => CliSelections::default(),
        };
        Ok(Self {
            home: text(m, "home").map(PathBuf::from),
            project: text(m, "project"),
            json: flag(m, "json"),
            quiet: flag(m, "quiet"),
            no_color: flag(m, "no_color"),
            key: text(m, "key").map(IdempotencyKey::new).transpose()?,
            selections,
        })
    }
}
fn text(m: &ArgMatches, id: &str) -> Option<String> {
    m.get_one::<String>(id).cloned()
}
fn flag(m: &ArgMatches, id: &str) -> bool {
    m.get_flag(id)
}
fn required(m: &ArgMatches, id: &str) -> Result<String> {
    text(m, id).ok_or_else(|| {
        SeError::new(Detail::UsageMissingArgument(
            details::UsageMissingArgument {
                command: "se".into(),
                argument: id.into(),
            },
        ))
    })
}
fn many(m: &ArgMatches, id: &str) -> Vec<String> {
    m.get_many::<String>(id)
        .map(|v| v.cloned().collect())
        .unwrap_or_default()
}
fn value(id: &'static str) -> Arg {
    Arg::new(id).long(id).num_args(1)
}
fn toggle(id: &'static str) -> Arg {
    Arg::new(id).long(id).action(ArgAction::SetTrue)
}
fn positional(id: &'static str, index: usize, required: bool) -> Arg {
    Arg::new(id).index(index).required(required)
}
fn deepest(mut matches: &ArgMatches) -> (Vec<String>, &ArgMatches) {
    let mut path = Vec::new();
    while let Some((name, next)) = matches.subcommand() {
        path.push(name.to_owned());
        matches = next;
    }
    (path, matches)
}
fn unknown(command: &str) -> SeError {
    SeError::new(Detail::UsageUnknownCommand(details::UsageUnknownCommand {
        got: command.into(),
        suggestion: None,
    }))
}
fn unknown_flag(flag: &str, command: &str, reason: &str) -> SeError {
    SeError::new(Detail::UsageUnknownFlag(details::UsageUnknownFlag {
        flag: flag.into(),
        command: command.into(),
        reason: reason.into(),
    }))
}

pub fn cli_command() -> Command {
    let mut root = Command::new("se")
        .about("StateEngine — durable agent work and context")
        .disable_help_flag(true)
        .disable_version_flag(true)
        .disable_help_subcommand(true)
        .arg(toggle("version").short('V').global(true))
        .arg(toggle("help").short('h').global(true))
        .arg(value("home").global(true))
        .arg(value("project").short('p').global(true))
        .arg(toggle("json").global(true))
        .arg(toggle("quiet").short('q').global(true))
        .arg(
            Arg::new("no_color")
                .long("no-color")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .arg(value("key").global(true));
    for meta in CATALOGUE {
        if let CliExposure::Leaf { path, hidden, .. } = meta.cli {
            root = insert(root, path, meta.name, hidden);
        }
    }
    // MCP is a streaming transport for the registered operations, not another
    // store operation with a fabricated product output family.
    root.subcommand(
        Command::new("mcp")
            .about("Serve session tools over newline-delimited JSON-RPC on stdin/stdout")
            .disable_help_flag(true)
            .disable_version_flag(true)
            .disable_help_subcommand(true)
            .arg(toggle("stdio")),
    )
}
fn insert(command: Command, path: &[&'static str], name: &str, hidden: bool) -> Command {
    let Some((head, tail)) = path.split_first() else {
        return command;
    };
    let update = |child| {
        if tail.is_empty() {
            input_command(name, child).hide(hidden)
        } else {
            insert(child, tail, name, hidden)
        }
    };
    if command.find_subcommand(head).is_some() {
        command.mut_subcommand(*head, update)
    } else {
        command.subcommand(update(
            Command::new(*head)
                .hide(hidden)
                .disable_help_flag(true)
                .disable_version_flag(true)
                .disable_help_subcommand(true),
        ))
    }
}
fn input_command(name: &str, c: Command) -> Command {
    match name {
        "meta.help" => c
            .arg(Arg::new("path").num_args(0..).action(ArgAction::Append))
            .arg(toggle("all")),
        "meta.schema" => c.arg(positional("op", 1, false)),
        "project.init" => c
            .arg(value("repo"))
            .arg(value("name"))
            .arg(value("agent").default_value("main"))
            .arg(value("provider").value_parser(["claude", "codex"]))
            .arg(value("model"))
            .arg(toggle("launch"))
            .arg(toggle("adopt")),
        "project.status" => c.arg(toggle("all")),
        "history.event_read" => c.arg(
            value("event")
                .conflicts_with_all(["agent", "session", "kind", "since", "limit", "cursor"]),
        ),
        "history.list" => c
            .arg(value("agent"))
            .arg(value("session"))
            .arg(value("kind").action(ArgAction::Append))
            .arg(
                value("since")
                    .help("An event position from se history, scoped to this caller and project"),
            )
            .arg(value("limit").default_value("20"))
            .arg(value("cursor")),
        "message.send" => c
            .arg(positional("to", 1, true))
            .arg(positional("body", 2, true))
            .arg(value("kind").default_value("note").value_parser([
                "note", "task", "question", "answer", "blocker", "done", "handoff", "finding",
            ]))
            .arg(Arg::new("refs").long("ref").action(ArgAction::Append))
            .arg(value("reply_to").long("reply-to")),
        "message.list" => c
            .arg(value("to"))
            .arg(value("from"))
            .arg(value("kind").value_parser([
                "note", "task", "question", "answer", "blocker", "done", "handoff", "finding",
            ]))
            .arg(toggle("all"))
            .arg(toggle("full"))
            .arg(value("limit").default_value("20"))
            .arg(value("preview_chars").long("preview-chars"))
            .arg(value("cursor"))
            .arg(
                value("box")
                    .value_parser(["inbox", "sent"])
                    .default_value("inbox"),
            ),
        "working_state.get" => c.arg(value("agent")),
        "agent.show" => c.arg(positional("agent", 1, true)),
        "agent.list" => c
            .arg(value("limit").default_value("20"))
            .arg(value("cursor")),
        "config.get" => c
            .arg(positional("setting_key", 1, true))
            .arg(toggle("origin")),
        "config.set" => {
            c.arg(positional("setting_key", 1, true))
                .arg(positional("setting_value", 2, true))
        }
        "agent.create" => c
            .arg(positional("name", 1, true))
            .arg(value("provider").value_parser(["claude", "codex"]))
            .arg(value("model")),
        "decision.show" => c.arg(positional("decision_id", 1, true)),
        "decision.propose" => c
            .arg(positional("decision_key", 1, true))
            .arg(positional("statement", 2, true))
            .arg(value("rationale"))
            .arg(value("supersedes")),
        "decision.ratify" => c
            .arg(positional("decision_id", 1, true))
            .arg(value("expect")),
        "decision.reject" | "decision.retract" => c
            .arg(positional("decision_id", 1, true))
            .arg(value("reason").required(true))
            .arg(value("expect")),
        "decision.supersede" => c
            .arg(positional("decision_id", 1, true))
            .arg(positional("replacement_id", 2, true))
            .arg(value("expect")),
        "working_state.set" => c
            .arg(positional("text", 1, true))
            .arg(value("expect").required(true))
            .arg(value("agent")),
        "runtime.up" => c.arg(toggle("foreground")),
        "hook.claude" => c.arg(positional("event", 1, true).value_parser([
            "session-start",
            "prompt",
            "stop",
            "stop-failure",
        ])),
        _ => c,
    }
}
pub fn selected_meta(matches: &ArgMatches) -> Result<&'static crate::registry::OpMeta> {
    let (path, m) = deepest(matches);
    if flag(m, "version") {
        return Ok(&MetaVersion::META);
    }
    if flag(m, "help") {
        return Ok(&MetaHelp::META);
    }
    if path.is_empty() {
        return Ok(&ProjectStatus::META);
    }
    let same_path = |meta: &crate::registry::OpMeta| {
        matches!(meta.cli,
        CliExposure::Leaf {path: registered, ..} if registered.iter().copied().eq(path.iter().map(String::as_str)))
    };
    CATALOGUE
        .iter()
        .copied()
        .find(|meta| {
            same_path(meta)
                && matches!(meta.cli,
        CliExposure::Leaf {select: Selector::Flag(flag), ..}
            if m.value_source(flag) == Some(clap::parser::ValueSource::CommandLine))
        })
        .or_else(|| {
            CATALOGUE.iter().copied().find(|meta| {
                same_path(meta)
                    && matches!(
                        meta.cli,
                        CliExposure::Leaf {
                            select: Selector::Always,
                            ..
                        }
                    )
            })
        })
        .ok_or_else(|| unknown(&path.join(" ")))
}
fn number(m: &ArgMatches, id: &str) -> Result<u16> {
    required(m, id)?
        .parse()
        .map_err(|_| SeError::invalid(id, "a bounded positive integer"))
}
