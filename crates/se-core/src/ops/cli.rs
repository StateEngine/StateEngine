//! Clap consumes the operation catalogue; no filesystem or ambient configuration is read here.
use super::*;
use crate::registry::{CliExposure, Scope};
use clap::{Arg, ArgAction, ArgMatches, Command};
use se_types::{Cursor, Detail, IdempotencyKey, Result, SeError, details};
use std::path::PathBuf;

mod agent_command;
pub use agent_command::AgentCommand;
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
            "continuity.resume" => CliSelections {
                preview: text(m, "preview"),
                ..CliSelections::default()
            },
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
            "agent.launch" => CliSelections {
                agent: text(m, "agent"),
                launch_provider: text(m, "provider")
                    .map(|value| {
                        serde_json::from_value(serde_json::Value::String(value))
                            .map_err(|_| SeError::invalid("provider", "claude or codex"))
                    })
                    .transpose()?,
                ..CliSelections::default()
            },
            "agent.stop" => CliSelections {
                agent: text(m, "agent"),
                control_all: flag(m, "all"),
                stop_release: flag(m, "release"),
                ..CliSelections::default()
            },
            "project.remove" => CliSelections {
                control_all: flag(m, "all"),
                ..CliSelections::default()
            },
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
    Arg::new(id)
        .long(id)
        .num_args(1)
        .allow_negative_numbers(true)
        .value_parser(clap::builder::NonEmptyStringValueParser::new())
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
/// Keep an option name while discarding both equals and attached-short values.
/// A non-option positional word remains the caller's ordinary diagnostic.
pub fn diagnostic_word(word: &str) -> &str {
    if !word.starts_with('-') {
        return word;
    }
    let option = word.split('=').next().unwrap_or(word);
    if option.starts_with("--") {
        return option;
    }
    option
        .char_indices()
        .nth(2)
        .map_or(option, |(end, _)| &option[..end])
}
fn unknown(command: &str) -> SeError {
    SeError::new(Detail::UsageUnknownCommand(details::UsageUnknownCommand {
        got: diagnostic_word(command).into(),
        suggestion: None,
    }))
}
fn unknown_flag(flag: &str, command: &str, reason: &str) -> SeError {
    SeError::new(Detail::UsageUnknownFlag(details::UsageUnknownFlag {
        flag: diagnostic_word(flag).into(),
        command: command_name(command),
        reason: reason.into(),
    }))
}

/// Public CLI spelling for diagnostics, derived from the live catalogue.
pub(crate) fn command_name(operation: &str) -> String {
    CATALOGUE
        .iter()
        .find(|meta| meta.name == operation)
        .and_then(|meta| match meta.cli {
            CliExposure::Leaf { path, .. } if !path.is_empty() => {
                Some(format!("se {}", path.join(" ")))
            }
            _ => None,
        })
        .unwrap_or_else(|| "se".into())
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
    root = root
        .mut_subcommand("decision", |command| {
            input_command("decision.list", command)
                .visible_alias("decisions")
                .args_conflicts_with_subcommands(true)
        })
        .subcommand(
            input_command(
                "decision.list",
                Command::new("pending")
                    .disable_help_flag(true)
                    .disable_version_flag(true)
                    .disable_help_subcommand(true),
            )
            .mut_arg("pending", |arg| arg.default_value("true")),
        );
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
            .arg(toggle("launch").hide(true))
            .arg(toggle("adopt").hide(true)),
        "doctor.inspect" => c.about("Check this installation and name exact supported repairs"),
        "doctor.repair" => c.arg(value("fix").help("Apply only this currently diagnosed CHECK-ID after printing its plan")),
        "store.import_node" => c.about("Import supported user history without changing the original Node state").arg(value("from_node").long("from-node").required(true)).arg(value("source_owner").long("source-owner").help("Source human ID explicitly adopted as the importing owner")).arg(value("map_human").long("map-human").action(ArgAction::Append).help("Historical human ID=existing target human ID; repeat for each explicit correspondence")),
        "project.status" => c.arg(toggle("all")),
        "agent.launch" => c
            .about("Start or resume a saved agent in a window; --detach runs headless")
            .arg(positional("agent", 1, true))
            .arg(toggle("new"))
            .arg(value("provider"))
            .arg(value("model"))
            .arg(value("task"))
            .arg(toggle("detach")),
        "agent.stop" => c
            .arg(positional("agent", 1, false).conflicts_with("all"))
            .arg(toggle("all").conflicts_with("release"))
            .arg(toggle("release")),
        "continuity.resume" => c
            .about("Restore your saved context without acknowledging packets or mail")
            .arg(value("since").help("An opaque cursor from resume for this same agent"))
            .arg(value("budget").default_value("4096").help("Maximum UTF-8 bytes in the JSON reply (1024..1048576)"))
            .arg(value("limit").default_value("20").help("Maximum recent turns and governing decisions per section (1..100)"))
            .arg(value("governing_cursor").long("governing-cursor").help("Continue project rulings from decisions.next_cursor"))
            .arg(value("preview").help("Owner: inspect this saved agent without binding or acknowledging it")),
        "session.context" => c
            .arg(value("since"))
            .arg(value("budget").default_value("32768"))
            .arg(value("governing_cursor").long("governing-cursor"))
            .arg(value("limit").default_value("20")),
        "project.remove" => c
            .arg(toggle("all").conflicts_with("project"))
            .arg(toggle("keep-integrations")),
        "history.event_read" => c.arg(
            value("event")
                .conflicts_with_all(["agent", "session", "kind", "since", "limit", "cursor"]),
        ),
        "history.list" => c
            .about("Read the public timeline: conversations, mail, decisions, working state and saved identity changes")
            .arg(value("agent"))
            .arg(value("session"))
            .arg(value("kind").action(ArgAction::Append))
            .arg(
                value("since")
                    .help("An event position from se history, scoped to this caller and project"),
            )
            .arg(value("limit").default_value("20"))
            .arg(value("cursor")),
        "message.read" => c.arg(positional("msg_id",1,true)).arg(value("budget").default_value("262144").help("Maximum serialized reply bytes, checked before marking read")),
        "message.ack" | "message.dismiss" => c.arg(positional("msg_id",1,true)),
        "message.send" => c
            .arg(positional("to", 1, true).help("A registered recipient, or floor with --work-action and --addressee"))
            .arg(positional("body", 2, true))
            .arg(value("kind").default_value("note").value_parser([
                "note", "task", "question", "answer", "blocker", "done", "handoff", "finding",
            ]))
            .arg(Arg::new("refs").long("ref").action(ArgAction::Append))
            .arg(value("reply_to").long("reply-to"))
            .arg(value("work_action").long("work-action").value_parser(["admit","assign","return","question","ruling_request","ruling","finding","notify"]))
            .arg(Arg::new("addressees").long("addressee").action(ArgAction::Append)),
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
        "message.inbox" => c
            .arg(positional("agent", 1, false))
            .arg(toggle("full"))
            .arg(value("limit").default_value("20"))
            .arg(value("preview_chars").long("preview-chars"))
            .arg(value("cursor")),
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
        "decision.list" => c
            .arg(value("id"))
            .arg(toggle("pending"))
            .arg(toggle("history"))
            .arg(value("limit").default_value("20"))
            .arg(value("cursor")),
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
    if path.len() == 1 && matches!(path[0].as_str(), "decision" | "pending") {
        return Ok(&DecisionList::META);
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
        .ok_or_else(|| {
            unknown(
                &path
                    .iter()
                    .map(|part| diagnostic_word(part))
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        })
}
fn number(m: &ArgMatches, id: &str) -> Result<u16> {
    required(m, id)?
        .parse()
        .map_err(|_| SeError::invalid(id, "a bounded positive integer"))
}
