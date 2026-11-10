//! Clap consumes the operation catalogue; no filesystem or ambient configuration is read here.
use super::*;
mod remote;
use crate::registry::{CliExposure, Scope};
use clap::{Arg, ArgAction, ArgMatches, Command};
use remote::command as remote_command;
pub use remote::parse_remote_target;
use se_types::{Cursor, Detail, IdempotencyKey, Result, SeError, details};
use std::path::PathBuf;

mod agent_command;
mod atlas;
pub use agent_command::AgentCommand;
mod decode;
mod help;
mod reopen;
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
                resume_agent: text(m, "agent"),
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
                        serde_json::from_value(serde_json::Value::String(value)).map_err(|_| {
                            SeError::invalid("provider", "claude, codex, secode or acp")
                        })
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
        .arg(
            Arg::new("version")
                .long("version")
                .short('V')
                .action(ArgAction::SetTrue)
                .help("Show the installed se version and exit")
                .global(true),
        )
        .arg(
            Arg::new("help")
                .long("help")
                .short('h')
                .action(ArgAction::SetTrue)
                .help("Show help for this command and exit")
                .global(true),
        )
        .arg(
            value("home")
                .help("Data home directory for this StateEngine installation")
                .global(true),
        )
        .arg(
            value("project")
                .short('p')
                .help("Saved project name or ID")
                .global(true),
        )
        .arg(
            toggle("json")
                .help("Print structured JSON instead of the default readable output")
                .global(true),
        )
        .arg(
            toggle("quiet")
                .short('q')
                .help("Suppress informational output; refusals still print")
                .global(true),
        )
        .arg(
            Arg::new("no_color")
                .long("no-color")
                .action(ArgAction::SetTrue)
                .help("Disable color in the plain rendering")
                .global(true),
        )
        .arg(
            value("key")
                .help("Request key: reuse it to repeat the same change; use a new key for a different change")
                .global(true),
        );
    for meta in CATALOGUE {
        if let CliExposure::Leaf { path, hidden, .. } = meta.cli {
            root = insert(root, path, meta.name, hidden);
        }
    }
    root = root
        .mut_subcommand("decision", |command| {
            let command = input_command("decision.list", command)
                .visible_alias("decisions")
                .args_conflicts_with_subcommands(true);
            match help::group("decision") {
                Some(summary) => command.about(summary),
                None => command,
            }
        })
        .subcommand(
            input_command(
                "decision.list",
                Command::new("pending")
                    .disable_help_flag(true)
                    .disable_version_flag(true)
                    .disable_help_subcommand(true),
            )
            .mut_arg("pending", |arg| arg.default_value("true"))
            .about("List decisions awaiting an outcome"),
        );
    // MCP is a streaming transport for the registered operations, not another
    // store operation with a fabricated product output family.
    root.subcommand(
        Command::new("mcp")
            .about("Serve session tools over newline-delimited JSON-RPC on stdin/stdout")
            .disable_help_flag(true)
            .disable_version_flag(true)
            .disable_help_subcommand(true)
            .arg(toggle("stdio").help("Read JSON-RPC on stdin and write replies on stdout")),
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
        let mut child = Command::new(*head)
            .hide(hidden)
            .disable_help_flag(true)
            .disable_version_flag(true)
            .disable_help_subcommand(true);
        if let Some(summary) = help::group(head) {
            child = child.about(summary);
        }
        command.subcommand(update(child))
    }
}
fn input_command(name: &str, c: Command) -> Command {
    let c = match name {
        name if name.starts_with("atlas.") => atlas::command(name, c),
        "remote.list" | "remote.watch" | "remote.send" | "client.watch" => remote_command(name, c),
        "meta.help" => c
            .arg(
                Arg::new("path")
                    .num_args(0..)
                    .action(ArgAction::Append)
                    .help("Command words to explain, e.g. help msg send; omit them for the full catalogue"),
            )
            .arg(toggle("all").help("Also show hidden commands")),
        "meta.schema" => c.arg(
            positional("op", 1, false)
                .help("Exact registered operation name, e.g. project.status; omit it for the full catalogue"),
        ),
        "project.init" => c
            .arg(value("repo").help("Existing repository folder to register as this project"))
            .arg(value("name").help("Project name shown in status and listings"))
            .arg(value("agent").default_value("main").help("Name for your first saved agent"))
            .arg(
                value("provider")
                    .value_parser(["claude", "codex", "secode", "acp"])
                    .help("Provider for the first agent: claude, codex, secode or acp"),
            )
            .arg(value("model").help("Model for the first agent"))
            .arg(toggle("launch").hide(true))
            .arg(toggle("adopt").hide(true)),
        "project.move" => c.arg(
            positional("root", 1, true)
                .help("The folder the repository now lives in; verified against the git identity recorded at se init"),
        ),
        "doctor.repair" => c.arg(value("fix").help("Apply only this currently diagnosed CHECK-ID after printing its plan")),
        "store.import_node" => c
            .arg(value("from_node").long("from-node").required(true).help("Copy of an earlier StateEngine data directory to import"))
            .arg(value("source_owner").long("source-owner").help("Source human ID explicitly adopted as the importing owner"))
            .arg(value("map_human").long("map-human").action(ArgAction::Append).help("Historical human ID=existing target human ID; repeat for each explicit correspondence")),
        "project.status" => c.arg(toggle("all").help("Also summarize every registered project, with its owner-mail counts")),
        "agent.launch" => c
            .arg(positional("agent", 1, true).help("Saved agent name or ID to start or resume"))
            .arg(toggle("new").help("Start a fresh provider conversation instead of resuming the saved one"))
            .arg(value("provider").help("Override the saved provider for this launch: claude, codex, secode or acp"))
            .arg(value("model").help("Override the saved model for this launch"))
            .arg(value("task").help("Task text handed to the agent for this launch"))
            .arg(toggle("detach").help("Run headless instead of in a window"))
            .arg(toggle("override_live").long("force").alias("override-live").help("Stop the existing agent sessions and their scoped jobs before relaunching; a terminal asks for confirmation")),
        "agent.stop" => c
            .arg(positional("agent", 1, false).conflicts_with("all").help("Saved agent name or ID to stop"))
            .arg(toggle("all").conflicts_with("release").help("Stop every running agent in this project"))
            .arg(toggle("release").help("Also release the stopped agent's reserved resources; one target only")),
        "continuity.resume" => c
            .arg(positional("agent", 1, false).conflicts_with("preview").help("Show the launch command that reopens this agent's saved conversation"))
            .arg(value("since").value_parser(clap::builder::StringValueParser::new()).help("An opaque cursor from resume for this same agent"))
            .arg(value("budget").default_value("4096").help("Maximum UTF-8 bytes in the JSON reply (1024..1048576)"))
            .arg(value("limit").default_value("20").help("Maximum recent turns and governing decisions per section (1..100)"))
            .arg(value("governing_cursor").long("governing-cursor").help("Continue project rulings from decisions.next_cursor"))
            .arg(value("preview").help("Owner: inspect this saved agent without binding or acknowledging it")),
        "session.context" => c
            .arg(value("since").help("An opaque cursor from context for this same agent"))
            .arg(value("budget").default_value("32768").help("Maximum UTF-8 bytes in the context reply"))
            .arg(value("governing_cursor").long("governing-cursor").help("Continue project rulings from the previous context page"))
            .arg(value("limit").default_value("20").help("Maximum recent entries per context section")),
        "project.remove" => c
            .arg(toggle("all").conflicts_with("project").help("Remove every registered project in this home"))
            .arg(toggle("keep-integrations").help("Keep registered integrations while removing the project")),
        "history.event_read" => c.arg(
            value("event")
                .conflicts_with_all(["agent", "session", "kind", "since", "limit", "cursor"])
                .help("One committed event ID from se history"),
        ),
        "history.list" => c
            .arg(value("agent").help("Saved agent name or ID to filter on"))
            .arg(value("session").help("Session ID to filter on"))
            .arg(value("kind").action(ArgAction::Append).help("Event kind to include; repeat for several"))
            .arg(
                value("since")
                    .help("An event position from se history, scoped to this caller and project"),
            )
            .arg(value("limit").default_value("20").help("Maximum events in this page"))
            .arg(value("cursor").help("Cursor from a previous page of this same read")),
        "message.read" => c
            .arg(positional("msg_id", 1, true).help("Message ID from se msg list or inbox"))
            .arg(value("budget").default_value("262144").help("Maximum serialized reply bytes, checked before marking read")),
        "message.ack" | "message.dismiss" => c
            .arg(positional("msg_id", 1, true).help("Message ID from se msg list or inbox")),
        "message.send" => c
            .arg(positional("to", 1, true).help("Registered recipient name or ID, the owner, or floor (shared project messages) with --work-action and --addressee"))
            .arg(positional("body", 2, true).help("Message text; - reads it from stdin"))
            .arg(toggle("no_wake").long("no-wake").help("Keep this note unread in the inbox without notifying recipients"))
            .arg(value("kind").default_value("note").value_parser([
                "note", "task", "question", "answer", "blocker", "done", "handoff", "finding",
            ]).help("Message kind: note, task, question, answer, blocker, done, handoff or finding"))
            .arg(Arg::new("refs").long("ref").action(ArgAction::Append).help("Message ID this one references; repeat for each"))
            .arg(value("reply_to").long("reply-to").help("Message ID this one directly answers"))
            .arg(value("work_action").long("work-action").value_parser(["admit","assign","return","question","ruling_request","ruling","finding","notify"]).help("For floor: what the message does: admit, assign, return, question, ruling_request, ruling, finding or notify"))
            .arg(Arg::new("addressees").long("addressee").action(ArgAction::Append).help("Explicit floor addressee; repeat for each")),
        "message.list" => c
            .arg(value("to").help("Only messages to this recipient"))
            .arg(value("from").help("Only messages from this sender"))
            .arg(value("kind").value_parser([
                "note", "task", "question", "answer", "blocker", "done", "handoff", "finding",
            ]).help("Only messages of this kind"))
            .arg(toggle("all").help("Include read messages, not only unread"))
            .arg(toggle("full").help("Return complete bodies instead of previews"))
            .arg(value("limit").default_value("20").help("Maximum messages in this page"))
            .arg(value("preview_chars").long("preview-chars").help("Maximum body preview characters when the full body is not requested"))
            .arg(value("cursor").help("Cursor from a previous page of this same read"))
            .arg(
                value("box")
                    .value_parser(["inbox", "sent"])
                    .default_value("inbox")
                    .help("inbox or sent"),
            ),
        "message.inbox" => c
            .arg(positional("agent", 1, false).help("Saved agent name or ID whose unread inbox the owner lists; omit it for your own"))
            .arg(toggle("full").help("Return complete bodies instead of previews"))
            .arg(value("limit").default_value("20").help("Maximum messages in this page"))
            .arg(value("preview_chars").long("preview-chars").help("Maximum body preview characters"))
            .arg(value("cursor").help("Cursor from a previous page of this same read")),
        "working_state.get" => c.arg(value("agent").help("Saved agent name or ID whose working state the owner reads")),
        "agent.show" => c.arg(positional("agent", 1, true).help("Saved agent name or ID to inspect")),
        "agent.list" => c
            .arg(value("limit").default_value("20").help("Maximum agents in this page"))
            .arg(value("cursor").help("Cursor from a previous page of this same read")),
        "config.get" => c
            .arg(positional("setting_key", 1, true).help("Saved agent setting: agent.<AGENT>.model, agent.<AGENT>.profile or agent.<AGENT>.can-create; example: se config get agent.main.model"))
            .arg(toggle("origin").help("Report where the value comes from")),
        "config.list" => c
            .arg(toggle("origin").help("Report where the settings come from"))
            .arg(value("limit").default_value("100").help("Maximum settings rows in this page"))
            .arg(value("cursor").help("Cursor from a previous page of this same read")),
        "config.set" => {
            c.arg(positional("setting_key", 1, true).help("Saved agent setting: agent.<AGENT>.model, agent.<AGENT>.profile or agent.<AGENT>.can-create. Edit permission profiles directly in your state home's config.toml."))
                .arg(positional("setting_value", 2, true).help("Model string or null for the default, an existing named permission profile, or true/false for can-create"))
        }
        "agent.create" => c
            .arg(positional("name", 1, true).help("Name for the new saved agent"))
            .arg(value("provider").value_parser(["claude", "codex", "secode", "acp"]).help("Provider for the new agent: claude, codex, secode or acp"))
            .arg(value("model").help("Model for the new agent")),
        "agent.rename" => c
            .arg(positional("agent", 1, true).help("Saved agent name or ID to rename"))
            .arg(positional("name", 2, true).help("New display name for the saved agent")),
        "decision.list" => c
            .arg(value("id").help("One decision ID"))
            .arg(toggle("pending").help("Only proposals awaiting an owner outcome"))
            .arg(toggle("history").help("Include retired decisions"))
            .arg(value("limit").default_value("20").help("Maximum decisions in this page"))
            .arg(value("cursor").help("Cursor from a previous page of this same read")),
        "decision.show" => c.arg(positional("decision_id", 1, true).help("Decision ID from se decision list")),
        "decision.propose" => c
            .arg(positional("decision_key", 1, true).help("Stable key naming this decision topic"))
            .arg(positional("statement", 2, true).help("The statement to propose"))
            .arg(value("rationale").help("Supporting reason for the proposal"))
            .arg(value("supersedes").help("Decision ID this proposal replaces")),
        "decision.ratify" => c
            .arg(positional("decision_id", 1, true).help("Decision ID from se decision list"))
            .arg(value("expect").help("Expected revision from se decision show")),
        "decision.reject" | "decision.retract" => c
            .arg(positional("decision_id", 1, true).help("Decision ID from se decision list"))
            .arg(value("reason").required(true).help("Why, recorded with the decision"))
            .arg(value("expect").help("Expected revision from se decision show")),
        "decision.supersede" => c
            .arg(positional("decision_id", 1, true).help("Decision ID to supersede"))
            .arg(positional("replacement_id", 2, true).help("New decision ID replacing it"))
            .arg(value("expect").help("Expected revision from se decision show")),
        "working_state.set" => c
            .arg(positional("text", 1, true).help("The new working-state text; - reads it from stdin"))
            .arg(value("expect").required(true).help("The revision you last read, or absent for the first write"))
            .arg(value("agent").help("Saved agent name or ID whose working state the owner replaces")),
        "runtime.up" => c.arg(toggle("foreground").help("Run the runtime in this terminal instead of detaching")),
        "hook.claude" => c.arg(positional("event", 1, true).help("Claude Code lifecycle event carried on stdin").value_parser([
            "session-start",
            "prompt",
            "stop",
            "stop-failure",
        ])),
        _ => c,
    };
    if let Some(summary) = help::command(name) {
        c.about(summary)
    } else {
        c
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
    if path.len() == 1 && path[0] == "atlas" {
        return Ok(&MetaHelp::META);
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
