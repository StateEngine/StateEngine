//! Clap consumes the operation catalogue; no filesystem or ambient configuration is read here.
mod remote;
use clap::{Arg, ArgAction, ArgMatches, Command};
use remote::command as remote_command;
pub use remote::parse_remote_target;
use se_core::ops::*;
use se_core::registry::{CliExposure, Scope, Selector};
use se_types::{Cursor, Detail, IdempotencyKey, Result, SeError, details};
use std::path::PathBuf;

mod atlas;
mod decode;
mod help;
pub use decode::{from_matches, from_matches_with_key};

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
            "agent.wake" => CliSelections {
                agent: text(m, "agent"),
                ..CliSelections::default()
            },
            "project.remove" => CliSelections {
                control_all: flag(m, "all"),
                ..CliSelections::default()
            },
            "message.list" => CliSelections {
                mail_to: text(m, "to"),
                mail_list: true,
                mail_follow: flag(m, "follow"),
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
fn unknown(command: &str) -> SeError {
    SeError::new(Detail::UsageUnknownCommand(details::UsageUnknownCommand {
        got: diagnostic_word(command).into(),
        suggestion: None,
    }))
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
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn input_command(name: &str, c: Command) -> Command {
    let c = match name {
        name if name.starts_with("atlas.") => atlas::command(name, c),
        "remote.list" | "remote.watch" | "remote.send" | "remote.launch" | "client.watch" => remote_command(name, c),
        "meta.help" => c
            .arg(
                Arg::new("path")
                    .num_args(0..)
                    .action(ArgAction::Append)
                    .help("Command words to explain, e.g. help msg send; omit them for the full catalogue"),
            )
            .arg(toggle("all").help("Also show hidden commands")),
        "meta.guide" => c.arg(positional("topic", 1, false).help("Exact topic name from se guide; omit to list names and short summaries")),
        "meta.schema" => c.arg(
            positional("op", 1, false)
                .help("Exact registered operation name, e.g. project.status; omit it for the full catalogue"),
        ),
        "project.init" => c
            .arg(value("harness").help("Choose claude, codex, secode, qwen-code, goose, hermes or a configured protocol harness"))
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
            .arg(toggle("adopt").help("Capture sessions started directly in Claude Code or Codex")),
        "project.move" => c.arg(
            positional("root", 1, true)
                .help("The folder the repository now lives in; verified against the git identity recorded at se init"),
        ),
        "doctor.repair" => c.arg(value("fix").help("Apply only this currently diagnosed CHECK-ID after printing its plan")),
        #[cfg(feature = "import")]
        "store.import_node" => c
            .arg(value("from_node").long("from-node").required(true).help("Copy of an earlier StateEngine data directory to import"))
            .arg(value("source_owner").long("source-owner").help("Source human ID explicitly adopted as the importing owner"))
            .arg(value("map_human").long("map-human").action(ArgAction::Append).help("Historical human ID=existing target human ID; repeat for each explicit correspondence")),
        "assignment.write" => c.arg(value("action").required(true)).arg(value("assignee")).arg(value("assignment")).arg(value("body").required(true)),
        "assignment.list" => c.arg(value("limit").default_value("20")).arg(value("cursor")),
        "captain.set" => c.arg(positional("captain", 1, true).help("Registered agent name or ID, or me")),
        "project.status" => c.arg(toggle("all").help("Also summarize every registered project, with its owner-mail counts"))
            .arg(toggle("fresh").help("Scan the working tree now instead of using watched status")),
        "agent.launch" => c
            .arg(positional("agent", 1, true).help("Saved agent name or ID to start in a fresh conversation"))
            .arg(value("resume").num_args(0..=1).default_missing_value("latest").value_name("SESSION").help("Reopen the latest saved conversation, or the one identified by SESSION"))
            .arg(value("provider").help("Override the saved provider for this launch: claude, codex, secode or acp"))
            .arg(value("model").help("Override the saved model for this launch"))
            .arg(value("task").help("Task text handed to the agent for this launch"))
            .arg(toggle("detach").help("Run headless instead of in a window"))
            .arg(toggle("override_live").long("force").alias("override-live").help("Stop the existing agent sessions and their scoped jobs before relaunching; a terminal asks for confirmation")),
        "agent.stop" => c
            .arg(positional("agent", 1, false).conflicts_with("all").help("Saved agent name or ID to stop"))
            .arg(toggle("all").conflicts_with("release").help("Stop every running agent in this project"))
            .arg(toggle("release").help("Also release the stopped agent's reserved resources; one target only")),
        "agent.wake" => c.arg(
            positional("agent", 1, true).help("Running saved agent whose pending mail to offer"),
        ),
        "continuity.resume" => c
            .arg(positional("agent", 1, false).conflicts_with("preview").help("Show the launch command that reopens this agent's saved conversation"))
            .arg(value("since").value_parser(clap::builder::StringValueParser::new()).help("An opaque cursor from resume for this same agent"))
            .arg(value("budget").default_value("4096").help("Maximum UTF-8 bytes in the JSON reply (1024..1048576)"))
            .arg(value("limit").default_value("20").help("Maximum recent turns per section (1..100)"))
            .arg(value("preview").help("Owner: inspect this saved agent without binding or acknowledging it")),
        "session.context" => c
            .arg(value("since").help("An opaque cursor from context for this same agent"))
            .arg(value("budget").default_value("32768").help("Maximum UTF-8 bytes in the context reply"))
            .arg(value("limit").default_value("20").help("Maximum recent entries per context section")),
        "store.forget" => c
            .arg(value("event").long("event").action(ArgAction::Append).required(true).help("Message or captured-turn event ID to forget; repeat for several from one project"))
            .arg(toggle("yes").help("Erase after reviewing the printed plan; without it nothing is erased")),
        "project.remove" => c
            .arg(toggle("all").conflicts_with("project").help("Remove every registered project in this home"))
            .arg(toggle("keep-integrations").help("Keep registered integrations while removing the project")),
        "history.event_read" => c.arg(
            value("event")
                .conflicts_with_all(["agent", "session", "kind", "position", "limit", "cursor"])
                .help("One committed event ID from se history"),
        ),
        "history.list" => c
            .arg(value("agent").help("Saved agent name or ID to filter on"))
            .arg(value("session").help("Session ID to filter on"))
            .arg(value("kind").action(ArgAction::Append).help("Event kind to include; repeat for several"))
            .arg(
                value("position")
                    .help("An opaque history position cursor, the position value from se history --event, scoped to this caller and project; not a time"),
            )
            .arg(value("limit").default_value("20").help("Maximum events in this page"))
            .arg(value("cursor").help("Cursor from a previous page of this same read"))
            .arg(toggle("newest").help("Read the page newest-first; the cursor continues toward the oldest event")),
        "message.read" => c
            .arg(positional("msg_id", 1, true).help("Message ID from se msg list or inbox"))
            .arg(value("budget").default_value("262144").help("Maximum serialized reply bytes, checked before marking read")),
        "message.ack" | "message.dismiss" => c
            .arg(positional("msg_id", 1, true).help("Message ID from se msg list or inbox")),
        "message.send" => c
            .arg(positional("to", 1, false).help("Recipient, or omit for a crew question, blocker, or done report"))
            .arg(positional("body", 2, false).help("Message text; - reads it from stdin"))
            .arg(toggle("no_wake").long("no-wake").help("Keep this note unread in the inbox without notifying recipients"))
            .arg(value("kind").default_value("note").value_parser([
                "note", "task", "question", "answer", "blocker", "done", "handoff", "finding",
            ]).help("Message kind: note, task, question, answer, blocker, done, handoff or finding"))
            .arg(Arg::new("refs").long("ref").action(ArgAction::Append).help("Message ID this one references; repeat for each"))
            .arg(value("reply_to").long("reply-to").help("Message ID this one directly answers"))
            .arg(value("supersedes").help("ID of an earlier direct message from you to the same recipient that this one replaces; it stops being active unread work and stays in history"))
            .arg(value("work_action").long("work-action").value_parser(["admit","assign","return","question","ruling_request","ruling","finding","notify"]).help("For floor: what the message does: admit, assign, return, question, ruling_request, ruling, finding or notify"))
            .arg(Arg::new("addressees").long("addressee").action(ArgAction::Append).help("Explicit floor addressee; repeat for each")),
        "message.list" => c
            .arg(toggle("follow").help("Stream your own inbox over one connection; resume with the last printed cursor"))
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
            .arg(toggle("newest").help("Read the page newest-first; the cursor continues toward the oldest message"))
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
            .arg(positional("setting_key", 1, true).help("Saved agent setting: agent.<AGENT>.model, .profile, .can-create, .model_provider, .base_url, .wire_api, .reasoning_effort or .context_window"))
            .arg(toggle("origin").help("Report where the value comes from")),
        "config.list" => c
            .arg(toggle("origin").help("Report where the settings come from"))
            .arg(value("limit").default_value("100").help("Maximum settings rows in this page"))
            .arg(value("cursor").help("Cursor from a previous page of this same read")),
        "config.set" => {
            c.arg(positional("setting_key", 1, true).help("Saved agent setting: agent.<AGENT>.model, agent.<AGENT>.profile, .can-create, .model_provider, .base_url, .wire_api, .reasoning_effort or .context_window. Edit permission profiles directly in your state home's config.toml."))
                .arg(positional("setting_value", 2, true).help("Model/provider/endpoint/effort string, positive context token count, null to inherit, an existing permission profile, or true/false for can-create"))
        }
        "agent.create" => c
            .arg(value("harness").help("Choose claude, codex, secode or a configured protocol harness"))
            .arg(positional("name", 1, true).help("Name for the new saved agent"))
            .arg(value("provider").value_parser(["claude", "codex", "secode", "acp"]).help("Provider for the new agent: claude, codex, secode or acp"))
            .arg(value("model").help("Model for the new agent"))
            .arg(value("model-provider").help("Per-agent Codex model provider name"))
            .arg(value("base-url").help("Non-secret provider endpoint; requires --model-provider"))
            .arg(value("wire-api").help("Provider wire protocol: responses"))
            .arg(value("reasoning-effort").help("Per-agent reasoning effort"))
            .arg(value("context-window").help("Per-agent positive token count")),
        "agent.rename" => c
            .arg(positional("agent", 1, true).help("Saved agent name or ID to rename"))
            .arg(positional("name", 2, true).help("New display name for the saved agent")),

        "working_state.set" => c
            .arg(positional("text", 1, true).help("The new working-state text; - reads it from stdin"))
            .arg(value("expect").required(true).help("The revision you last read, or absent for the first write"))
            .arg(value("agent").help("Saved agent name or ID whose working state the owner replaces")),
        "runtime.up" => c.arg(toggle("foreground").help("Run the runtime in this terminal instead of detaching")),
        "installation.uninstall" => c.arg(toggle("yes").help("Confirm unattended removal; OS ownership and agent ancestry checks still apply")),
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
pub fn selected_meta(matches: &ArgMatches) -> Result<&'static se_core::registry::OpMeta> {
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
    let same_path = |meta: &se_core::registry::OpMeta| {
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
