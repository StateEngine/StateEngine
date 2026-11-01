//! Clap consumes the operation catalogue; no filesystem or ambient configuration is read here.
use super::*;
use crate::{
    commit::{AbsentRevision, ExpectedRevision},
    registry::{CliExposure, Scope},
};
use clap::{Arg, ArgAction, ArgMatches, Command};
use se_types::{Cursor, Detail, IdempotencyKey, Result, SeError, details};
use std::path::PathBuf;

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
/// Authenticated CLI routing metadata, separate from model-facing operation DTOs.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CliSelections {
    /// Resolved from CLI project policy before forwarding; never an authority.
    /// The host must select/check this scope before opening an admitted snapshot.
    pub project: Option<se_types::ProjectId>,
    pub agent: Option<String>,
    pub mail_to: Option<String>,
    pub mail_list: bool,
    pub status_all: bool,
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
            "working_state.get" | "working_state.set" | "agent.show" => CliSelections {
                agent: text(m, "agent"),
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
    root
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
        "history.event_read" => c.arg(value("event").required(true)),
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
    CATALOGUE.iter().copied().find(|meta|matches!(meta.cli,CliExposure::Leaf{path:p,..} if p.iter().copied().eq(path.iter().map(String::as_str))))
        .ok_or_else(||unknown(&path.join(" ")))
}
pub fn from_matches(matches: &ArgMatches) -> Result<AnyOp> {
    from_matches_with_key(matches, None)
}
pub fn from_matches_with_key(
    matches: &ArgMatches,
    generated: Option<IdempotencyKey>,
) -> Result<AnyOp> {
    let (path, m) = deepest(matches);
    let meta = selected_meta(matches)?;
    let common = CommonArgs::from_matches(matches)?;
    if meta.scope == Scope::None && common.home.is_some() {
        return Err(unknown_flag(
            "--home",
            meta.name,
            "metadata does not select a state home",
        ));
    }
    if !matches!(
        meta.scope,
        Scope::Project | Scope::ProjectOrAll | Scope::Session
    ) && common.project.is_some()
    {
        return Err(unknown_flag(
            "--project",
            meta.name,
            "this operation has no project selector",
        ));
    }
    if !meta.mutates() && common.key.is_some() {
        return Err(unknown_flag(
            "--key",
            meta.name,
            "read-only calls do not accept a mutation key",
        ));
    }
    if meta.name == "hook.claude" && (common.key.is_some() || common.project.is_some()) {
        return Err(SeError::invalid(
            "hook flags",
            "bound session project and the existing natural capture identity; no --project or --key; --json selects the explicit receipt",
        ));
    }
    if meta.name == "meta.version"
        && (!path.is_empty() || common.quiet || common.no_color || flag(m, "help"))
    {
        return Err(SeError::invalid(
            "--version",
            "only --json alongside the version flag",
        ));
    }
    let key = || {
        common
            .key
            .clone()
            .or_else(|| generated.clone())
            .ok_or_else(|| {
                SeError::new(Detail::UsageMissingArgument(
                    details::UsageMissingArgument {
                        command: meta.name.into(),
                        argument:
                            "request identity generated before first send (or --key for retry)"
                                .into(),
                    },
                ))
            })
    };
    let op =
        match meta.name {
            "agent.show" => AnyOp::AgentShow(AgentShow {
                target_agent_id: None,
            }),
            "config.get" => AnyOp::ConfigGet(ConfigGet {
                key: required(m, "setting_key")?,
                origin: flag(m, "origin"),
            }),
            "config.set" => AnyOp::ConfigSet(ConfigSet {
                key: required(m, "setting_key")?,
                value: required(m, "setting_value")?,
                idempotency_key: key()?,
            }),
            "meta.version" => AnyOp::MetaVersion(MetaVersion {}),
            "meta.help" => AnyOp::MetaHelp(MetaHelp {
                path: if flag(m, "help") {
                    path
                } else {
                    many(m, "path")
                },
                all: if flag(m, "help") {
                    false
                } else {
                    flag(m, "all")
                },
            }),
            "meta.schema" => AnyOp::MetaSchema(MetaSchema { op: text(m, "op") }),
            "project.status" => AnyOp::ProjectStatus(ProjectStatus {
                all: if path.is_empty() {
                    false
                } else {
                    flag(m, "all")
                },
            }),
            "hook.claude" => AnyOp::HookClaude(HookClaude {
                event: serde_json::from_value(serde_json::Value::String(required(m, "event")?))
                    .map_err(|_| SeError::invalid("event", "a fixed Claude hook event"))?,
            }),
            "project.init" => AnyOp::ProjectInit(ProjectInit {
                repo: text(m, "repo"),
                name: text(m, "name"),
                agent: required(m, "agent")?,
                provider: text(m, "provider")
                    .map(|v| {
                        serde_json::from_value(serde_json::Value::String(v))
                            .map_err(|_| SeError::invalid("provider", "claude or codex"))
                    })
                    .transpose()?,
                model: text(m, "model"),
                launch: flag(m, "launch"),
                adopt: flag(m, "adopt"),
                idempotency_key: key()?,
            }),
            "history.event_read" => AnyOp::EventRead(EventRead {
                event_id: required(m, "event")?,
            }),
            "message.send" => AnyOp::MessageSend(MessageSend {
                to: required(m, "to")?,
                body: required(m, "body")?,
                kind: serde_json::from_value(serde_json::Value::String(required(m, "kind")?))
                    .map_err(|_| SeError::invalid("kind", "a registered message kind"))?,
                refs: many(m, "refs"),
                reply_to: text(m, "reply_to")
                    .map(se_types::MessageId::from_legacy)
                    .transpose()?,
                idempotency_key: key()?,
            }),
            "message.list" => AnyOp::MessageList(MessageList {
                cli_list: true,
                view: if flag(m, "all") {
                    MessageView::All
                } else {
                    MessageView::Unread
                },
                mailbox: if text(m, "box").as_deref() == Some("sent") {
                    MessageBox::Sent
                } else {
                    MessageBox::Inbox
                },
                from: text(m, "from"),
                kind: text(m, "kind")
                    .map(|v| {
                        serde_json::from_value(serde_json::Value::String(v))
                            .map_err(|_| SeError::invalid("kind", "a registered message kind"))
                    })
                    .transpose()?,
                full: flag(m, "full"),
                limit: number(m, "limit")?,
                preview_chars: text(m, "preview_chars")
                    .map(|v| {
                        v.parse()
                            .map_err(|_| SeError::invalid("preview-chars", "0..4000"))
                    })
                    .transpose()?,
                cursor: text(m, "cursor").map(Cursor::new).transpose()?,
                owner_to: text(m, "to"),
            }),
            "working_state.get" => AnyOp::WorkingStateGet(WorkingStateGet { owner_agent: None }),
            "agent.create" => AnyOp::AgentCreate(AgentCreate {
                name: required(m, "name")?,
                provider: text(m, "provider")
                    .map(|value| {
                        serde_json::from_value(serde_json::Value::String(value))
                            .map_err(|_| SeError::invalid("provider", "claude or codex"))
                    })
                    .transpose()?,
                model: text(m, "model"),
                idempotency_key: key()?,
            }),
            "decision.show" => AnyOp::DecisionShow(DecisionShow {
                decision_id: required(m, "decision_id")?,
            }),
            "decision.propose" => AnyOp::DecisionPropose(DecisionPropose {
                key: required(m, "decision_key")?,
                statement: required(m, "statement")?,
                rationale: text(m, "rationale"),
                supersedes: text(m, "supersedes")
                    .map(se_types::DecisionId::from_legacy)
                    .transpose()?,
                idempotency_key: key()?,
            }),
            "decision.ratify" => AnyOp::DecisionRatify(DecisionRatify {
                decision_id: se_types::DecisionId::from_legacy(required(m, "decision_id")?)?,
                expect: text(m, "expect")
                    .map(|value| {
                        value
                            .parse()
                            .map_err(|_| SeError::invalid("expect", "positive entity revision"))
                    })
                    .transpose()?,
                idempotency_key: key()?,
            }),
            "decision.reject" => AnyOp::DecisionReject(DecisionReject {
                decision_id: se_types::DecisionId::from_legacy(required(m, "decision_id")?)?,
                reason: required(m, "reason")?,
                expect: text(m, "expect")
                    .map(|value| {
                        value
                            .parse()
                            .map_err(|_| SeError::invalid("expect", "positive entity revision"))
                    })
                    .transpose()?,
                idempotency_key: key()?,
            }),
            "decision.retract" => AnyOp::DecisionRetract(DecisionRetract {
                decision_id: se_types::DecisionId::from_legacy(required(m, "decision_id")?)?,
                reason: required(m, "reason")?,
                expect: text(m, "expect")
                    .map(|value| {
                        value
                            .parse()
                            .map_err(|_| SeError::invalid("expect", "positive entity revision"))
                    })
                    .transpose()?,
                idempotency_key: key()?,
            }),
            "decision.supersede" => AnyOp::DecisionSupersede(DecisionSupersede {
                decision_id: se_types::DecisionId::from_legacy(required(m, "decision_id")?)?,
                replacement_id: se_types::DecisionId::from_legacy(required(m, "replacement_id")?)?,
                expect: text(m, "expect")
                    .map(|value| {
                        value
                            .parse()
                            .map_err(|_| SeError::invalid("expect", "positive entity revision"))
                    })
                    .transpose()?,
                replacement_expect: None,
                idempotency_key: key()?,
            }),
            "working_state.set" => {
                let expect = required(m, "expect")?;
                AnyOp::WorkingStateSet(WorkingStateSet {
                    text: required(m, "text")?,
                    expect: if expect == "absent" {
                        ExpectedRevision::Absent(AbsentRevision::Absent)
                    } else {
                        ExpectedRevision::Revision(expect.parse().map_err(|_| {
                            SeError::invalid("expect", "positive revision or absent")
                        })?)
                    },
                    idempotency_key: key()?,
                    owner_agent: None,
                })
            }
            "runtime.up" => AnyOp::RuntimeUp(RuntimeUp {
                foreground: flag(m, "foreground"),
                idempotency_key: key()?,
            }),
            "runtime.down" => AnyOp::RuntimeDown(RuntimeDown {
                idempotency_key: key()?,
            }),
            "installation.uninstall" => AnyOp::Uninstall(Uninstall {
                idempotency_key: key()?,
            }),
            _ => return Err(unknown(meta.name)),
        };
    Ok(op)
}
fn number(m: &ArgMatches, id: &str) -> Result<u16> {
    required(m, id)?
        .parse()
        .map_err(|_| SeError::invalid(id, "a bounded positive integer"))
}

impl CliSelections {
    pub fn validate(&self) -> Result<()> {
        for (name, selector) in [("agent", &self.agent), ("to", &self.mail_to)] {
            if let Some(selector) = selector {
                bounded(name, selector, 512, false)?;
            }
        }
        if self.status_all && self.project.is_some() {
            return Err(SeError::invalid(
                "--all",
                "no simultaneous project selector",
            ));
        }
        Ok(())
    }
    /// Called only by the authenticated CLI route inside its admitted finite read.
    /// The same metadata crosses IPC separately; MCP arguments never carry it.
    pub fn apply<R: se_store::Snapshot>(
        &self,
        op: &mut AnyOp,
        cx: &mut crate::commit::Cx<'_, R>,
    ) -> Result<()> {
        self.validate()?;
        if let Some(project) = &self.project
            && cx.admission.scope != se_store::Scope::Project(project.clone())
        {
            return Err(SeError::invalid(
                "CLI project routing",
                "the resolved project must match the verified admission scope before reading",
            ));
        }
        if self.status_all {
            match op {
                AnyOp::ProjectStatus(input) => input.all = true,
                _ => {
                    return Err(unknown_flag(
                        "--all",
                        op.meta().name,
                        "only status accepts all-project routing",
                    ));
                }
            }
        }
        if let Some(selector) = &self.agent {
            if !matches!(
                op,
                AnyOp::WorkingStateGet(_) | AnyOp::WorkingStateSet(_) | AnyOp::AgentShow(_)
            ) {
                return Err(unknown_flag(
                    "--agent",
                    op.meta().name,
                    "this operation has no agent selector",
                ));
            }
            let actor = crate::scope::actor_selector(cx.read, selector)?;
            let se_store::Actor::Agent(agent) = actor else {
                return Err(SeError::invalid("agent", "a project agent, not the owner"));
            };
            crate::scope::working_agent(cx.admission, Some(&agent), op.meta().name)?;
            match op {
                AnyOp::AgentShow(input) => input.target_agent_id = Some(agent),
                AnyOp::WorkingStateGet(input) => input.owner_agent = Some(agent),
                AnyOp::WorkingStateSet(input) => input.owner_agent = Some(agent),
                _ => (),
            }
        }
        if self.mail_list || self.mail_to.is_some() {
            match op {
                AnyOp::MessageList(input) => {
                    input.cli_list = self.mail_list;
                    input.owner_to = self.mail_to.clone();
                }
                _ => {
                    return Err(unknown_flag(
                        "--to",
                        op.meta().name,
                        "this operation has no mail filter",
                    ));
                }
            }
        }
        Ok(())
    }
}
