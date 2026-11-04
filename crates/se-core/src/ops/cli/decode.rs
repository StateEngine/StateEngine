//! Translate the generated command leaf to its registered typed core input.
use super::*;
use crate::commit::{AbsentRevision, ExpectedRevision};

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
    if meta.name != "meta.help" && meta.scope == Scope::None && common.home.is_some() {
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
        && meta.name != "meta.help"
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
            "continuity.resume" => AnyOp::Resume(Resume {
                limit: required(m, "limit")?
                    .parse()
                    .map_err(|_| SeError::invalid("limit", "1..100"))?,
                governing_cursor: text(m, "governing_cursor").map(Cursor::new).transpose()?,
                since: text(m, "since").map(Cursor::new).transpose()?,
                byte_budget: required(m, "budget")?
                    .parse()
                    .map_err(|_| SeError::invalid("budget", "1024..1048576"))?,
                preview_agent: None,
            }),
            "session.context" => AnyOp::SessionContext(SessionContextRequest {
                governing_cursor: text(m, "governing_cursor").map(Cursor::new).transpose()?,
                limit: required(m, "limit")?
                    .parse()
                    .map_err(|_| SeError::invalid("limit", "1..100"))?,
                since: text(m, "since").map(Cursor::new).transpose()?,
                byte_budget: required(m, "budget")?
                    .parse()
                    .map_err(|_| SeError::invalid("budget", "1024..1048576"))?,
            }),
            "agent.list" => AnyOp::AgentList(AgentList {
                limit: required(m, "limit")?
                    .parse()
                    .map_err(|_| SeError::invalid("limit", "1..100"))?,
                cursor: text(m, "cursor").map(Cursor::new).transpose()?,
            }),
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
            "doctor.inspect" => AnyOp::DoctorInspect(DoctorInspect {}),
            "doctor.repair" => AnyOp::DoctorRepair(DoctorRepair {
                check_id: required(m, "fix")?,
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
            "store.import_node" => AnyOp::ImportNode(ImportNode {
                from_node: required(m, "from_node")?,
                source_owner: text(m, "source_owner")
                    .map(se_types::HumanId::from_legacy)
                    .transpose()?,
                idempotency_key: key()?,
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
            "history.list" => AnyOp::HistoryList(HistoryList {
                session: text(m, "session")
                    .map(|value| {
                        value
                            .parse()
                            .map_err(|_| SeError::invalid("session", "a canonical session ID"))
                    })
                    .transpose()?,
                kinds: many(m, "kind"),
                since: text(m, "since").map(Cursor::new).transpose()?,
                limit: number(m, "limit")?,
                cursor: text(m, "cursor").map(Cursor::new).transpose()?,
                owner_agent: None,
            }),
            "history.event_read" => AnyOp::EventRead(EventRead {
                event_id: required(m, "event")?,
            }),
            "message.read" => AnyOp::MessageRead(MessageRead {
                msg_id: required(m, "msg_id")?
                    .parse()
                    .map_err(|_| SeError::invalid("message ID", "a canonical msg_ ID"))?,
                budget: required(m, "budget")?
                    .parse()
                    .map_err(|_| SeError::invalid("budget", "512..1048576 bytes"))?,
            }),
            "message.ack" => AnyOp::MessageAck(MessageAck {
                msg_id: required(m, "msg_id")?
                    .parse()
                    .map_err(|_| SeError::invalid("message ID", "a canonical msg_ ID"))?,
            }),
            "message.dismiss" => AnyOp::MessageDismiss(MessageDismiss {
                msg_id: required(m, "msg_id")?
                    .parse()
                    .map_err(|_| SeError::invalid("message ID", "a canonical msg_ ID"))?,
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
            "message.inbox" => AnyOp::MessageInbox(MessageInbox {
                agent: text(m, "agent"),
                full: flag(m, "full"),
                limit: number(m, "limit")?,
                preview_chars: text(m, "preview_chars")
                    .map(|value| {
                        value
                            .parse()
                            .map_err(|_| SeError::invalid("preview-chars", "0..4000"))
                    })
                    .transpose()?,
                cursor: text(m, "cursor").map(Cursor::new).transpose()?,
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
            "agent.launch" => AnyOp::AgentLaunch(AgentLaunch {
                target_agent_id: None,
                fresh: flag(m, "new"),
                model: text(m, "model"),
                task: text(m, "task"),
                detach: flag(m, "detach"),
                idempotency_key: key()?,
                owner_agent: text(m, "agent"),
                owner_provider: common.selections.launch_provider,
            }),
            "agent.stop" => AnyOp::AgentStop(AgentStop {
                target_agent_id: None,
                idempotency_key: key()?,
                owner_agent: if flag(m, "all") {
                    None
                } else {
                    Some(required(m, "agent")?)
                },
                all: flag(m, "all"),
                release: flag(m, "release"),
            }),
            "project.remove" => AnyOp::ProjectRemove(ProjectRemove {
                all: flag(m, "all"),
                keep_integrations: flag(m, "keep-integrations"),
                idempotency_key: key()?,
            }),
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
            "decision.list" => AnyOp::DecisionList(DecisionList {
                id: text(m, "id"),
                pending: flag(m, "pending"),
                history: flag(m, "history"),
                limit: text(m, "limit")
                    .map(|value| {
                        value
                            .parse()
                            .map_err(|_| SeError::invalid("limit", "1..100"))
                    })
                    .transpose()?
                    .unwrap_or(20),
                cursor: text(m, "cursor").map(se_types::Cursor::new).transpose()?,
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
