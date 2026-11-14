//! Translate the generated command leaf to its registered typed core input.
use super::*;
use crate::commit::{AbsentRevision, ExpectedRevision};

pub fn from_matches(matches: &ArgMatches) -> Result<AnyOp> {
    from_matches_with_key(matches, None)
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
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
                        command: command_name(meta.name),
                        argument:
                            "request identity generated before first send (or --key for retry)"
                                .into(),
                    },
                ))
            })
    };
    if matches!(
        meta.name,
        "remote.list" | "remote.watch" | "remote.send" | "remote.launch" | "client.watch"
    ) {
        return super::remote::decode(meta.name, m, key);
    }
    let op = match meta.name {
        name if name.starts_with("atlas.") => atlas::decode(name, m, common.json)?,
        "continuity.resume" => AnyOp::Resume(Resume {
            source_failure: None,
            limit: required(m, "limit")?
                .parse()
                .map_err(|_| SeError::invalid("limit", "1..100"))?,
            since: text(m, "since")
                .map(crate::ops::continuity::resume_since)
                .transpose()?,
            byte_budget: required(m, "budget")?
                .parse()
                .map_err(|_| SeError::invalid("budget", "1024..1048576"))?,
            preview_agent: None,
        }),
        "session.context" => AnyOp::SessionContext(SessionContextRequest {
            source_failure: None,
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
        "config.list" => AnyOp::ConfigList(ConfigList {
            origin: flag(m, "origin"),
            limit: required(m, "limit")?
                .parse()
                .map_err(|_| SeError::invalid("limit", "1..500"))?,
            cursor: text(m, "cursor").map(Cursor::new).transpose()?,
        }),
        "diagnostic.bundle" => AnyOp::DiagnosticBundle(DiagnosticBundle {}),
        "doctor.inspect" => AnyOp::DoctorInspect(DoctorInspect {}),
        "doctor.repair" => AnyOp::DoctorRepair(DoctorRepair {
            check_id: required(m, "fix")?,
        }),
        "meta.version" => AnyOp::MetaVersion(MetaVersion {}),
        "meta.help" => AnyOp::MetaHelp(MetaHelp {
            path: if flag(m, "help") || path == ["atlas"] {
                path.clone()
            } else {
                many(m, "path")
            },
            all: if flag(m, "help") || path == ["atlas"] {
                false
            } else {
                flag(m, "all")
            },
        }),
        "meta.guide" => AnyOp::MetaGuide(MetaGuide {
            topic: text(m, "topic"),
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
        #[cfg(feature = "import")]
        "store.import_node" => AnyOp::ImportNode(ImportNode {
            from_node: required(m, "from_node")?,
            source_owner: text(m, "source_owner")
                .map(se_types::HumanId::from_legacy)
                .transpose()?,
            human_mappings: m
                .get_many::<String>("map_human")
                .into_iter()
                .flatten()
                .map(|v| store_import::HumanMapping::parse(v))
                .collect::<Result<Vec<_>>>()?,
            idempotency_key: key()?,
        }),

        "project.init" => AnyOp::ProjectInit(ProjectInit {
            harness: text(m, "harness"),
            repo: text(m, "repo"),
            name: text(m, "name"),
            agent: required(m, "agent")?,
            provider: text(m, "provider")
                .map(|v| {
                    serde_json::from_value(serde_json::Value::String(v))
                        .map_err(|_| SeError::invalid("provider", "claude, codex, secode or acp"))
                })
                .transpose()?,
            model: text(m, "model"),
            launch: flag(m, "launch"),
            adopt: flag(m, "adopt"),
            idempotency_key: key()?,
        }),
        "project.move" => AnyOp::ProjectMove(ProjectMove {
            root: required(m, "root")?,
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
            quiet: flag(m, "no_wake"),
            kind: serde_json::from_value(serde_json::Value::String(required(m, "kind")?))
                .map_err(|_| SeError::invalid("kind", "a registered message kind"))?,
            work: work_addressing(m)?,
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
            override_live: flag(m, "override_live"),
            force_selection: None,
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
                Some(stop_agent(m)?)
            },
            all: flag(m, "all"),
            release: flag(m, "release"),
        }),
        "agent.wake" => AnyOp::AgentWake(AgentWake {
            target_agent_id: None,
            owner_agent: Some(required(m, "agent")?),
        }),
        "project.remove" => AnyOp::ProjectRemove(ProjectRemove {
            all: flag(m, "all"),
            keep_integrations: flag(m, "keep-integrations"),
            idempotency_key: key()?,
        }),
        "agent.create" => AnyOp::AgentCreate(AgentCreate {
            harness: text(m, "harness"),
            name: required(m, "name")?,
            provider: text(m, "provider")
                .map(|value| {
                    serde_json::from_value(serde_json::Value::String(value))
                        .map_err(|_| SeError::invalid("provider", "claude, codex, secode or acp"))
                })
                .transpose()?,
            model: text(m, "model"),
            idempotency_key: key()?,
        }),
        "agent.rename" => AnyOp::AgentRename(AgentRename {
            agent: required(m, "agent")?,
            name: required(m, "name")?,
            idempotency_key: key()?,
        }),
        "working_state.set" => {
            let expect = required(m, "expect")?;
            AnyOp::WorkingStateSet(WorkingStateSet {
                text: required(m, "text")?,
                expect: if expect == "absent" {
                    ExpectedRevision::Absent(AbsentRevision::Absent)
                } else {
                    ExpectedRevision::Revision(
                        expect.parse().map_err(|_| {
                            SeError::invalid("expect", "positive revision or absent")
                        })?,
                    )
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
            yes: m.get_flag("yes"),
        }),
        _ => return Err(unknown(meta.name)),
    };
    Ok(op)
}

fn stop_agent(m: &ArgMatches) -> Result<String> {
    text(m, "agent").ok_or_else(|| {
        let mut error = SeError::new(Detail::UsageMissingArgument(
            details::UsageMissingArgument {
                command: "se stop".into(),
                argument: "an agent name/ID or --all".into(),
            },
        ));
        error.body = error.body.with_remedy(se_types::Remedy {
            text: "Use se stop AGENT for one agent, or se stop --all for all agents in the selected project. Use se down only to stop the background runtime.".into(),
            command: None,
        });
        error
    })
}

fn work_addressing(m: &ArgMatches) -> Result<Option<se_types::WorkAddressing>> {
    let floor = text(m, "to").as_deref() == Some("floor");
    let addressees = many(m, "addressees");
    let Some(action) = text(m, "work_action") else {
        if floor {
            return Err(floor_guidance(SeError::invalid(
                "floor message",
                "--work-action ACTION and 1..20 distinct --addressee AGENT_ID values",
            )));
        }
        if !addressees.is_empty() {
            return Err(SeError::invalid(
                "addressee",
                "--work-action with a floor target",
            ));
        }
        return Ok(None);
    };
    let work = se_types::WorkAddressing {
        action: serde_json::from_value(serde_json::Value::String(action))
            .map_err(|_| SeError::invalid("work-action", "a registered work action"))?,
        addressees: addressees
            .into_iter()
            .map(|id| {
                id.parse().map_err(|_| {
                    floor_guidance(SeError::invalid("addressee", "a canonical agent ID"))
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    if floor {
        work.validate().map_err(floor_guidance)?;
    }
    Ok(Some(work))
}

fn floor_guidance(mut error: SeError) -> SeError {
    error.body = error.body.with_remedy(se_types::Remedy {
        text: "Run se msg send --help for --work-action values and --addressee syntax. Use se agent list with the same --home and --project to find agent IDs; repeat --addressee for each distinct recipient (1..20).".into(),
        command: None,
    });
    error
}
