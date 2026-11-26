//! Translate the generated command leaf to its registered typed core input.
use super::*;
use se_core::commit::{AbsentRevision, ExpectedRevision};

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
    // Help and guide text is the same in every home, so a habitual --home is harmless.
    if !matches!(meta.name, "meta.help" | "meta.guide")
        && meta.scope == Scope::None
        && common.home.is_some()
    {
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
        // A machine-wide operation names its scope instead of repeating a
        // generic selector absence, and gives the working command as typed.
        let reason = match meta.scope {
            Scope::Home => {
                "this operation runs on the whole machine, not a project; run it without --project"
            }
            _ => "this operation has no project selector",
        };
        return Err(unknown_flag("--project", meta.name, reason));
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
        _ => decode_leaf(meta.name, m, &path, &common, &key)?,
    };
    Ok(op)
}
fn decode_leaf(
    name: &str,
    m: &ArgMatches,
    path: &[String],
    common: &CommonArgs,
    key: &impl Fn() -> Result<IdempotencyKey>,
) -> Result<AnyOp> {
    decode_session(name, m)?
        .or(decode_meta(name, m, path)?)
        .or(decode_agent(name, m, common, key)?)
        .or(decode_config(name, m, key)?)
        .or(decode_project(name, m, path, key)?)
        .or(decode_store(name, m, key)?)
        .or(decode_history(name, m)?)
        .or(decode_message(name, m, key)?)
        .or(decode_runtime(name, m, key)?)
        .or(decode_assignment(name, m, key)?)
        .ok_or_else(|| unknown(name))
}
fn decode_session(name: &str, m: &ArgMatches) -> Result<Option<AnyOp>> {
    let op = match name {
        "continuity.resume" => AnyOp::Resume(Resume {
            source_failure: None,
            limit: required(m, "limit")?
                .parse()
                .map_err(|_| SeError::invalid("limit", "1..100"))?,
            since: text(m, "since")
                .map(se_core::ops::continuity::resume_since)
                .transpose()?,
            byte_budget: required(m, "budget")?
                .parse()
                .map_err(|_| SeError::invalid("budget", "1024..1048576"))?,
            preview_agent: None,
        }),
        "handoff.export" => AnyOp::HandoffExport(HandoffExport {
            from: text(m, "from"),
            budget: required(m, "budget")?
                .parse()
                .map_err(|_| SeError::invalid("budget", "256..16384"))?,
            since: text(m, "since")
                .map(se_core::ops::continuity::resume_since)
                .transpose()?,
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
        _ => return Ok(None),
    };
    Ok(Some(op))
}
fn decode_meta(name: &str, m: &ArgMatches, path: &[String]) -> Result<Option<AnyOp>> {
    let op = match name {
        "meta.version" => AnyOp::MetaVersion(MetaVersion {}),
        "meta.help" => AnyOp::MetaHelp(MetaHelp {
            path: if flag(m, "help") || is_group(path) {
                path.to_vec()
            } else {
                many(m, "path")
            },
            all: if flag(m, "help") || is_group(path) {
                false
            } else {
                flag(m, "all")
            },
        }),
        "meta.guide" => AnyOp::MetaGuide(MetaGuide {
            topic: text(m, "topic"),
        }),
        "meta.schema" => AnyOp::MetaSchema(MetaSchema { op: text(m, "op") }),
        _ => return Ok(None),
    };
    Ok(Some(op))
}
fn decode_agent(
    name: &str,
    m: &ArgMatches,
    common: &CommonArgs,
    key: &impl Fn() -> Result<IdempotencyKey>,
) -> Result<Option<AnyOp>> {
    let op = match name {
        "agent.list" => AnyOp::AgentList(AgentList {
            limit: required(m, "limit")?
                .parse()
                .map_err(|_| SeError::invalid("limit", "1..100"))?,
            cursor: text(m, "cursor").map(Cursor::new).transpose()?,
            include_temp: flag(m, "include-temp"),
        }),
        "agent.show" => AnyOp::AgentShow(AgentShow {
            target_agent_id: None,
        }),
        "agent.launch" => AnyOp::AgentLaunch(AgentLaunch {
            target_agent_id: None,
            resume: se_types::ResumeSelection::from_cli(text(m, "resume"))?,
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
        "agent.create" => AnyOp::AgentCreate(AgentCreate {
            provider_settings: Box::new(se_types::ProviderSettings {
                model_provider: text(m, "model-provider"),
                base_url: text(m, "base-url"),
                wire_api: text(m, "wire-api"),
                reasoning_effort: text(m, "reasoning-effort"),
                context_window: text(m, "context-window")
                    .map(|value| {
                        value.parse::<u64>().map_err(|_| {
                            SeError::invalid("context-window", "a positive token count")
                        })
                    })
                    .transpose()?,
            }),
            harness: text(m, "harness"),
            name: required(m, "name")?,
            provider: text(m, "provider")
                .map(|value| {
                    serde_json::from_value(serde_json::Value::String(value))
                        .map_err(|_| SeError::invalid("provider", provider_list()))
                })
                .transpose()?,
            model: text(m, "model"),
            profile: text(m, "profile"),
            idempotency_key: key()?,
        }),
        "delegate.start" => decode_delegate_start(m, key)?,
        "delegate.cancel" => AnyOp::DelegateCancel(DelegateCancel {
            agent: required(m, "agent")?,
            idempotency_key: key()?,
        }),
        "agent.rename" => AnyOp::AgentRename(AgentRename {
            agent: required(m, "agent")?,
            name: required(m, "name")?,
            idempotency_key: key()?,
        }),
        _ => return Ok(None),
    };
    Ok(Some(op))
}
fn decode_delegate_start(
    m: &ArgMatches,
    key: &impl Fn() -> Result<IdempotencyKey>,
) -> Result<AnyOp> {
    let handoff_from = text(m, "handoff_from");
    let handoff_budget = text(m, "handoff_budget")
        .map(|v| {
            v.parse::<u32>()
                .map_err(|_| SeError::invalid("handoff-budget", "256..=8192"))
        })
        .transpose()?;
    let handoff_since = text(m, "handoff_since")
        .map(se_core::ops::continuity::resume_since)
        .transpose()?;
    let handoff = if flag(m, "handoff")
        || handoff_from.is_some()
        || handoff_budget.is_some()
        || handoff_since.is_some()
    {
        Some(Box::new(DelegateHandoff {
            from: handoff_from,
            budget: handoff_budget,
            since: handoff_since,
        }))
    } else {
        None
    };
    Ok(AnyOp::DelegateStart(DelegateStart {
        task: required(m, "task")?,
        role: text(m, "role"),
        provider: text(m, "provider")
            .map(|value| {
                serde_json::from_value(serde_json::Value::String(value))
                    .map_err(|_| SeError::invalid("provider", provider_list()))
            })
            .transpose()?,
        harness: text(m, "harness"),
        model: text(m, "model"),
        profile: text(m, "profile"),
        handoff,
        ttl_seconds: text(m, "ttl")
            .map(|v| {
                v.parse::<u32>()
                    .map_err(|_| SeError::invalid("ttl", "1..=86400 seconds"))
            })
            .transpose()?,
        idempotency_key: key()?,
    }))
}
fn decode_config(
    name: &str,
    m: &ArgMatches,
    key: &impl Fn() -> Result<IdempotencyKey>,
) -> Result<Option<AnyOp>> {
    let op = match name {
        "config.get" => AnyOp::ConfigGet(ConfigGet {
            key: required(m, "setting_key")?,
            origin: flag(m, "origin"),
        }),
        "config.set" => AnyOp::ConfigSet(ConfigSet {
            key: required(m, "setting_key")?,
            value: required(m, "setting_value")?,
            idempotency_key: key()?,
        }),
        "harness.add" => AnyOp::HarnessAdd(se_core::ops::HarnessAdd {
            name: required(m, "harness_name")?,
            command: required(m, "command")?,
            arguments: many(m, "arg"),
            environment: many(m, "env"),
        }),
        "config.list" => AnyOp::ConfigList(ConfigList {
            origin: flag(m, "origin"),
            limit: required(m, "limit")?
                .parse()
                .map_err(|_| SeError::invalid("limit", "1..500"))?,
            cursor: text(m, "cursor").map(Cursor::new).transpose()?,
        }),
        _ => return Ok(None),
    };
    Ok(Some(op))
}
fn decode_project(
    name: &str,
    m: &ArgMatches,
    path: &[String],
    key: &impl Fn() -> Result<IdempotencyKey>,
) -> Result<Option<AnyOp>> {
    let op = match name {
        "project.status" => AnyOp::ProjectStatus(ProjectStatus {
            fresh: !path.is_empty() && flag(m, "fresh"),
            watch_only: false,
            include_temp: !path.is_empty() && flag(m, "include-temp"),
            scope: if !path.is_empty() && flag(m, "all") {
                StatusScope::All
            } else {
                StatusScope::Selected
            },
        }),
        "project.init" => AnyOp::ProjectInit(ProjectInit {
            harness: text(m, "harness"),
            repo: text(m, "repo"),
            name: text(m, "name"),
            agent: required(m, "agent")?,
            provider: text(m, "provider")
                .map(|v| {
                    serde_json::from_value(serde_json::Value::String(v))
                        .map_err(|_| SeError::invalid("provider", provider_list()))
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
        "worktree.remove" => AnyOp::WorktreeRemove(WorktreeRemove {
            path: required(m, "path")?,
            force: flag(m, "force"),
        }),
        "project.remove" => AnyOp::ProjectRemove(ProjectRemove {
            all: flag(m, "all"),
            keep_integrations: flag(m, "keep-integrations"),
            idempotency_key: key()?,
        }),
        _ => return Ok(None),
    };
    Ok(Some(op))
}
fn decode_store(
    name: &str,
    m: &ArgMatches,
    key: &impl Fn() -> Result<IdempotencyKey>,
) -> Result<Option<AnyOp>> {
    let op = match name {
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

        "store.restore" => AnyOp::StoreRestore(StoreRestore {
            yes: flag(m, "yes"),
            idempotency_key: key()?,
        }),
        "store.forget" => AnyOp::StoreForget(StoreForget {
            events: m
                .get_many::<String>("event")
                .into_iter()
                .flatten()
                .map(|v| v.parse())
                .collect::<Result<Vec<_>>>()?,
            yes: flag(m, "yes"),
            plan: text(m, "plan"),
            idempotency_key: key()?,
        }),
        _ => return Ok(None),
    };
    Ok(Some(op))
}
fn decode_history(name: &str, m: &ArgMatches) -> Result<Option<AnyOp>> {
    let op = match name {
        "history.list" => AnyOp::HistoryList(HistoryList {
            session: text(m, "session")
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| SeError::invalid("session", "a canonical session ID"))
                })
                .transpose()?,
            kinds: many(m, "kind"),
            since: text(m, "position")
                .map(se_core::ops::history::position_cursor)
                .transpose()?,
            limit: number(m, "limit")?,
            cursor: text(m, "cursor").map(Cursor::new).transpose()?,
            newest: flag(m, "newest"),
            owner_agent: None,
        }),
        "history.search" => AnyOp::HistorySearch(HistorySearch {
            query: required(m, "query")?,
            session: text(m, "session")
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| SeError::invalid("session", "a canonical session ID"))
                })
                .transpose()?,
            kinds: many(m, "kind"),
            since: text(m, "position")
                .map(se_core::ops::history::position_cursor)
                .transpose()?,
            limit: number(m, "limit")?,
            byte_budget: required(m, "budget")?
                .parse()
                .map_err(|_| SeError::invalid("budget", "1024..1048576 bytes"))?,
            cursor: text(m, "cursor").map(Cursor::new).transpose()?,
            newest: flag(m, "newest"),
            owner_agent: None,
        }),
        "history.event_read" => AnyOp::EventRead(EventRead {
            event_id: required(m, "event")?,
        }),
        _ => return Ok(None),
    };
    Ok(Some(op))
}
fn decode_message(
    name: &str,
    m: &ArgMatches,
    key: &impl Fn() -> Result<IdempotencyKey>,
) -> Result<Option<AnyOp>> {
    let op = match name {
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
            to: if text(m, "body").is_some() {
                Some(required(m, "to")?)
            } else {
                None
            },
            body: text(m, "body")
                .or_else(|| text(m, "to"))
                .ok_or_else(|| SeError::invalid("body", "message text"))?,
            quiet: flag(m, "no_wake"),
            kind: serde_json::from_value(serde_json::Value::String(required(m, "kind")?))
                .map_err(|_| SeError::invalid("kind", "a registered message kind"))?,
            work: work_addressing(m)?,
            refs: many(m, "refs"),
            reply_to: text(m, "reply_to")
                .map(se_types::MessageId::from_legacy)
                .transpose()?,
            supersedes: text(m, "supersedes")
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
            newest: flag(m, "newest"),
            owner_to: text(m, "to"),
        }),
        _ => return Ok(None),
    };
    Ok(Some(op))
}
fn decode_runtime(
    name: &str,
    m: &ArgMatches,
    key: &impl Fn() -> Result<IdempotencyKey>,
) -> Result<Option<AnyOp>> {
    let op =
        match name {
            "diagnostic.bundle" => AnyOp::DiagnosticBundle(DiagnosticBundle {}),
            "doctor.inspect" => AnyOp::DoctorInspect(DoctorInspect {}),
            "doctor.repair" => AnyOp::DoctorRepair(DoctorRepair {
                check_id: required(m, "fix")?,
            }),
            "hook.claude" => AnyOp::HookClaude(HookClaude {
                event: serde_json::from_value(serde_json::Value::String(required(m, "event")?))
                    .map_err(|_| SeError::invalid("event", "a fixed Claude hook event"))?,
            }),
            "working_state.get" => AnyOp::WorkingStateGet(WorkingStateGet { owner_agent: None }),
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
                yes: m.get_flag("yes"),
            }),
            _ => return Ok(None),
        };
    Ok(Some(op))
}
fn decode_assignment(
    name: &str,
    m: &ArgMatches,
    key: &impl Fn() -> Result<IdempotencyKey>,
) -> Result<Option<AnyOp>> {
    let op = match name {
        "captain.set" => AnyOp::CaptainSet(CaptainSet {
            captain: required(m, "captain")?,
            idempotency_key: key()?,
        }),
        "captain.clear" => AnyOp::CaptainClear(CaptainClear {
            idempotency_key: key()?,
        }),
        "captain.show" => AnyOp::CaptainShow(CaptainShow {}),
        "assignment.write" => AnyOp::AssignmentWrite(AssignmentWrite {
            action: match required(m, "action")?.as_str() {
                "open" => AssignmentAction::Open,
                "accept" => AssignmentAction::Accept,
                "done" => AssignmentAction::Done,
                "block" => AssignmentAction::Block,
                "hand-back" => AssignmentAction::HandBack,
                _ => {
                    return Err(SeError::invalid(
                        "action",
                        "open, accept, done, block, or hand-back",
                    ));
                }
            },
            assignment: text(m, "assignment").map(|s| s.try_into()).transpose()?,
            assignee: text(m, "assignee"),
            body: required(m, "body")?,
            idempotency_key: key()?,
        }),
        "assignment.list" => AnyOp::AssignmentList(AssignmentList {
            limit: required(m, "limit")?
                .parse()
                .map_err(|_| SeError::invalid("limit", "1..100"))?,
            cursor: text(m, "cursor").map(Cursor::new).transpose()?,
        }),
        _ => return Ok(None),
    };
    Ok(Some(op))
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
