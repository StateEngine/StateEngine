//! Out-of-band Owner external-seat controls (`se external list|approve|revoke`),
//! dedicated authenticated blocking wait CLI (`se msg wait`), and the turn
//! state an external seat's runner reports (`se msg activity`).
use clap::{Arg, Command};
use se_core::store_error::store_error;
use se_host::{
    IpcEnvelope, IpcRequest, OperationOutput,
    client::{ClientOptions, lease::Deadline, presence::OwnerPresence},
    external::{
        ActivityState, ExternalApproveOutput, ExternalListOutput, ExternalMailWaitOutput,
        ExternalRequest, ExternalRevokeOutput, ExternalSessionActivityOutput,
    },
};
use se_store::{Scope, Snapshot};
use se_types::{ProjectId, RenderCx, Result, SeError};
use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

pub(crate) fn entry(args: &[OsString]) -> Option<io::Result<u8>> {
    // A cheap candidate filter keeps ordinary commands off this grammar; only
    // the parse below selects a transport route.
    let word = |w: &str| args.iter().skip(1).any(|a| a == w);
    if !(word("external") || (word("msg") && (word("wait") || word("activity")))) {
        return None;
    }
    let command = transport_command();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    match command.clone().try_get_matches_from(args) {
        Ok(matches) => {
            let (route, sub) = route(&matches)?;
            drop((stdout, stderr));
            Some(match route {
                Route::External => run_external(sub),
                Route::Wait => run_msg_wait(sub),
                Route::Activity => run_msg_activity(sub),
            })
        }
        Err(err) => {
            // Refuse only invocations that select a transport route; anything
            // else (`se msg send ...`) belongs to the ordinary CLI.
            let selected = command
                .ignore_errors(true)
                .try_get_matches_from(args)
                .ok()?;
            route(&selected)?;
            if matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                return Some(write!(stdout, "{err}").map(|()| 0));
            }
            let se_err = crate::grammar::usage_error(err, args);
            let json = crate::grammar::json_requested(args);
            Some(crate::render::error::write(
                &se_err,
                &RenderCx::default(),
                json,
                &mut stdout,
                &mut stderr,
            ))
        }
    }
}

enum Route {
    External,
    Wait,
    Activity,
}

fn route(matches: &clap::ArgMatches) -> Option<(Route, &clap::ArgMatches)> {
    match matches.subcommand()? {
        ("external", sub) => Some((Route::External, sub)),
        ("msg", msg) => match msg.subcommand()? {
            ("wait", sub) => Some((Route::Wait, sub)),
            ("activity", sub) => Some((Route::Activity, sub)),
            _ => None,
        },
        _ => None,
    }
}

/// One grammar for the transport commands. The ordinary CLI's global flags are
/// shared, so they may lead or follow the command.
fn transport_command() -> Command {
    Command::new("se")
        .args(se_cli_spec::output_global_args())
        .subcommand(
            Command::new("external")
                .about("Manage owner-approved external seats")
                .subcommand_required(true)
                .subcommand(
                    Command::new("list")
                        .about("List pending external seat claims and active leases"),
                )
                .subcommand(
                    Command::new("approve")
                        .about("Approve a pending external seat claim once")
                        .arg(Arg::new("claim_id").required(true)),
                )
                .subcommand(
                    Command::new("revoke")
                        .about("Revoke an active external seat")
                        .arg(Arg::new("agent").required(true)),
                ),
        )
        .subcommand(
            Command::new("msg")
                .subcommand(
                    Command::new("wait")
                        .about("Block on the host's recipient-scoped mail registry until mail arrives or the seat closes")
                        .arg(Arg::new("as").long("as").help("External seat agent name or ID to wait on"))
                        .arg(Arg::new("after").long("after").help("Cursor from a previous `messages` result"))
                        .arg(
                            Arg::new("timeout")
                                .long("timeout")
                                .value_parser(clap::value_parser!(u64))
                                .help("Wait timeout in seconds (1..=300)"),
                        ),
                )
                .subcommand(
                    Command::new("activity")
                        .about("Report an external seat's turn state so `se msg wait` holds mail while it is busy")
                        .arg(Arg::new("as").long("as").help("External seat agent name or ID"))
                        .arg(
                            Arg::new("state")
                                .required(true)
                                .value_parser(["busy", "idle"])
                                .help("busy when a turn starts, idle when it ends"),
                        ),
                ),
        )
}

fn run_msg_activity(sub: &clap::ArgMatches) -> io::Result<u8> {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let home = sub.get_one::<String>("home").map(PathBuf::from);
    let project_arg = sub.get_one::<String>("project").cloned();
    let agent = sub.get_one::<String>("as").cloned();
    let state = match sub.get_one::<String>("state").map(String::as_str) {
        Some("busy") => ActivityState::Busy,
        _ => ActivityState::Idle,
    };
    let json = sub.get_flag("json");
    let result = (|| -> Result<()> {
        let cx = if agent.is_some() {
            crate::bootstrap::Bootstrap::resolve_owner(home, false, json, "session.activity")?
        } else {
            crate::bootstrap::Bootstrap::resolve_either(home, project_arg.clone(), false, json)?
        };
        let project = if agent.is_some() {
            Some(resolve_required_project(&cx, project_arg.as_deref())?)
        } else {
            resolve_optional_project(&cx, project_arg.as_deref())?
        };
        let request = ExternalRequest::SessionActivity {
            project,
            agent,
            state,
        };
        let out = send_seat_request(&cx, request, Duration::from_secs(30))?;
        let reported: ExternalSessionActivityOutput = serde_json::from_value(out.value)
            .map_err(|e| se_core::scope::unreadable("session activity output", &e.to_string()))?;
        let line = if json {
            serde_json::to_string(&reported)
                .map_err(|e| se_core::scope::unreadable("json", &e.to_string()))?
        } else {
            let state = match reported.state {
                ActivityState::Busy => "busy: `se msg wait` holds new mail until it reports idle",
                ActivityState::Idle if reported.turn_ended => {
                    "idle: the next `se msg wait` returns any unread mail at once"
                }
                ActivityState::Idle => "idle",
            };
            format!("External seat {} is {state}", reported.agent_id)
        };
        writeln!(stdout, "{line}").map_err(|e| se_core::scope::unreadable("stdout", &e.to_string()))
    })();
    match result {
        Ok(()) => Ok(0),
        Err(err) => {
            crate::render::error::write(&err, &RenderCx::default(), json, &mut stdout, &mut stderr)
        }
    }
}

fn run_external(ext: &clap::ArgMatches) -> io::Result<u8> {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let home = ext.get_one::<String>("home").map(PathBuf::from);
    let project_arg = ext.get_one::<String>("project").cloned();
    let json = ext.get_flag("json");
    let result = (|| -> Result<()> {
        let cx =
            crate::bootstrap::Bootstrap::resolve_owner(home, false, json, "external seat control")?;
        let (request, project_needed) = match ext.subcommand() {
            Some(("list", _)) => {
                let project = resolve_optional_project(&cx, project_arg.as_deref())?;
                (ExternalRequest::List { project }, false)
            }
            Some(("approve", sub)) => {
                let claim_id = sub
                    .get_one::<String>("claim_id")
                    .cloned()
                    .ok_or_else(|| SeError::invalid("claim_id", "a pending claim ID"))?;
                (ExternalRequest::Approve { claim_id }, false)
            }
            Some(("revoke", sub)) => {
                let agent = sub
                    .get_one::<String>("agent")
                    .cloned()
                    .ok_or_else(|| SeError::invalid("agent", "an agent name or ID"))?;
                let project = resolve_required_project(&cx, project_arg.as_deref())?;
                (
                    ExternalRequest::Revoke {
                        project: Some(project),
                        agent,
                    },
                    true,
                )
            }
            _ => return Err(SeError::invalid("external", "list, approve, or revoke")),
        };
        let _ = project_needed;
        let out = send_owner_external(&cx, request, Duration::from_secs(30))?;
        render_external_output(&out, json, &mut stdout)
            .map_err(|e| se_core::scope::unreadable("stdout", &e.to_string()))
    })();
    match result {
        Ok(()) => Ok(0),
        Err(err) => {
            crate::render::error::write(&err, &RenderCx::default(), json, &mut stdout, &mut stderr)
        }
    }
}

fn run_msg_wait(wait: &clap::ArgMatches) -> io::Result<u8> {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let home = wait.get_one::<String>("home").map(PathBuf::from);
    let project_arg = wait.get_one::<String>("project").cloned();
    let agent = wait.get_one::<String>("as").cloned();
    let after = wait.get_one::<String>("after").cloned();
    let timeout_secs = wait.get_one::<u64>("timeout").copied().unwrap_or(25);
    let timeout_ms = timeout_secs.saturating_mul(1000);
    let json = wait.get_flag("json");
    let result = (|| -> Result<()> {
        let cx = if agent.is_some() {
            crate::bootstrap::Bootstrap::resolve_owner(home, false, json, "msg.wait")?
        } else {
            crate::bootstrap::Bootstrap::resolve_either(home, project_arg.clone(), false, json)?
        };
        let project = if agent.is_some() {
            Some(resolve_required_project(&cx, project_arg.as_deref())?)
        } else {
            resolve_optional_project(&cx, project_arg.as_deref())?
        };
        let request = ExternalRequest::MailWait {
            project,
            agent,
            after,
            timeout_ms: Some(timeout_ms),
        };
        let out = send_seat_request(
            &cx,
            request,
            Duration::from_millis(timeout_ms.saturating_add(10_000)),
        )?;
        let waited: ExternalMailWaitOutput = serde_json::from_value(out.value)
            .map_err(|e| se_core::scope::unreadable("mail wait output", &e.to_string()))?;
        if json {
            writeln!(
                stdout,
                "{}",
                serde_json::to_string(&waited)
                    .map_err(|e| se_core::scope::unreadable("json", &e.to_string()))?
            )
            .map_err(|e| se_core::scope::unreadable("stdout", &e.to_string()))?;
        } else if waited.status == "busy" {
            writeln!(
                stdout,
                "Seat is busy: {} unread message(s) held until it reports idle (cursor: {})",
                waited.ids.len(),
                waited.cursor
            )
            .map_err(|e| se_core::scope::unreadable("stdout", &e.to_string()))?;
        } else if waited.ids.is_empty() || waited.status != "messages" {
            writeln!(
                stdout,
                "No new mail (status: {}, cursor: {})",
                waited.status, waited.cursor
            )
            .map_err(|e| se_core::scope::unreadable("stdout", &e.to_string()))?;
        } else {
            writeln!(
                stdout,
                "Pending mail ({} message(s), complete: {}, cursor: {}):",
                waited.ids.len(),
                waited.complete,
                waited.cursor
            )
            .map_err(|e| se_core::scope::unreadable("stdout", &e.to_string()))?;
            for id in &waited.ids {
                writeln!(stdout, "  {id}")
                    .map_err(|e| se_core::scope::unreadable("stdout", &e.to_string()))?;
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok(0),
        Err(err) => {
            crate::render::error::write(&err, &RenderCx::default(), json, &mut stdout, &mut stderr)
        }
    }
}

fn send_owner_external(
    cx: &crate::bootstrap::Bootstrap,
    request: ExternalRequest,
    timeout: Duration,
) -> Result<OperationOutput> {
    let crate::route::setup::Setup::Present((files, (reader, mut phase))) =
        crate::route::setup::inspect_phase(
            &cx.home,
            se_core::ops::receipt::timestamp(crate::route::execute::now_us()?)?,
        )?
    else {
        return Err(crate::route::setup::required(cx));
    };
    let caller = crate::route::admit::observe(cx, &mut phase, &files)?;
    phase.close().map_err(|e| store_error(&e))?;
    drop(reader);
    if !matches!(caller.admission.actor, se_store::Actor::Human(_))
        || caller.admission.session.is_some()
    {
        return Err(SeError::new(se_types::Detail::OwnerRequired(
            se_types::details::OwnerRequired {
                op: "external seat control".into(),
            },
        )));
    }
    let owner = caller.owner.as_ref().ok_or_else(|| {
        SeError::invalid("external seat control", "a verified native human Owner")
    })?;
    let endpoint = se_core::scope::require_present(
        crate::route::execute::endpoint(&files)?,
        "external seat host",
        "Start the local StateEngine host (`se up`) first.",
    )?;
    let options = ClientOptions {
        expected_generation: Some(endpoint.generation),
        timeout,
        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let call = IpcEnvelope {
        version: se_types::API_VERSION,
        request_id: 1,
        generation: endpoint.generation,
        authority: None,
        presence: Some(OwnerPresence::from_observation(owner.native_observation())),
        cli_selections: None,
        request: IpcRequest::External(Box::new(request)),
    };
    crate::ipc::exchange_output(
        &endpoint,
        crate::route::execute::credential(cx, &files)?,
        call,
        &options,
    )
}

/// Send a seat-scoped request (wait or activity) with the caller's own credential.
fn send_seat_request(
    cx: &crate::bootstrap::Bootstrap,
    request: ExternalRequest,
    timeout: Duration,
) -> Result<OperationOutput> {
    let crate::route::setup::Setup::Present((files, (reader, mut phase))) =
        crate::route::setup::inspect_phase(
            &cx.home,
            se_core::ops::receipt::timestamp(crate::route::execute::now_us()?)?,
        )?
    else {
        return Err(crate::route::setup::required(cx));
    };
    let caller = crate::route::admit::observe(cx, &mut phase, &files)?;
    phase.close().map_err(|e| store_error(&e))?;
    drop(reader);
    let endpoint = se_core::scope::require_present(
        crate::route::execute::endpoint(&files)?,
        "mail wait host",
        "Start the local StateEngine host (`se up`) first.",
    )?;
    let options = ClientOptions {
        expected_generation: Some(endpoint.generation),
        timeout,
        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let presence = caller
        .owner
        .as_ref()
        .map(|owner| OwnerPresence::from_observation(owner.native_observation()));
    let call = IpcEnvelope {
        version: se_types::API_VERSION,
        request_id: 1,
        generation: endpoint.generation,
        authority: None,
        presence,
        cli_selections: None,
        request: IpcRequest::External(Box::new(request)),
    };
    let _ = Deadline::from_options(&options)?;
    crate::ipc::exchange_output(
        &endpoint,
        crate::route::execute::credential(cx, &files)?,
        call,
        &options,
    )
}

fn resolve_optional_project(
    cx: &crate::bootstrap::Bootstrap,
    explicit: Option<&str>,
) -> Result<Option<ProjectId>> {
    if let Some(selector) = explicit {
        return crate::route::select::resolve_project_selector(&cx.home, selector).map(Some);
    }
    let crate::route::setup::Setup::Present((files, (reader, mut phase))) =
        crate::route::setup::inspect_phase(
            &cx.home,
            se_core::ops::receipt::timestamp(crate::route::execute::now_us()?)?,
        )?
    else {
        return Ok(None);
    };
    let mut caller = crate::route::admit::observe(cx, &mut phase, &files)?;
    let mut snap = phase
        .into_snapshot(se_core::admission::read_scope(&caller.admission))
        .map_err(|e| store_error(&e))?;
    let dummy = se_core::ops::AnyOp::ProjectStatus(Default::default());
    let _ = crate::route::select::apply(cx, &mut snap, &mut caller.admission, &dummy);
    let _ = snap.close();
    drop(reader);
    Ok(match caller.admission.scope {
        Scope::Project(project) => Some(project),
        Scope::Registry => None,
    })
}

fn resolve_required_project(
    cx: &crate::bootstrap::Bootstrap,
    explicit: Option<&str>,
) -> Result<ProjectId> {
    resolve_optional_project(cx, explicit)?.ok_or_else(|| {
        SeError::new(se_types::Detail::ProjectRequired(
            se_types::details::ProjectRequired { choices: vec![] },
        ))
    })
}

fn render_external_output(
    out: &OperationOutput,
    json: bool,
    stdout: &mut impl Write,
) -> io::Result<()> {
    if json {
        writeln!(stdout, "{}", out.value)?;
        return Ok(());
    }
    match out.schema.as_str() {
        "se.external-list/v1" => {
            if let Ok(list) = serde_json::from_value::<ExternalListOutput>(out.value.clone()) {
                writeln!(stdout, "Pending claims: {}", list.pending_claims.len())?;
                for claim in &list.pending_claims {
                    writeln!(
                        stdout,
                        "  {} — agent {} ({}) pid {} scope {}",
                        claim.claim_id,
                        claim.agent_name,
                        claim.agent_id,
                        claim.peer_pid,
                        claim.scope
                    )?;
                }
                writeln!(
                    stdout,
                    "Active external leases: {}",
                    list.active_leases.len()
                )?;
                for lease in &list.active_leases {
                    writeln!(
                        stdout,
                        "  {} ({}) — session {} gen {} pid {}",
                        lease.agent_name,
                        lease.agent_id,
                        lease.session_id,
                        lease.lease_generation,
                        lease.peer_pid
                    )?;
                }
            }
        }
        "se.external-approve/v1" => {
            if let Ok(approved) = serde_json::from_value::<ExternalApproveOutput>(out.value.clone())
            {
                writeln!(
                    stdout,
                    "Approved external seat {} (session {}, lease generation {})",
                    approved.agent_name, approved.session_id, approved.lease_generation
                )?;
            }
        }
        "se.external-revoke/v1" => {
            if let Ok(revoked) = serde_json::from_value::<ExternalRevokeOutput>(out.value.clone()) {
                writeln!(
                    stdout,
                    "Revoked external seat {} (session {})",
                    revoked.agent_id, revoked.session_id
                )?;
            }
        }
        _ => writeln!(stdout, "{}", out.value)?,
    }
    Ok(())
}
