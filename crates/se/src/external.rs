//! Out-of-band Owner external-seat controls (`se external list|approve|revoke`)
//! and dedicated authenticated blocking wait CLI (`se msg wait`).
use clap::{Arg, ArgAction, Command};
use se_core::store_error::store_error;
use se_host::{
    IpcEnvelope, IpcRequest, OperationOutput,
    client::{ClientOptions, lease::Deadline, presence::OwnerPresence},
    external::{
        ExternalApproveOutput, ExternalListOutput, ExternalMailWaitOutput, ExternalRequest,
        ExternalRevokeOutput,
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
    let first = args.get(1)?.to_str()?;
    if first == "external" {
        return Some(run_external(args));
    }
    if first == "msg" && args.get(2).and_then(|s| s.to_str()) == Some("wait") {
        return Some(run_msg_wait(args));
    }
    None
}

fn external_command() -> Command {
    Command::new("se").subcommand(
        Command::new("external")
            .about("Manage owner-approved external seats")
            .subcommand_required(true)
            .arg(Arg::new("home").long("home").global(true))
            .arg(Arg::new("project").long("project").global(true))
            .arg(
                Arg::new("json")
                    .long("json")
                    .action(ArgAction::SetTrue)
                    .global(true),
            )
            .subcommand(
                Command::new("list").about("List pending external seat claims and active leases"),
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
}

fn msg_wait_command() -> Command {
    Command::new("se").subcommand(
        Command::new("msg").subcommand(
            Command::new("wait")
                .about("Block on the host's recipient-scoped mail registry until mail arrives or the seat closes")
                .arg(Arg::new("home").long("home"))
                .arg(Arg::new("project").long("project"))
                .arg(Arg::new("as").long("as").help("External seat agent name or ID to wait on"))
                .arg(Arg::new("after").long("after").help("Cursor from a previous wait"))
                .arg(
                    Arg::new("timeout")
                        .long("timeout")
                        .value_parser(clap::value_parser!(u64))
                        .help("Wait timeout in seconds (1..=300)"),
                )
                .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
        ),
    )
}

fn run_external(args: &[OsString]) -> io::Result<u8> {
    let json = crate::grammar::json_requested(args);
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let matches = match external_command().try_get_matches_from(args) {
        Ok(m) => m,
        Err(err) => {
            if matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                let _ = write!(stdout, "{err}");
                return Ok(0);
            }
            let se_err = crate::grammar::usage_error(err, args);
            return crate::render::error::write(
                &se_err,
                &RenderCx::default(),
                json,
                &mut stdout,
                &mut stderr,
            );
        }
    };
    let Some(ext) = matches.subcommand_matches("external") else {
        return Ok(2);
    };
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

fn run_msg_wait(args: &[OsString]) -> io::Result<u8> {
    let json = crate::grammar::json_requested(args);
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let matches = match msg_wait_command().try_get_matches_from(args) {
        Ok(m) => m,
        Err(err) => {
            if matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                let _ = write!(stdout, "{err}");
                return Ok(0);
            }
            let se_err = crate::grammar::usage_error(err, args);
            return crate::render::error::write(
                &se_err,
                &RenderCx::default(),
                json,
                &mut stdout,
                &mut stderr,
            );
        }
    };
    let Some(wait) = matches
        .subcommand_matches("msg")
        .and_then(|m| m.subcommand_matches("wait"))
    else {
        return Ok(2);
    };
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
        let out = send_wait_request(
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
        } else if waited.ids.is_empty() {
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
    se_core::admission::require_human_terminal(
        "external seat control",
        &caller.admission,
        &caller.terminal,
    )?;
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

fn send_wait_request(
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
    if let Some(id) = explicit {
        return id.parse::<ProjectId>().map(Some);
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
