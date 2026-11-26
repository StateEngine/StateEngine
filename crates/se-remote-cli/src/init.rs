//! Owner-driven one-command remote setup (`se remote init`).
//!
//! Composes existing verified SSH image staging, machine pairing, remote
//! `se init --repo`, optional agent registration, and opt-in `--allow-launch`
//! consent with honest partial-failure reporting across every phase.
use crate::{OwnerCommands, Presentation, invalid, pair, progress, required, text};
use clap::ArgMatches;
use se_host::remote::{
    LaunchPermissionChange, OwnerInput,
    ssh::{prepare_image, run_verified_se_command, validate_destination},
};
use se_store::remote::LaunchCandidate;
use se_types::{
    AgentId, IdempotencyKey, NativePath, ProjectId, Read, Result, SeError, remote::RemoteTarget,
};
use serde::Serialize;
use std::{
    io::{self, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct RemoteProjectInit {
    project_id: ProjectId,
    project_name: String,
    project_root: String,
    agent_id: AgentId,
    agent_name: String,
    project_reused: bool,
    agent_reused: bool,
}

#[derive(Clone, Debug, Serialize)]
struct PhaseReport {
    phase: &'static str,
    status: &'static str,
    detail: String,
}

#[derive(Debug, Serialize)]
struct InitReport {
    complete: bool,
    alias: String,
    destination: String,
    remote_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<serde_json::Value>,
    launch_allowed: bool,
    phases: Vec<PhaseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<serde_json::Value>,
}

struct InitArgs {
    destination: String,
    remote_path: String,
    alias: String,
    agent: Option<String>,
    allow_launch: bool,
    distribution: NativePath,
}

/// Parse `<host>:<remote-path>` safely, supporting IPv6 literals (`[::1]:/path`),
/// `user@host:/path`, SSH aliases (`build:/srv/repo`), and Windows drive paths
/// (`winhost:C:\repo`).
pub fn parse_remote_spec(spec: &str) -> Result<(String, String)> {
    let (host, remote_path) = if let Some(rest) = spec.strip_prefix('[') {
        let Some((addr, after)) = rest.split_once("]:") else {
            return Err(SeError::invalid(
                "remote target",
                "<host>:<remote-path> (for IPv6 use [addr]:<remote-path>)",
            ));
        };
        (format!("[{addr}]"), after)
    } else {
        let Some((host, path)) = spec.split_once(':') else {
            return Err(SeError::invalid(
                "remote target",
                "<host>:<remote-path> separated by ':'",
            ));
        };
        (host.to_owned(), path)
    };
    validate_destination(&host)?;
    validate_remote_path(remote_path)?;
    Ok((host, remote_path.to_owned()))
}

pub fn validate_remote_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 4096
        || path.bytes().any(|b| b == 0)
        || path.chars().any(char::is_control)
    {
        return Err(SeError::invalid(
            "remote path",
            "a non-empty path without NUL or control characters (at most 4096 bytes)",
        ));
    }
    Ok(())
}

pub fn validate_agent_name(agent: &str) -> Result<()> {
    if agent.is_empty()
        || agent.len() > 64
        || !agent
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(SeError::invalid(
            "remote agent name",
            "1..64 ASCII letters, digits, hyphens, or underscores",
        ));
    }
    Ok(())
}

/// Derive a safe local machine alias when `--alias` is omitted.
pub fn derive_alias(destination: &str) -> Result<String> {
    let host = destination
        .rsplit_once('@')
        .map_or(destination, |(_, h)| h)
        .trim_matches(['[', ']']);
    let mut candidate = String::with_capacity(host.len());
    for byte in host.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-') {
            candidate.push(byte as char);
        } else {
            candidate.push('-');
        }
    }
    let trimmed = candidate.trim_matches('-').to_owned();
    se_core::ops::remote::validate_alias(&trimmed).map_err(|_| {
        SeError::invalid(
            "remote alias",
            "pass `--alias NAME` (1..64 ASCII letters, digits, '_' or '-')",
        )
    })?;
    Ok(trimmed)
}

pub(crate) fn run<H: OwnerCommands + Presentation + 'static>(
    m: &ArgMatches,
    json: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    host: &'static H,
) -> io::Result<u8> {
    let parsed = (|| -> Result<(InitArgs, H::Context)> {
        if m.get_flag("version") || m.get_one::<String>("project").is_some() {
            return Err(invalid(
                "remote controls accept --home, not --project or --version",
            ));
        }
        if text(m, "key").is_some() {
            return Err(invalid("this machine control has no mutation-key argument"));
        }
        let args = decode_args(m)?;
        let cx = host.resolve_owner(
            text(m, "home").map(Into::into),
            m.get_flag("no_color"),
            json,
        )?;
        Ok((args, cx))
    })();
    let (args, cx) = match parsed {
        Ok(pair) => pair,
        Err(error) => {
            return host.write_error(&error, &se_types::RenderCx::default(), json, stdout, stderr);
        }
    };

    let report = execute(host, &cx, args, &mut |event| {
        progress::write(event, json, stderr)
    });

    if json {
        serde_json::to_writer(
            &mut *stdout,
            &serde_json::json!({"schema": "stateengine.remote-init/v1", "value": report}),
        )
        .map_err(io::Error::other)?;
        writeln!(stdout)?;
    } else {
        write_human(&report, stdout)?;
    }
    stdout.flush()?;
    Ok(if report.complete { 0 } else { 1 })
}

fn decode_args(m: &ArgMatches) -> Result<InitArgs> {
    let target = required(m, "target")?;
    let (destination, remote_path) = parse_remote_spec(&target)?;
    let alias = match text(m, "alias") {
        Some(explicit) => {
            se_core::ops::remote::validate_alias(&explicit)?;
            explicit
        }
        None => derive_alias(&destination)?,
    };
    let agent = text(m, "agent");
    if let Some(worker) = agent.as_deref() {
        validate_agent_name(worker)?;
    }
    let distribution = NativePath::from_local(
        std::env::current_exe().map_err(|_| invalid("a readable native distribution path"))?,
    )?;
    Ok(InitArgs {
        destination,
        remote_path,
        alias,
        agent,
        allow_launch: m.get_flag("allow_launch"),
        distribution,
    })
}

fn execute<H: OwnerCommands + 'static>(
    host: &'static H,
    context: &H::Context,
    args: InitArgs,
    progress: &mut dyn FnMut(se_host::remote::ssh::ImageProgress) -> Result<()>,
) -> InitReport {
    let mut report = InitReport {
        complete: false,
        alias: args.alias.clone(),
        destination: args.destination.clone(),
        remote_path: args.remote_path.clone(),
        host: None,
        project: None,
        agent: None,
        launch_allowed: false,
        phases: Vec::new(),
        error: None,
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => {
            fail_phase(
                &mut report,
                "prepare_local",
                &SeError::invalid("remote setup", "an available native I/O runtime"),
            );
            return report;
        }
    };

    runtime.block_on(async {
        let cancelled = Arc::new(AtomicBool::new(false));
        let interrupted = pair::interruption();
        let work = run_phases(host, context, &args, &cancelled, progress, &mut report);
        tokio::pin!(work);
        match interrupted {
            Ok(sig) => {
                tokio::pin!(sig);
                tokio::select! {
                    biased;
                    () = &mut work => {}
                    _ = &mut sig => {
                        cancelled.store(true, Ordering::Release);
                        work.await;
                    }
                }
            }
            Err(_) => work.await,
        }
    });

    report
}

async fn run_phases<H: OwnerCommands + 'static>(
    host: &'static H,
    context: &H::Context,
    args: &InitArgs,
    cancelled: &Arc<AtomicBool>,
    progress: &mut dyn FnMut(se_host::remote::ssh::ImageProgress) -> Result<()>,
    report: &mut InitReport,
) {
    let Some(dist_path) = stage_and_pair(host, context, args, cancelled, progress, report).await
    else {
        return;
    };
    let remote = match init_remote_project(
        &args.destination,
        &dist_path,
        &args.remote_path,
        args.agent.as_deref(),
    )
    .await
    {
        Ok(info) => info,
        Err(err) => {
            fail_phase(report, "init_remote_project", &err);
            return;
        }
    };
    record_remote_project(report, &remote);

    if !args.allow_launch {
        report.phases.push(PhaseReport {
            phase: "grant_launch_permission",
            status: "skipped",
            detail: format!(
                "not requested; run `se remote permissions --name {} --launch` to grant later",
                args.alias
            ),
        });
        report.complete = true;
        return;
    }

    match grant_launch_consent(host, context, &args.alias, &remote, cancelled).await {
        Ok(reused_grant) => {
            report.launch_allowed = true;
            report.phases.push(PhaseReport {
                phase: "grant_launch_permission",
                status: if reused_grant { "reused" } else { "ok" },
                detail: format!(
                    "launch consent active for {}/{}",
                    remote.project_id, remote.agent_id
                ),
            });
            report.complete = true;
        }
        Err(err) => {
            fail_phase(report, "grant_launch_permission", &err);
        }
    }
}

async fn stage_and_pair<H: OwnerCommands + 'static>(
    host: &'static H,
    context: &H::Context,
    args: &InitArgs,
    cancelled: &Arc<AtomicBool>,
    progress: &mut dyn FnMut(se_host::remote::ssh::ImageProgress) -> Result<()>,
    report: &mut InitReport,
) -> Option<std::path::PathBuf> {
    if let Err(err) = pair::request(
        host,
        context,
        OwnerInput::PrepareAdd {
            destination: args.destination.clone(),
            alias: args.alias.clone(),
        },
        Arc::clone(cancelled),
    )
    .await
    {
        fail_phase(report, "prepare_local", &err);
        return None;
    }
    report.phases.push(PhaseReport {
        phase: "prepare_local",
        status: "ok",
        detail: format!("verified local owner and alias '{}'", args.alias),
    });

    let dist_path = match args.distribution.to_local() {
        Ok(path) => path,
        Err(err) => {
            fail_phase(report, "stage_image", &err);
            return None;
        }
    };
    if let Err(err) = prepare_image(&args.destination, &dist_path, cancelled, progress).await {
        fail_phase(report, "stage_image", &err);
        return None;
    }
    report.phases.push(PhaseReport {
        phase: "stage_image",
        status: "ok",
        detail: "verified remote StateEngine executable over SSH".into(),
    });

    let paired = match pair::request(
        host,
        context,
        OwnerInput::Add {
            destination: args.destination.clone(),
            alias: args.alias.clone(),
            distribution: args.distribution.clone(),
        },
        Arc::clone(cancelled),
    )
    .await
    {
        Ok(output) => output,
        Err(err) => {
            fail_phase(report, "pair_machine", &err);
            return None;
        }
    };
    let reused = paired.value["reused"].as_bool() == Some(true);
    report.host = Some(paired.value["host"].clone());
    report.phases.push(PhaseReport {
        phase: "pair_machine",
        status: if reused { "reused" } else { "ok" },
        detail: format!(
            "saved binding '{}' ({})",
            args.alias,
            if reused { "reused" } else { "new" }
        ),
    });
    Some(dist_path)
}

async fn init_remote_project(
    destination: &str,
    distribution: &Path,
    remote_path: &str,
    agent: Option<&str>,
) -> Result<RemoteProjectInit> {
    let mut init_args = vec!["init", "--repo", remote_path, "--json"];
    if let Some(worker) = agent {
        init_args.extend(["--agent", worker]);
    }
    let stdout = run_verified_se_command(destination, distribution, &init_args).await?;
    let mut result = parse_init_envelope(&stdout)?;
    if let Some(worker) = agent
        && result.agent_name != worker
    {
        let project_id = result.project_id.to_string();
        let (agent_id, agent_reused) =
            ensure_remote_agent(destination, distribution, &project_id, worker).await?;
        result.agent_id = agent_id;
        result.agent_name = worker.to_owned();
        result.agent_reused = agent_reused;
    }
    Ok(result)
}

async fn ensure_remote_agent(
    destination: &str,
    distribution: &Path,
    project_id: &str,
    worker: &str,
) -> Result<(AgentId, bool)> {
    let add_args = ["--project", project_id, "agent", "add", worker, "--json"];
    match run_verified_se_command(destination, distribution, &add_args).await {
        Ok(stdout) => {
            #[derive(serde::Deserialize)]
            struct Envelope {
                agent: Ref,
            }
            #[derive(serde::Deserialize)]
            struct Ref {
                id: AgentId,
            }
            let receipt: Envelope = serde_json::from_slice(&stdout)
                .map_err(|_| SeError::invalid("remote agent add", "a compatible JSON receipt"))?;
            Ok((receipt.agent.id, false))
        }
        Err(err) if err.code() == se_types::Code::AgentNameConflict => {
            let show_args = ["--project", project_id, "agent", "show", worker, "--json"];
            let stdout = run_verified_se_command(destination, distribution, &show_args).await?;
            let value: serde_json::Value = serde_json::from_slice(&stdout)
                .map_err(|_| SeError::invalid("remote agent show", "a compatible JSON response"))?;
            let id_str = value
                .pointer("/agent/value/id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| SeError::invalid("remote agent show", "an agent id"))?;
            let agent_id: AgentId = id_str
                .parse()
                .map_err(|_| SeError::invalid("remote agent show", "a valid agent id"))?;
            Ok((agent_id, true))
        }
        Err(err) => Err(err),
    }
}

fn parse_init_envelope(bytes: &[u8]) -> Result<RemoteProjectInit> {
    #[derive(serde::Deserialize)]
    struct InitEnvelope {
        schema: String,
        outcome: String,
        project: ProjectPart,
        agent: AgentPart,
    }
    #[derive(serde::Deserialize)]
    struct ProjectPart {
        id: ProjectId,
        name: String,
        root: String,
    }
    #[derive(serde::Deserialize)]
    struct AgentPart {
        id: AgentId,
        name: String,
        outcome: String,
    }
    let env: InitEnvelope = serde_json::from_slice(bytes)
        .map_err(|_| SeError::invalid("remote init", "a compatible se.init/v1 JSON response"))?;
    if env.schema != "se.init/v1" {
        return Err(SeError::invalid("remote init", "schema se.init/v1"));
    }
    Ok(RemoteProjectInit {
        project_id: env.project.id,
        project_name: env.project.name,
        project_root: env.project.root,
        agent_id: env.agent.id,
        agent_name: env.agent.name,
        project_reused: env.outcome == "already-present",
        agent_reused: env.agent.outcome == "existing",
    })
}

fn record_remote_project(report: &mut InitReport, remote: &RemoteProjectInit) {
    report.project = Some(serde_json::json!({
        "id": remote.project_id,
        "name": remote.project_name,
        "root": remote.project_root,
        "reused": remote.project_reused,
    }));
    report.agent = Some(serde_json::json!({
        "id": remote.agent_id,
        "name": remote.agent_name,
        "reused": remote.agent_reused,
    }));
    report.phases.push(PhaseReport {
        phase: "init_remote_project",
        status: if remote.project_reused {
            "reused"
        } else {
            "ok"
        },
        detail: format!(
            "project {} ({}) with agent {} ({})",
            remote.project_name, remote.project_id, remote.agent_name, remote.agent_id
        ),
    });
}

async fn grant_launch_consent<H: OwnerCommands + 'static>(
    host: &'static H,
    context: &H::Context,
    alias: &str,
    remote: &RemoteProjectInit,
    cancelled: &Arc<AtomicBool>,
) -> Result<bool> {
    let target = RemoteTarget {
        project: remote.project_id.clone(),
        agent: remote.agent_id.clone(),
    };
    let mut after = None;
    let candidate = loop {
        let output = pair::request(
            host,
            context,
            OwnerInput::PairingLaunchPermissions {
                alias: alias.to_owned(),
                after: after.clone(),
                change: None,
            },
            Arc::clone(cancelled),
        )
        .await?;
        let targets: Vec<LaunchCandidate> = serde_json::from_value(output.value["targets"].clone())
            .map_err(|_| {
                SeError::invalid(
                    "launch pairing permissions",
                    "a compatible destination agent inventory",
                )
            })?;
        if let Some(found) = targets.into_iter().find(|c| c.target == target) {
            break found;
        }
        if output.value["more"] != true {
            return Err(SeError::invalid(
                "launch pairing permissions",
                "the initialized remote agent to appear in destination launch candidates",
            ));
        }
        after = serde_json::from_value(output.value["next"].clone()).map_err(|_| {
            SeError::invalid("launch pairing permissions", "a valid pagination cursor")
        })?;
    };

    let expected_revision = match &candidate.permission {
        Read::Present { value } if value.allowed => return Ok(true),
        Read::Present { value } => Some(value.revision.value.get()),
        Read::Absent { .. } => None,
        _ => {
            return Err(SeError::invalid(
                "launch consent",
                "readable current launch consent on the destination",
            ));
        }
    };

    let key = IdempotencyKey::new(uuid::Uuid::new_v4().to_string())?;
    pair::request(
        host,
        context,
        OwnerInput::PairingLaunchPermissions {
            alias: alias.to_owned(),
            after: None,
            change: Some(LaunchPermissionChange {
                target,
                allowed: true,
                expected_revision,
                key,
            }),
        },
        Arc::clone(cancelled),
    )
    .await?;
    Ok(false)
}

fn fail_phase(report: &mut InitReport, phase: &'static str, error: &SeError) {
    let envelope = se_types::ErrorEnvelope::new(error.body.clone(), &se_types::RenderCx::default())
        .ok()
        .and_then(|env| serde_json::to_value(env).ok());
    report.phases.push(PhaseReport {
        phase,
        status: "failed",
        detail: error.to_string(),
    });
    report.error = envelope.or_else(|| Some(serde_json::json!({"message": error.to_string()})));
}

fn write_human(report: &InitReport, out: &mut impl Write) -> io::Result<()> {
    if report.complete {
        writeln!(
            out,
            "Initialized remote '{}' ({}:{}).",
            report.alias, report.destination, report.remote_path
        )?;
        for phase in &report.phases {
            writeln!(
                out,
                "  [{}] {}: {}",
                phase.status, phase.phase, phase.detail
            )?;
        }
        writeln!(out, "Next: se remote list --host {}", report.alias)?;
    } else {
        writeln!(
            out,
            "Remote init for '{}' ({}:{}) stopped with partial progress:",
            report.alias, report.destination, report.remote_path
        )?;
        for phase in &report.phases {
            writeln!(
                out,
                "  [{}] {}: {}",
                phase.status, phase.phase, phase.detail
            )?;
        }
    }
    Ok(())
}
