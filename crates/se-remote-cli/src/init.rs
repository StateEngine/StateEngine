//! Owner-driven one-command remote setup (`se remote init`).
//!
//! Composes existing verified SSH image staging, machine pairing, remote
//! `se init --repo`, optional agent registration, and opt-in `--allow-launch`
//! consent with honest partial-failure reporting across every phase.
use crate::{OwnerCommands, Presentation, invalid, pair, progress, required, text};
use clap::ArgMatches;
use se_core::ops::{IdentityOutcome, InitOutcome};
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
    #[serde(skip_serializing)]
    remedy: Option<String>,
    #[serde(skip_serializing)]
    requested_agent: Option<String>,
    #[serde(skip_serializing)]
    requested_allow_launch: bool,
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
        || path.contains('"')
        || path.ends_with('\\')
        || path.contains("\\ ")
        || path.contains("\\\t")
    {
        return Err(SeError::invalid(
            "remote path",
            "a non-empty path without NUL, control characters, double quotes, or trailing/space-escaped backslashes (at most 4096 bytes)",
        ));
    }
    Ok(())
}

pub fn validate_agent_name(agent: &str) -> Result<()> {
    if agent.is_empty()
        || agent.len() > 64
        || agent.starts_with('-')
        || !agent
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(SeError::invalid(
            "remote agent name",
            "1..64 ASCII letters, digits, hyphens, or underscores, not starting with '-'",
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
    Ok(exit_code_for(&report))
}

fn exit_code_for(report: &InitReport) -> u8 {
    if report.complete {
        0
    } else if report
        .phases
        .iter()
        .any(|phase| matches!(phase.status, "ok" | "reused"))
    {
        2
    } else {
        1
    }
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

fn execute<H: OwnerCommands + Presentation + 'static>(
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
        remedy: None,
        requested_agent: args.agent.clone(),
        requested_allow_launch: args.allow_launch,
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => {
            fail_phase(
                host,
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

async fn run_phases<H: OwnerCommands + Presentation + 'static>(
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
            fail_phase(host, report, "init_remote_project", &err);
            return;
        }
    };
    // Record the proved remote project receipt before validating any optional
    // worker mismatch so partial progress is never lost.
    record_remote_project_receipt(report, &remote);
    if let Some(worker) = args.agent.as_deref()
        && remote.agent_name != worker
    {
        let err = SeError::invalid(
            "remote agent registration",
            &format!(
                "remote init returned agent '{}' instead of requested '{worker}'",
                remote.agent_name.escape_debug()
            ),
        );
        fail_phase(host, report, "init_remote_project", &err);
        return;
    }
    record_remote_agent_and_phase(report, &remote);

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
            fail_phase(host, report, "grant_launch_permission", &err);
        }
    }
}

async fn stage_and_pair<H: OwnerCommands + Presentation + 'static>(
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
        fail_phase(host, report, "prepare_local", &err);
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
            fail_phase(host, report, "stage_image", &err);
            return None;
        }
    };
    if let Err(err) = prepare_image(&args.destination, &dist_path, cancelled, progress).await {
        fail_phase(host, report, "stage_image", &err);
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
            fail_phase(host, report, "pair_machine", &err);
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
    let repo_flag = format!("--repo={remote_path}");
    let agent_flag = agent.map(|worker| format!("--agent={worker}"));
    let mut init_args: Vec<&str> = vec!["init", &repo_flag, "--json"];
    if let Some(flag) = agent_flag.as_deref() {
        init_args.push(flag);
    }
    let stdout = run_verified_se_command(destination, distribution, &init_args).await?;
    parse_init_envelope(&stdout)
}

fn parse_init_envelope(bytes: &[u8]) -> Result<RemoteProjectInit> {
    #[derive(serde::Deserialize)]
    struct InitEnvelope {
        schema: String,
        outcome: InitOutcome,
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
        outcome: IdentityOutcome,
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
        project_reused: matches!(env.outcome, InitOutcome::AlreadyPresent),
        agent_reused: matches!(env.agent.outcome, IdentityOutcome::Existing),
    })
}

fn record_remote_project_receipt(report: &mut InitReport, remote: &RemoteProjectInit) {
    report.project = Some(serde_json::json!({
        "id": remote.project_id,
        "name": remote.project_name,
        "root": remote.project_root,
        "reused": remote.project_reused,
    }));
}

fn record_remote_agent_and_phase(report: &mut InitReport, remote: &RemoteProjectInit) {
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
            remote.project_name.escape_debug(),
            remote.project_id,
            remote.agent_name.escape_debug(),
            remote.agent_id
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
    let receipt = pair::request(
        host,
        context,
        OwnerInput::PairingLaunchPermissions {
            alias: alias.to_owned(),
            after: None,
            change: Some(LaunchPermissionChange {
                target: target.clone(),
                allowed: true,
                expected_revision,
                key,
            }),
        },
        Arc::clone(cancelled),
    )
    .await?;
    verify_grant_receipt(&receipt.value, &target)?;
    Ok(false)
}

fn verify_grant_receipt(value: &serde_json::Value, expected: &RemoteTarget) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct ChangedReceipt {
        permission: PermissionPart,
        state: String,
    }
    #[derive(serde::Deserialize)]
    struct PermissionPart {
        target: RemoteTarget,
        allowed: bool,
    }
    let changed: ChangedReceipt =
        serde_json::from_value(value["changed"].clone()).map_err(|_| {
            SeError::invalid(
                "launch consent receipt",
                "a committed or replayed `changed` permission receipt from the destination",
            )
        })?;
    if changed.permission.target != *expected
        || !changed.permission.allowed
        || !matches!(changed.state.as_str(), "committed" | "replayed")
    {
        return Err(SeError::invalid(
            "launch consent receipt",
            "a confirmed allowed launch permission receipt for the requested target",
        ));
    }
    Ok(())
}

fn fail_phase<H: Presentation>(
    host: &H,
    report: &mut InitReport,
    phase: &'static str,
    error: &SeError,
) {
    let escaped = se_types::ErrorEnvelope::new(error.body.clone(), &se_types::RenderCx::default())
        .ok()
        .map(|env| host.escape_far_text(env));
    let detail = escaped
        .as_ref()
        .map(|env| env.message().to_owned())
        .unwrap_or_else(|| error.to_string().escape_debug().to_string());
    let remedy = escaped.as_ref().map(|env| env.remedy().text.clone());
    let error_json = escaped
        .and_then(|env| serde_json::to_value(env).ok())
        .or_else(|| Some(serde_json::json!({"message": detail})));
    report.phases.push(PhaseReport {
        phase,
        status: "failed",
        detail,
    });
    report.remedy = remedy;
    report.error = error_json;
}

fn sanitize_terminal_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() {
            out.extend(ch.escape_debug());
        } else {
            out.push(ch);
        }
    }
    out
}

fn write_human(report: &InitReport, out: &mut impl Write) -> io::Result<()> {
    let alias = sanitize_terminal_text(&report.alias);
    let destination = sanitize_terminal_text(&report.destination);
    let remote_path = sanitize_terminal_text(&report.remote_path);
    if report.complete {
        writeln!(
            out,
            "Initialized remote '{alias}' ({destination}:{remote_path})."
        )?;
        for phase in &report.phases {
            writeln!(
                out,
                "  [{}] {}: {}",
                phase.status,
                phase.phase,
                sanitize_terminal_text(&phase.detail)
            )?;
        }
        writeln!(out, "Next: se remote list --host {alias}")?;
    } else {
        let partial = report
            .phases
            .iter()
            .any(|p| matches!(p.status, "ok" | "reused"));
        let headline = if partial {
            "stopped with partial progress"
        } else {
            "failed before completing any phase"
        };
        writeln!(
            out,
            "Remote init for '{alias}' ({destination}:{remote_path}) {headline}:"
        )?;
        for phase in &report.phases {
            writeln!(
                out,
                "  [{}] {}: {}",
                phase.status,
                phase.phase,
                sanitize_terminal_text(&phase.detail)
            )?;
        }
        if let Some(remedy) = report.remedy.as_deref().filter(|r| !r.is_empty()) {
            writeln!(out, "Remedy: {}", sanitize_terminal_text(remedy))?;
        }
        writeln!(
            out,
            "Next: resolve the reported error, then rerun `{}` to continue.",
            format_rerun_command(report)
        )?;
    }
    Ok(())
}

fn quote_rerun_arg(value: &str) -> String {
    let safe = !value.is_empty()
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'\\')
        });
    if safe {
        value.to_owned()
    } else {
        se_host::remote::ssh::posix_single_quote(value)
    }
}

fn format_rerun_command(report: &InitReport) -> String {
    let target = format!(
        "{}:{}",
        sanitize_terminal_text(&report.destination),
        sanitize_terminal_text(&report.remote_path)
    );
    let mut cmd = format!(
        "se remote init {} --alias {}",
        quote_rerun_arg(&target),
        sanitize_terminal_text(&report.alias)
    );
    if let Some(agent) = report.requested_agent.as_deref() {
        cmd.push_str(&format!(" --agent {}", sanitize_terminal_text(agent)));
    }
    if report.requested_allow_launch {
        cmd.push_str(" --allow-launch");
    }
    cmd
}

#[cfg(test)]
mod tests;
