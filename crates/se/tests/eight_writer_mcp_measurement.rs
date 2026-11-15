//! Development observer for writes through eight kept-open public MCP doors.
use se_host::*;
use se_store::*;
use serde_json::{Value, json};
use std::{num::NonZeroU16, path::Path, process::Stdio};
use tokio::io::AsyncWriteExt;
#[path = "../../se-host/tests/support/wave2_host_fixture.rs"]
mod support;
use support::*;

#[test]
fn measure_eight_mcp_writers() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let (mut writer, lease) = direct(&f)?;
    let now = now()?;
    let mut clients = Vec::new();
    for index in 0..8 {
        let agent = agent()?;
        let session = support::session::session()?;
        let capability = format!("sec1.{session}.{}", "A".repeat(43));
        let issued = credential(
            &session,
            "session",
            &capability,
            now + 600_000_000,
            now + 60_000_000,
        )?;
        let EventBody::CredentialIssued { credential: id, .. } = &issued else {
            return Err("credential shape".into());
        };
        let id = *id;
        writer.append(
            f.batch(
                f.owner_project(),
                Some(fixture::request(&format!("mcp-measurement-{index}"))?),
                vec![
                    EventBody::PrincipalRegistered {
                        principal: Actor::Agent(agent.clone()),
                        kind: PrincipalKind::Agent,
                        owner: f.owner.clone(),
                        created_by: None,
                        name: format!("Writer {index}"),
                        role: "builder".into(),
                        expected: Expected::Absent,
                    },
                    EventBody::ProfileSaved {
                        agent: agent.clone(),
                        profile: Profile {
                            provider: Provider::Claude,
                            model: None,
                            harness: None,
                            permission: PermissionProfile::WorkspaceWrite,
                            named_profile: "default".into(),
                            effort: None,
                        },
                        expected: Expected::Absent,
                    },
                    support::session::prepared(&f, &session, &agent),
                    support::session::activated(&session)?,
                    issued,
                    EventBody::CredentialActivated {
                        credential: id,
                        session: session.clone(),
                        expected: revision(1)?,
                        first_request: support::session::record()?,
                    },
                ],
            )?,
            &*lease,
        )?;
        clients.push(json!({"capability": capability, "to": agent.as_str()}));
    }
    writer.close()?;
    drop(lease);
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(8)
        .build()?;
    engine.block_on(async {
        let mut settings = start(&f)?;
        settings.writer.maximum_requests = NonZeroU16::new(16).ok_or("group bound")?;
        settings.writer.queue_requests = NonZeroU16::new(64).ok_or("queue bound")?;
        settings.limits.sessions = positive(8)?;
        settings.limits.active_connections = positive(64)?;
        settings.limits.preauth_connections = positive(32)?;
        settings.limits.blocking_jobs = se_config::config_policy::ConfigFile::default()
            .runtime
            .resolve_blocking_jobs(std::thread::available_parallelism().ok())?;
        settings.limits.session_notice_ids = positive(128)?;
        settings.limits.aggregate_notice_ids = positive(4096)?;
        let mut host =
            HostedRuntime::prepare(initialized, settings, engine.handle().clone(), &bound()?)
                .await?;
        host.configure(se_config::config_policy::ConfigFile::default())?;
        let (_coordinator, reconciliation) = LaunchCoordinator::install(
            &mut host,
            ProcessOptions {
                helper_executable: se_types::NativePath::from_local(
                    Path::new(env!("CARGO_BIN_EXE_se")).to_path_buf(),
                )?,
                linux_delegation: se_proc::LinuxDelegation::CurrentScope,
                maximum_sessions: 8,
            },
            &bound()?,
        )
        .await?;
        require(
            reconciliation.unproved.is_empty(),
            "fresh observer has native reconciliation debt",
        )?;
        let listener = host.listen(engine.handle().clone(), &bound()?).await?;
        let stop = host.local_stop();
        let client = async {
            let result = observe(&f.options.state_directory, &clients).await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        result?;
        require(
            report.transport_closed
                && report.endpoint_retired
                && report.pending.is_empty()
                && report.errors.is_empty(),
            format!(
                "observer shutdown incomplete: {:?}, {:?}",
                report.pending, report.errors
            ),
        )
    })
}

async fn observe(home: &Path, clients: &[Value]) -> Check {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut child = tokio::process::Command::new("python3")
        .arg(root.join("crates/se/tests/kept_open_writes.py"))
        .arg("--se")
        .arg(env!("CARGO_BIN_EXE_se"))
        .arg("--home")
        .arg(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().ok_or("observer input absent")?;
    input
        .write_all(&serde_json::to_vec(&json!({"clients":clients}))?)
        .await?;
    drop(input);
    let output = child.wait_with_output().await?;
    let path = root.join("target/judge-diagnostics");
    std::fs::create_dir_all(&path)?;
    std::fs::write(path.join("mcp-writers.json"), &output.stdout)?;
    std::fs::write(path.join("mcp-writers.stderr"), &output.stderr)?;
    let report: Value = serde_json::from_slice(&output.stdout)?;
    let cohorts = report["cohorts"]
        .as_object()
        .ok_or("observer cohorts absent")?;
    for (count, clients) in cohorts {
        for (index, client) in clients
            .as_array()
            .ok_or("client observations absent")?
            .iter()
            .enumerate()
        {
            require(
                client.get("error").is_none() && client.get("cleanup_error").is_none(),
                format!("cohort {count} client {index} failed: {client}"),
            )?;
            require(
                client["verified_events"] == 60,
                "outside event readback missing",
            )?;
            println!("cohort {count} client {index} p95: {}", client["p95_ms"]);
        }
    }
    // The observer retains misses as measured values. Budget judgment belongs
    // to the independent review; an absent or failed write still fails here.
    require(
        output
            .status
            .code()
            .is_some_and(|code| code == 0 || code == 1),
        "observer did not return a measurement verdict",
    )
}
