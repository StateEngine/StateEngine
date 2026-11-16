//! Independent native witness: quiet SSH forwards leave public host work available.
#![cfg(windows)]
use se_host::*;
use se_store::*;
use serde_json::{Value, json};
use std::{num::NonZeroU16, path::Path, process::Stdio};
#[path = "../../se-host/tests/support/wave2_host_fixture.rs"]
mod support;
use support::*;

#[test]
fn quiet_forwards_leave_host_workers_available() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let (mut writer, lease) = direct(&f)?;
    let now = now()?;
    let mut clients = Vec::new();
    for index in 0..1 {
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
    let count: usize = std::env::var("SE_WITNESS_FORWARD_COUNT")?.parse()?;
    require(
        matches!(count, 0 | 2),
        "witness accepts zero or two forwards",
    )?;
    let diagnostics = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/forward-witness");
    std::fs::create_dir_all(&diagnostics)?;
    let input_path = f.home.join("synthetic-probe-input.json");
    std::fs::write(
        &input_path,
        serde_json::to_vec(&json!({"client":clients[0], "forward_count": count}))?,
    )?;
    let config = se_config::config_policy::ConfigFile::default();
    let workers = config
        .runtime
        .resolve_blocking_jobs(std::thread::available_parallelism().ok())?;
    require(
        workers.get() == 2,
        "witness requires the actual two-worker default",
    )?;
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    engine.block_on(async {
        let mut settings = start(&f)?;
        settings.writer.maximum_requests = NonZeroU16::new(16).ok_or("group bound")?;
        settings.writer.queue_requests = NonZeroU16::new(64).ok_or("queue bound")?;
        settings.limits.sessions = positive(8)?;
        settings.limits.active_connections = positive(64)?;
        settings.limits.preauth_connections = positive(32)?;
        settings.limits.blocking_jobs = workers;
        let mut host =
            HostedRuntime::prepare(initialized, settings, engine.handle().clone(), &bound()?)
                .await?;
        host.configure(config)?;
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
        require(reconciliation.unproved.is_empty(), "fresh witness has reconciliation debt")?;
        let listener = host.listen(engine.handle().clone(), &bound()?).await?;
        let stop = host.local_stop();
        let client = async {
            let forwards = se_host::remote::ssh::Forwards::default();
            let result = async {
                let mut configurations = Vec::new();
                for index in 0..count {
                    let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
                    let local = reservation.local_addr()?;
                    drop(reservation);
                    let config = se_host::remote::ssh::ForwardConfig {
                        destination: "forward-witness".into(),
                        local,
                        remote_port: 9,
                        command: "unused-in-pipe-lifetime-witness".into(),
                        host: se_types::remote::RemoteHostId(se_types::Sha256::from_bytes([index as u8 + 1;32])),
                    };
                    require(forwards.activate(config.clone()).await? == local, "forward listener changed")?;
                    configurations.push(config);
                }
                std::fs::write(diagnostics.join("forwards.json"), serde_json::to_vec_pretty(&configurations)?)?;
                // Let the two stderr readers settle before the independent process calls IPC.
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                observe(&f.options.state_directory, &input_path, &diagnostics).await
            }.await;
            // Closing forwards releases their native pipes before host drain. Every path joins
            // those exact owned children, including a refused or timed-out public request.
            let closed = forwards.close().await;
            stop.request();
            std::fs::write(diagnostics.join("forward-close.json"), serde_json::to_vec_pretty(
                &json!({"closed":closed.is_ok(), "error":closed.as_ref().err().map(ToString::to_string)})
            )?)?;
            result?;
            closed?;
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        let storage_closed = matches!(&report.storage, se_types::Read::Present { value }
            if value.writer_joined && value.pending.is_empty()
                && matches!(&value.checkpoint, se_types::Read::Present { value }
                    if !value.busy && value.checkpointed_frames == value.wal_frames)
                && matches!(&value.backup, se_types::Read::Present { .. }));
        std::fs::write(diagnostics.join("shutdown.json"), serde_json::to_vec_pretty(&json!({
            "storage_closed":storage_closed, "transport_closed":report.transport_closed,"endpoint_retired":report.endpoint_retired,
            "pending":report.pending,"errors":report.errors.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "storage":format!("{:?}",report.storage)
        }))?)?;
        result?;
        require(storage_closed && report.transport_closed && report.endpoint_retired
            && report.pending.is_empty() && report.errors.is_empty(),
            "host did not prove native closure")
    })
}

async fn observe(home: &Path, input: &Path, diagnostics: &Path) -> Check {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // No Tokio child pipe reader or writer may occupy the host's finite pool.
    let mut child = tokio::process::Command::new("python")
        .arg(root.join("crates/se/tests/forward_worker_probe.py"))
        .arg("--se")
        .arg(env!("CARGO_BIN_EXE_se"))
        .arg("--home")
        .arg(home)
        .stdin(Stdio::from(std::fs::File::open(input)?))
        .stdout(Stdio::from(std::fs::File::create(
            diagnostics.join("probe.json"),
        )?))
        .stderr(Stdio::from(std::fs::File::create(
            diagnostics.join("probe.stderr"),
        )?))
        .kill_on_drop(true)
        .spawn()?;
    let status = child.wait().await?;
    require(
        status.success(),
        "independent probe could not classify its observation",
    )?;
    let report: Value = serde_json::from_slice(&std::fs::read(diagnostics.join("probe.json"))?)?;
    require(
        report["qualified"] == true,
        "independent probe is unqualified",
    )
}
