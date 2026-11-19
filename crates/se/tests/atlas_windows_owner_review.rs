#![cfg(all(windows, target_arch = "x86_64"))]
#![allow(
    dead_code,
    reason = "The shared fixture includes other store assertions."
)]

#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::{Check, Fixture};
use se_host::{
    ExecutionContext, HostKind, HostLimits, HostStart, HostedRuntime, NativeAtlasQualification,
    client, initialize_host_process,
};
use se_store::{Actor, DirectStore, Door, EventBody, Root, Scope, WriterOptions};
use se_types::{
    HostEpoch, HostGeneration, MachineId, NativePath, ProcessFields, ProcessInstance, ProjectId,
    Read, SeError,
    code::{CoverageReason, IndexSummary},
};
use std::{
    fs,
    io::Write,
    num::{NonZeroU16, NonZeroU32},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

fn number(n: u32) -> Result<NonZeroU32, Box<dyn std::error::Error>> {
    NonZeroU32::new(n).ok_or_else(|| "zero test bound".into())
}

fn deadline() -> Result<client::lease::Deadline, Box<dyn std::error::Error>> {
    Ok(client::lease::Deadline::from_options(
        &client::ClientOptions {
            expected_generation: None,
            timeout: Duration::from_secs(10),
            cancelled: Arc::new(AtomicBool::new(false)),
        },
    )?)
}

fn start(f: &Fixture, generation: u64) -> Result<HostStart, Box<dyn std::error::Error>> {
    let machine = MachineId::new("atlas-native-owner-review")?;
    let native = se_proc::current_runtime_identity(machine.clone())
        .map_err(|e| format!("runtime observation: {e:?}"))?;
    let peer = se_proc::native_ipc::observe_ipc_self()?;
    Ok(HostStart {
        state_directory: f.options.state_directory.clone(),
        channel_delay_us: se_store::CHANNEL_DELAY_US,
        epoch: HostEpoch {
            owner: ProcessInstance::from_observation(ProcessFields {
                machine,
                boot: native.boot_id,
                pid: number(peer.pid())?,
                started: peer.started().clone(),
                executable: peer.image().clone(),
                argv_sha256: se_types::Sha256::from_bytes([0; 32]),
            })?,
            generation: HostGeneration::new(generation)?,
        },
        kind: HostKind::Standalone,
        writer: WriterOptions {
            maximum_requests: NonZeroU16::new(16).ok_or("requests")?,
            queue_requests: NonZeroU16::new(16).ok_or("queue")?,
            resident_bytes: number(1_048_576)?,
            group_bytes: number(1_048_576)?,
        },
        limits: HostLimits {
            sessions: number(2)?,
            active_connections: number(2)?,
            preauth_connections: number(2)?,
            parked_mail_waits: number(2)?,
            resident_queue_bytes: number(1_048_576)?,
            session_notice_ids: number(16)?,
            aggregate_notice_ids: number(32)?,
            response_bytes: number(1_048_576)?,
            blocking_jobs: number(2)?,
        },
    })
}

fn setup(f: &Fixture, root: &Path) -> Check {
    fs::create_dir(root)?;
    fs::write(
        root.join("sample.js"),
        "export function initial_marker() {}",
    )?;
    for args in [
        &["init", "--initial-branch=main"][..],
        &["add", "--", "sample.js"],
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "Synthetic history marker",
        ],
    ] {
        let result = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "NUL")
            .output()?;
        assert!(result.status.success(), "{result:?}");
    }
    let (mut direct, lease) = f.direct()?;
    let mut registration = f.batch(
        f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
        Some(fixture::request("atlas-windows-review-root")?),
        vec![EventBody::ProjectUpdated {
            project: f.project.clone(),
            name: "Synthetic project".into(),
            roots: vec![Root {
                path: NativePath::from_local(root.to_owned())?,
                canonical_key: root.as_os_str().as_encoded_bytes().to_vec(),
            }],
            expected: fixture::revision(1)?,
        }],
    )?;
    for event in &mut registration.events {
        event.header.door = Door::Import;
    }
    direct.append(registration, &*lease)?;
    direct.close()?;
    drop(lease);
    let home = &f.options.state_directory;
    let files = se_proc::NativeStateFiles::open(home)?;
    let mut staged = files.create_staging(home)?;
    staged.file.write_all(&[23; 32])?;
    staged.file.sync_all()?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, &home.join("credential"))?;
    Ok(())
}

const WRITE: &str = "export function renewed_marker() {}";
const OFFLINE: &str = "export function offline_marker() {}";

fn sample(
    context: &ExecutionContext,
    project: &ProjectId,
    marker: &str,
) -> Result<Option<IndexSummary>, Box<dyn std::error::Error>> {
    let Read::Present { value: summary } = context.atlas.status(project, None)? else {
        return Ok(None);
    };
    if summary.epoch.is_none() || !summary.coverage.watch_discovery_complete {
        return Ok(None);
    }
    let mut found = false;
    context
        .atlas
        .with_reader(project, None, None, &mut |connection, _, _| {
            connection.read(Instant::now() + Duration::from_secs(2), |sql| {
                let error =
                    |e: rusqlite::Error| SeError::invalid("Atlas review readback", &e.to_string());
                found = sql
                    .prepare("SELECT EXISTS(SELECT 1 FROM symbols s JOIN names n ON n.id=s.name WHERE n.text=?1)")?
                    .query_row([marker], |row| row.get(0))
                    .map_err(error)?;
                Ok(())
            })
        })?;
    Ok(found.then_some(summary))
}

async fn observe(
    context: &ExecutionContext,
    project: &ProjectId,
    marker: &'static str,
) -> Result<IndexSummary, Box<dyn std::error::Error>> {
    let end = Instant::now() + Duration::from_secs(25);
    while Instant::now() < end {
        let read = context.clone();
        let project = project.clone();
        let result = tokio::task::spawn_blocking(move || {
            sample(&read, &project, marker).map_err(|error| error.to_string())
        })
        .await?;
        match result {
            Ok(Some(summary)) => return Ok(summary),
            Ok(None) => (),
            Err(error) => eprintln!("waiting for {marker}: {error}"),
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }
    Err(format!(
        "never observed {marker}: {:?}",
        context.atlas.status(project, None)
    )
    .into())
}

fn query(
    endpoint: se_host::EndpointRecord,
    project: ProjectId,
) -> Result<se_core::ops::AnyOutput, Box<dyn std::error::Error>> {
    let options = client::ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    let mut connection = client::BlockingIpcClient::connect_authenticated(
        &endpoint,
        client::lease::ClientCredential::Machine(se_types::Secret::new(vec![23; 32])?),
        number(32_768)?,
        &options,
    )?;
    let reply = connection.exchange(
        se_host::IpcEnvelope {
            version: connection.negotiated().version,
            request_id: 1,
            generation: endpoint.generation,
            authority: None,
            presence: None,
            cli_selections: Some(serde_json::to_value(se_core::ops::CliSelections {
                project: Some(project),
                ..Default::default()
            })?),
            request: se_host::IpcRequest::Operation(se_host::RawOperation {
                name: "atlas.find".into(),
                arguments: serde_json::json!({"query":"offline_marker","mode":"exact"}),
                key: None,
            }),
        },
        &options,
    )?;
    let mut output = reply.value;
    output["schema"] = reply.schema.into();
    Ok(serde_json::from_value(output)?)
}

fn assert_history(summary: &IndexSummary) -> Check {
    assert!(
        summary
            .coverage
            .reasons
            .contains(&CoverageReason::HistoryUnavailable)
    );
    let history = summary
        .coverage
        .history_unavailable
        .as_ref()
        .ok_or("history diagnostic absent")?;
    assert!(
        history
            .message()
            .contains("Contained Git history is unavailable"),
        "{history:?}"
    );
    let status = se_core::ops::status::atlas_view(Ok(Read::Present {
        value: summary.clone(),
    }));
    assert_eq!(status.history, "unavailable");
    Ok(())
}

#[test]
fn windows_owner_keeps_source_renewal_and_explains_unavailable_history() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let root = f.home.join("source");
    setup(&f, &root)?;
    let image = std::env::var_os("SE_W3_SE_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_se")))
        .canonicalize()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    let mut observations = Vec::new();
    for generation in 1..=3 {
        let epoch = initialize_host_process()?;
        let bound = deadline()?;
        let host_start = start(&f, generation)?;
        let result = runtime.block_on(async {
            let mut host =
                HostedRuntime::prepare(epoch, host_start, runtime.handle().clone(), &bound).await?;
            host.configure(se_config::config_policy::ConfigFile::default())?;
            let qualification = if generation == 3 {
                NativeAtlasQualification::default()
            } else {
                NativeAtlasQualification::measured_windows_components()?
            };
            host.install_native_atlas(image.clone(), qualification)?;
            let context = host.execution_context();
            let stop = host.local_stop();
            let listener = host.listen(runtime.handle().clone(), &bound).await?;
            let endpoint = listener.endpoint().clone();
            let serve = tokio::spawn(host.serve(listener));
            let result = async {
                if generation >= 2 {
                    let project = f.project.clone();
                    let output = tokio::task::spawn_blocking(move || {
                        query(endpoint, project).map_err(|error| error.to_string())
                    }).await??;
                    if generation == 3 {
                        let se_core::ops::AnyOutput::AtlasFind(output) = output else {
                            return Err("warm-cache query returned a different family".into());
                        };
                        let query_reason = serde_json::to_value(&output.value.answer.data)?;
                        assert!(query_reason.to_string().contains("not yet qualified"), "{query_reason}");
                        assert!(output.value.answer.index.epoch.is_none());
                        let status = se_core::ops::status::atlas_view(context.atlas.status(&f.project, None));
                        assert_eq!(status.state, "unavailable");
                        assert!(status.reason.as_deref().is_some_and(|r| r.contains("not yet qualified")));
                        return Ok(serde_json::json!({"generation":generation,"query":query_reason,"status":status}));
                    }
                }
                let first = observe(
                    &context,
                    &f.project,
                    if generation == 1 {
                        "initial_marker"
                    } else {
                        "offline_marker"
                    },
                )
                .await?;
                assert_history(&first)?;
                let mut renewed = None;
                if generation == 1 {
                    fs::write(root.join("sample.js"), WRITE)?;
                    let renewal = observe(&context, &f.project, "renewed_marker").await?;
                    assert_history(&renewal)?;
                    assert_eq!(
                        renewal.epoch, first.epoch,
                        "ordinary watch change should renew the live epoch"
                    );
                    renewed = Some(renewal);
                }
                Ok::<_, Box<dyn std::error::Error>>(serde_json::json!({"generation":generation,"first":first,"renewed":renewed}))
            }
            .await;
            stop.request();
            let mut outcome = serve.await?;
            let close = deadline()?;
            let report = outcome.runtime.drain_storage(&close).await?;
            assert!(report.writer_joined && report.pending.is_empty());
            outcome
                .listener
                .close_transport(&context.blocking, &close)
                .await?
                .retire(&context.blocking, &close)
                .await?;
            if let Some(error) = outcome.failure {
                return Err(error.into());
            }
            result
        })?;
        observations.push(result);
        if generation == 1 {
            fs::write(root.join("sample.js"), OFFLINE)?;
        }
    }
    assert_eq!(
        observations[0]["first"]["root"],
        observations[1]["first"]["root"]
    );
    let output = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/judge-diagnostics");
    fs::create_dir_all(&output)?;
    fs::write(
        output.join("atlas-windows-owner.json"),
        serde_json::to_vec_pretty(&observations)?,
    )?;
    Ok(())
}
