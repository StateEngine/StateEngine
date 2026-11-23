//! Development consumer of automatic after-ready composition and record wakes.
//! It reads the v5 store the owner writes; no legacy cache or memory profile.
#![cfg(all(target_os = "linux", not(debug_assertions)))]
use se_host::*;
use se_store::*;
use se_types::code::AtlasText as _;
use se_types::{HostEpoch, HostGeneration, MachineId, ProcessFields, ProcessInstance, Secret};
use std::{
    io::Write,
    num::{NonZeroU16, NonZeroU32},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[allow(dead_code)]
#[path = "../../se-store/tests/support/capture_fixture.rs"]
mod sessions;
fn positive(n: u32) -> Result<NonZeroU32, Box<dyn std::error::Error>> {
    NonZeroU32::new(n).ok_or_else(|| "zero test bound".into())
}
fn client_options() -> client::ClientOptions {
    client::ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn deadline() -> Result<client::lease::Deadline, Box<dyn std::error::Error>> {
    Ok(client::lease::Deadline::from_options(&client_options())?)
}
fn start(f: &Fixture) -> Result<HostStart, Box<dyn std::error::Error>> {
    let machine = MachineId::new("atlas-owner-native-consumer")?;
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
                pid: positive(peer.pid())?,
                started: peer.started().clone(),
                executable: peer.image().clone(),
                argv_sha256: se_types::Sha256::from_bytes([0; 32]),
            })?,
            generation: HostGeneration::new(1)?,
        },
        kind: HostKind::Standalone,
        writer: WriterOptions {
            maximum_requests: NonZeroU16::new(16).ok_or("requests")?,
            queue_requests: NonZeroU16::new(16).ok_or("queue")?,
            resident_bytes: positive(1048576)?,
            group_bytes: positive(1048576)?,
        },
        limits: HostLimits {
            sessions: positive(2)?,
            active_connections: positive(2)?,
            preauth_connections: positive(2)?,
            parked_mail_waits: positive(2)?,
            resident_queue_bytes: positive(1048576)?,
            session_notice_ids: positive(16)?,
            aggregate_notice_ids: positive(32)?,
            response_bytes: positive(1048576)?,
            blocking_jobs: positive(2)?,
        },
    })
}

fn setup(f: &Fixture) -> Check {
    let source = f.home.join("source");
    std::fs::create_dir(&source)?;
    std::fs::write(source.join("good.js"), "export function good(){return 1;}")?;
    for name in [
        ".env",
        "secrets.py",
        "config.js",
        "private.pem",
        "credentials.json",
    ] {
        std::fs::write(
            source.join(name),
            "export function DO_NOT_INDEX(){return 'PRIVATE';}",
        )?;
    }
    std::fs::write(
        source.join(".gitignore"),
        "!.env\n!secrets.py\n!config.js\n!private.pem\n!credentials.json\n",
    )?;
    // The automatic owner must discover this registration itself and seed
    // history after the real installed parser image has been exactly reaped.
    for args in [
        vec!["init", "--initial-branch=main"],
        vec!["add", "--", "."],
        vec![
            "-c",
            "user.name=History Fixture",
            "-c",
            "user.email=atlas-fixture.invalid",
            "commit",
            "-m",
            "automatic_git_seed",
        ],
    ] {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Git fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
    }
    let (mut direct, lease) = f.direct()?;
    let mut registration = f.batch(
        f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
        Some(request("atlas-startup-project-root")?),
        vec![EventBody::ProjectUpdated {
            project: f.project.clone(),
            name: "Project".into(),
            roots: vec![Root {
                path: se_types::NativePath::from_local(source.clone())?,
                canonical_key: source.as_os_str().as_encoded_bytes().to_vec(),
            }],
            expected: revision(1)?,
        }],
    )?;
    for event in &mut registration.events {
        event.header.door = Door::Import;
    }
    direct.append(registration, &*lease)?;
    direct.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.a.clone()),
            message()?,
            "good.js packet budget",
            "startup-seed",
        )?,
        &*lease,
    )?;
    let session = sessions::session()?;
    let credential = sessions::record()?;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    use sha2::{Digest, Sha256};
    direct.append(
        f.batch(
            f.owner_project(),
            Some(request("atlas-startup-session-credential")?),
            vec![
                sessions::prepared(f, &session, &f.a),
                EventBody::CredentialIssued {
                    credential,
                    session: session.clone(),
                    purpose: "session".into(),
                    secret_sha256: Sha256::digest([17; 32]).into(),
                    expires_at_us: now + 300_000_000,
                    activation_deadline_us: now + 60_000_000,
                    expected: Expected::Absent,
                },
                sessions::activated(&session)?,
                EventBody::CredentialActivated {
                    first_request: Some(sessions::record()?),
                    credential,
                    session,
                    expected: revision(1)?,
                },
            ],
        )?,
        &*lease,
    )?;
    direct.close()?;
    drop(lease);
    let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
    let mut staged = files.create_staging(&f.options.state_directory)?;
    staged.file.write_all(&[23; 32])?;
    staged.file.sync_all()?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, &f.options.state_directory.join("credential"))?;
    Ok(())
}
fn write(endpoint: &EndpointRecord) -> Result<(), String> {
    let options = client_options();
    let mut connection = client::BlockingIpcClient::connect_authenticated(
        endpoint,
        client::lease::ClientCredential::Session(
            Secret::new(vec![17; 32]).map_err(|e| e.to_string())?,
        ),
        positive(65536).map_err(|e| e.to_string())?,
        &options,
    )
    .map_err(|e| e.to_string())?;
    let key = se_types::IdempotencyKey::new("automatic-record-feed").map_err(|e| e.to_string())?;
    let input = se_core::commit::WorkingStateSet {
        text: "good.js after ready".into(),
        expect: se_core::commit::ExpectedRevision::Absent(se_core::commit::AbsentRevision::Absent),
        idempotency_key: key.clone(),
        owner_agent: None,
    };
    connection
        .exchange(
            IpcEnvelope {
                version: connection.negotiated().version,
                request_id: 1,
                generation: endpoint.generation,
                authority: None,
                presence: None,
                cli_selections: None,
                request: IpcRequest::Operation(RawOperation {
                    name: "working_state.set".into(),
                    arguments: serde_json::to_value(input).map_err(|e| e.to_string())?,
                    key: Some(key),
                }),
            },
            &options,
        )
        .map_err(|e| e.to_string())?;
    // A committed record wakes maintenance; the read port explicitly refuses
    // while its finite quantum owns the lock. Exercise that legal retry only.
    let until = Instant::now() + Duration::from_secs(5);
    let mut request_id = 2;
    let answer = loop {
        let result = connection.exchange(IpcEnvelope {
            version: connection.negotiated().version,
            request_id,
            generation: endpoint.generation,
            authority: None,
            presence: None,
            cli_selections: None,
            request: IpcRequest::Operation(RawOperation {
                name: "atlas.find".into(),
                arguments: serde_json::json!({"query":"good.js","kind":"path","mode":"literal","byte_budget":4096}),
                key: None,
            }),
        }, &options);
        match result {
            Ok(answer) => break answer,
            Err(error)
                if Instant::now() < until
                    && matches!(error.body.detail(),
                se_types::Detail::SourceUnreadable(detail) if detail.subject=="Atlas owner"
                    && detail.reason.starts_with("a finite maintenance quantum is active")) =>
            {
                request_id += 1;
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.to_string()),
        }
    };
    assert!(
        serde_json::to_vec(&answer.value)
            .map_err(|e| e.to_string())?
            .len()
            <= 4096
    );
    let mut wire = answer.value;
    wire["schema"] = answer.schema.into();
    let se_core::ops::AnyOutput::AtlasFind(output) =
        serde_json::from_value(wire).map_err(|e| e.to_string())?
    else {
        return Err("Atlas query returned a different output family".into());
    };
    assert!(
        matches!(&output.value.answer.data, se_types::Read::Present { value }
        if value.page.items().iter().any(|hit| matches!(&hit.target,
            se_types::code::HitTarget::Code(code) if code.pointer.path.as_str() == "good.js"))),
        "real IPC path search did not find the indexed file"
    );
    assert!(
        !output
            .value
            .answer
            .index
            .coverage
            .reasons
            .contains(&se_types::code::CoverageReason::ResultLimit),
        "complete one-commit history was labelled partial"
    );
    Ok(())
}
/// The v5 store's current epoch database for one root, opened read-only.
fn indexed_paths(
    state: &std::path::Path,
    project: &se_types::ProjectId,
    root: &se_types::code::RootId,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let dir = state
        .join("atlas-v5")
        .join(project.as_str())
        .join(root.as_str());
    let current = std::fs::read_to_string(dir.join("atlas.v5.current"))?;
    let conn = rusqlite::Connection::open_with_flags(
        dir.join(current.trim()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = conn.prepare("SELECT path FROM files")?;
    let paths = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(paths)
}
/// Wait until the owner indexed the fixture, certified its record feed
/// current for the root's epoch, and folded records past `after`.
async fn caught_up(
    context: &ExecutionContext,
    state: &std::path::Path,
    project: &se_types::ProjectId,
    after: Option<se_types::EventId>,
) -> Result<se_types::EventId, Box<dyn std::error::Error>> {
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        let owner = context.clone();
        let selected = project.clone();
        let pool = context.blocking.clone();
        let result = pool
            .run(BlockingClass::Foreground, &deadline()?, move || {
                let summary = owner.atlas.summary(&selected, None)?;
                let Some(epoch) = summary.epoch.clone() else {
                    return Ok(None);
                };
                let ticket = owner.atlas.records.ticket()?;
                let scope = atlas_runtime::record_fence::RecordFeedScope {
                    project: selected.clone(),
                    root: summary.root.clone(),
                    epoch,
                };
                let fresh = owner.atlas.records.is_current(&scope, ticket)?;
                let cursor = owner.atlas.engine(&selected, None)?.feed_cursor()?;
                Ok(Some((fresh, cursor, summary.root)))
            })
            .await;
        let last = match result {
            Ok(Some((true, Some(cursor), root))) if Some(&cursor) != after.as_ref() => {
                let paths = indexed_paths(state, project, &root)?;
                assert!(paths.iter().any(|p| p == "good.js"));
                for path in paths {
                    assert!(
                        !se_atlas::policy::built_in_denied(&se_types::code::RelativePath::new(
                            &path
                        )?),
                        "private file entered the v5 store: {path}"
                    );
                }
                return Ok(cursor);
            }
            Ok(value) => format!(
                "feed not caught up: {:?}",
                value.map(|(fresh, cursor, _)| (fresh, cursor))
            ),
            Err(error) => error.to_string(),
        };
        if Instant::now() >= end {
            return Err(format!("automatic owner never caught up: {last}").into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[test]
fn automatic_owner_indexes_and_catches_committed_records_up() -> Check {
    // Embedded hosts deliberately have no native Atlas owner; their refusal
    // is exercised by atlas_embedded_tools in se-host.
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    setup(&f)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(3)
        .build()?;
    runtime.block_on(async {
        let options = start(&f)?;
        let mut host =
            HostedRuntime::prepare(initialized, options, runtime.handle().clone(), &deadline()?)
                .await?;
        host.configure(se_config::config_policy::ConfigFile::default())?;
        host.install_native_atlas(
            std::path::PathBuf::from(env!("CARGO_BIN_EXE_se")).canonicalize()?,
            NativeAtlasQualification::default(),
        )?;
        let context = host.execution_context();
        let stop = host.local_stop();
        let listener = host.listen(runtime.handle().clone(), &deadline()?).await?;
        let endpoint = listener.endpoint().clone();
        let serving = tokio::spawn(host.serve(listener));
        let result = async {
            let state = f.options.state_directory.clone();
            let first = caught_up(&context, &state, &f.project, None).await?;
            tokio::task::spawn_blocking(move || write(&endpoint)).await??;
            caught_up(&context, &state, &f.project, Some(first)).await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        stop.request();
        let mut exit = serving.await?;
        let drained = exit.runtime.drain_storage(&deadline()?).await?;
        assert!(drained.writer_joined && drained.pending.is_empty());
        exit.listener
            .close_transport(&context.blocking, &deadline()?)
            .await?
            .retire(&context.blocking, &deadline()?)
            .await?;
        if let Some(error) = exit.failure {
            return Err(error.into());
        }
        result
    })?;

    Ok(())
}
