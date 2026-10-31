#![allow(
    dead_code,
    reason = "The native consumer compiles unchanged production adapters, including their private runtime entry."
)]
#[path = "support/host_cold_capture.rs"]
mod cold_capture;
#[path = "../src/config.rs"]
mod config;
#[path = "support/host_executor.rs"]
mod executor_judge;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "support/history_cli.rs"]
mod history_cli;
#[path = "../src/runtime/host.rs"]
mod host;
#[path = "support/host_fixture.rs"]
mod host_fixture;
#[path = "../src/ipc.rs"]
mod ipc;
#[path = "support/host_presence.rs"]
mod presence_judge;
#[path = "support/host_route.rs"]
mod route;
#[path = "support/host_startup.rs"]
mod startup_judge;
use fixture::*;
use host_fixture::*;
use se_store::*;
use se_types::{
    HostEpoch, HostGeneration, MachineId, NativePath, ProcessFields, ProcessInstance,
    ProviderSessionId, Read, Secret, SessionId, Sha256,
};
use sha2::{Digest, Sha256 as Hasher};
use std::{
    io::Write,
    num::{NonZeroU16, NonZeroU32},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
/// Protects: wave-1 hosted E3 — real authenticated listener/supervisor commits message, working state and pinned Claude stop; fresh outside snapshots observe their atomic facts and natural replay.
fn listener_message_working_and_hook() -> Check {
    let initialized = se_host::initialize_host_process()?;
    let f = std::mem::ManuallyDrop::new(Fixture::new()?);
    let (mut direct, lease) = f.direct()?;
    let machine = route::identity::ensure_machine_identity(&f.options.state_directory)?;
    let machine_key = secret()?;
    publish(&f, "credential", machine_key.expose())?;
    let session = SessionId::from_parts(1_700_000_000_000 + serial(), [40; 10])?;
    let conversation = ProviderSessionId::new("otto-real-listener-conversation")?;
    let source = record(41)?;
    let transcript = f.home.join("provider.jsonl");
    let mut provider = std::fs::OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&transcript)?;
    let line = serde_json::to_vec(
        &serde_json::json!({"type":"assistant","sessionId":conversation.as_str(),"uuid":"otto-record-1","message":{"role":"assistant","content":[{"type":"text","text":"outside provider text"}]}}),
    )?;
    provider.write_all(&line)?;
    provider.write_all(b"\n")?;
    provider.sync_all()?;
    let pin = se_proc::NativeSourcePin::open(&transcript)?.ok_or("source pin absent")?;
    let file_identity = Sha256::from_bytes(pin.identity());
    let session_key = secret()?;
    prepare_session(
        &f,
        &mut direct,
        &lease,
        SessionSetup {
            session: &session,
            conversation: &conversation,
            source,
            pin: &pin,
            credential: &session_key,
        },
    )?;
    drop(direct);
    drop(lease);
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    engine.block_on(async {
        let mut runtime = se_host::HostedRuntime::prepare(
            initialized,
            start_options(&f, epoch(machine)?)?,
            engine.handle().clone(),
            &bound()?,
        )
        .await?;
        runtime.configure(se_core::config_policy::ConfigFile::default())?;
        let path = NativePath::from_local(transcript.clone())?;
        runtime
            .bind_transcript(
                se_host::TranscriptPin {
                    identity: se_host::SessionIdentity {
                        project: f.project.clone(),
                        agent: f.a.clone(),
                        session: session.clone(),
                    },
                    conversation: conversation.clone(),
                    path: path.clone(),
                    file_identity,
                },
                source,
                pin,
                &bound()?,
            )
            .await?;
        let listener = runtime.listen(engine.handle().clone(), &bound()?).await?;
        let endpoint = listener.endpoint().clone();
        executor_judge::uncertain_write(&f, &session, &runtime).await?;

        let client_conversation = conversation.clone();
        let b = f.b.clone();
        let owner_key = copy_secret(&machine_key)?;
        let session_secret = copy_secret(&session_key)?;
        let client = std::thread::spawn(move || -> Result<(), String> {
            let outcome = (|| -> Check {
                let credential=||->Result<se_host::client::lease::ClientCredential,Box<dyn std::error::Error>> {Ok(se_host::client::lease::ClientCredential::Session(copy_secret(&session_secret)?))};
                let selected = se_core::ops::CliSelections::default();
                let message = || -> Result<se_core::ops::AnyOp, Box<dyn std::error::Error>> {
                    Ok(se_core::ops::AnyOp::MessageSend(
                        se_core::ops::MessageSend {
                            to: b.as_str().into(),
                            body: "real listener message".into(),
                            kind: Default::default(),
                            refs: vec![],
                            reply_to: None,
                            idempotency_key: key("listener-message")?,
                        },
                    ))
                };
                let sent = ipc::forward(
                    &endpoint,
                    credential()?,
                    message()?,
                    &selected,
                    None,
                    &options(),
                )?;
                let first = serde_json::to_value(&sent)?;
                assert_eq!(first["state"], "committed");
                assert_eq!(first["writer"]["mode"], "host");
                let replay = serde_json::to_value(ipc::forward(
                    &endpoint,
                    credential()?,
                    message()?,
                    &selected,
                    None,
                    &options(),
                )?)?;
                assert_eq!(replay["state"], "replayed");
                assert_eq!(replay["event_id"], first["event_id"]);
                let working = ipc::forward(
                    &endpoint,
                    credential()?,
                    se_core::ops::AnyOp::WorkingStateSet(se_core::ops::WorkingStateSet {
                        text: "fresh committed state".into(),
                        expect: se_core::commit::ExpectedRevision::Revision(1),
                        idempotency_key: key("listener-working")?,
                        owner_agent: None,
                    }),
                    &selected,
                    None,
                    &options(),
                )?;
                let working = serde_json::to_value(working)?;
                assert_eq!(working["revision"], 2);
                assert_eq!(working["current_revision"], 2);
                let hook = || se_host::ClaudeHookInput {
                    kind: se_host::ClaudeHookKind::Stop,
                    conversation: client_conversation.clone(),
                    claimed_transcript: path.clone(),
                    payload: serde_json::Value::Null,
                };
                let captured = ipc::forward_hook(&endpoint, credential()?, hook(), &options())?;
                assert!(
                    matches!(captured,se_core::ops::AnyOutput::HookClaude(ref value) if value.value.receipt.is_some())
                );
                let duplicate = ipc::forward_hook(&endpoint, credential()?, hook(), &options())?;
                assert!(
                    matches!(duplicate,se_core::ops::AnyOutput::HookClaude(ref value) if value.value.receipt.as_ref().is_some_and(|receipt|matches!(receipt.result,se_core::ops::hook::CaptureResult::Duplicate)))
                );
                Ok(())
            })();
            let stop_result = (|| -> Check {
                let until = se_types::UnixMicros::new(
                    (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_micros()
                        + 10_000_000) as u64,
                )?;
                let reply = se_host::client::BlockingIpcClient::stop(
                    &endpoint,
                    &owner_key,
                    key("listener-stop")?,
                    until,
                    &options(),
                )?;
                assert!(matches!(
                    reply.outcome,
                    se_host::client::endpoint::RuntimeStopOutcome::Facts { .. }
                ));
                Ok(())
            })();
            outcome.and(stop_result).map_err(|error| error.to_string())
        });
        let mut exit = tokio::time::timeout(Duration::from_secs(20), runtime.serve(listener))
            .await
            .map_err(|_| "real host supervisor did not receive its bounded stop")?;
        let report = exit.runtime.drain_storage(&bound()?).await?;
        assert!(report.writer_joined);
        assert!(
            report.pending.is_empty(),
            "storage remained pending: {:?}",
            report.pending
        );
        assert!(matches!(report.backup, Read::Present { .. }));
        let pool = exit.runtime.blocking_pool();
        exit.listener
            .close_transport(&pool, &bound()?)
            .await?
            .retire(&pool, &bound()?)
            .await?;
        let stop = exit
            .stop
            .take()
            .ok_or("supervisor lost authenticated stop")?;
        let reply = se_host::client::endpoint::RuntimeStopReply {
            epoch: stop.request().expected_epoch.clone(),
            generation: stop.request().generation,
            key: stop.request().key.clone(),
            outcome: se_host::client::endpoint::RuntimeStopOutcome::Facts {
                achieved: vec![se_host::client::endpoint::RuntimeStopFact::WriterJoined],
                retained_resume: vec![],
                pending: vec![
                    "SDK test asserts storage only; full lifecycle shutdown is separate".into(),
                ],
            },
        };
        stop.reply(&reply, &bound()?).await?;
        client.join().map_err(|_| "real IPC client panicked")??;
        if let Some(error) = exit.failure {
            return Err(Box::new(error) as Box<dyn std::error::Error>);
        }
        drop(exit.runtime);
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    verify_capture(&f, source, 1, (line.len() + 1) as u64)?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut read = reader.snapshot(f.self_scope(&f.a))?;
    let state = present(read.working_state(f.a.clone())?)?;
    assert!(
        matches!(state.current.body,EventBody::WorkingStateSet {text:StoredText::Present(ref text),..} if text=="fresh committed state")
    );
    read.close()?;
    drop(reader);
    assert!(
        !f.options
            .state_directory
            .join("endpoint.json")
            .try_exists()?
    );
    drop(Lease::acquire(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(f.store.clone()),
    )?);
    cold_capture::check(
        &f,
        cold_capture::Capture {
            machine_key: &machine_key,
            session_key: &session_key,
            conversation: &conversation,
            transcript: &transcript,
            first_line: &line,
            source,
        },
    )?;
    println!(
        "PASS listener_message_working_and_hook: authenticated commits, replay, outside turn/cursor/state, storage join, endpoint retirement and lease reacquisition"
    );
    drop(std::mem::ManuallyDrop::into_inner(f));
    Ok(())
}
fn main() -> Check {
    let args: Vec<_> = std::env::args_os().collect();
    if let Some(result) = host::dispatch(&args) {
        std::process::exit(match result {
            Ok(code) => i32::from(code),
            Err(error) => {
                eprintln!("{error}");
                1
            }
        });
    }
    se_proc::initialize_file_creation_owner()?;
    if args.get(1).is_some_and(|arg| arg == "--owner-client") {
        return presence_judge::client(&args);
    }
    startup_judge::private_startup_refuses_missing_and_mismatched_machine()?;
    startup_judge::private_startup_serves_and_retires()?;
    listener_message_working_and_hook()?;
    println!(
        "host_e3: 5 passed; 0 failed; boundary: native library and real IPC/store; agent-tree IPC case deferred to wave 2, installed lifecycle qualification separate"
    );
    Ok(())
}
