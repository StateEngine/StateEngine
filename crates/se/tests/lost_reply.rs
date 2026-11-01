#![allow(
    dead_code,
    reason = "Shared native fixtures compile the unchanged production adapters."
)]
#[path = "../src/compat.rs"]
mod compat;
#[path = "../src/route/direct.rs"]
mod direct;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "../src/grammar.rs"]
mod grammar;
#[path = "support/host_fixture.rs"]
mod host_fixture;
#[path = "../src/ipc.rs"]
mod ipc;
#[path = "../src/render/error.rs"]
mod render_error;
#[path = "support/host_route.rs"]
mod route;
use fixture::*;
use host_fixture::*;
use se_store::*;
use se_types::{
    HostEpoch, HostGeneration, MachineId, Page, ProcessFields, ProcessInstance, ProviderSessionId,
    Read, Secret, SessionId, Sha256,
};
use sha2::{Digest, Sha256 as Hasher};
use std::{
    io::{Read as ByteReader, Write},
    num::{NonZeroU16, NonZeroU32},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

fn generated() -> Result<se_core::ops::AnyOp, Box<dyn std::error::Error>> {
    // Exercise the actual no---key grammar path, rather than supplying a key
    // that a stranger would already know to preserve.
    grammar::parse(
        [
            "se",
            "working-state",
            "set",
            "lost reply",
            "--expect",
            "absent",
        ]
        .into_iter()
        .map(Into::into)
        .collect(),
    )
    .map(|parsed| parsed.operation)
    .map_err(|failure| failure.error.into())
}
fn options_with_timeout(ms: u64) -> se_host::client::ClientOptions {
    let mut value = options();
    value.timeout = Duration::from_millis(ms);
    value
}
fn rendered_key(error: &se_types::SeError, key: &str) -> Check {
    for json in [false, true] {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = render_error::write(error, &Default::default(), json, &mut stdout, &mut stderr)?;
        assert_ne!(exit, 0);
        assert!(
            String::from_utf8(stderr)?.contains(key),
            "human output lost the original key"
        );
        if json {
            let value: serde_json::Value = serde_json::from_slice(&stdout)?;
            assert_eq!(
                value["detail"]["key"], key,
                "JSON output lost the original key"
            );
        } else {
            assert!(stdout.is_empty());
        }
    }
    Ok(())
}
async fn receive(
    listener: &mut se_host::HostedListener,
    router: &se_host::HostedRouter,
) -> Result<se_host::AdmittedExchange, Box<dyn std::error::Error>> {
    let stream = listener.accept(Arc::new(AtomicBool::new(false))).await?;
    let se_host::AcceptedPeer::Operation(connection) =
        router.authenticate_stream(stream, &bound()?).await?
    else {
        return Err("operation became a stop".into());
    };
    router
        .read_call(*connection, &bound()?)
        .await?
        .ok_or("operation disappeared before send".into())
}
fn client(
    endpoint: &se_host::EndpointRecord,
    credential: &Secret,
    op: se_core::ops::AnyOp,
    timeout_ms: u64,
) -> Result<
    std::thread::JoinHandle<se_types::Result<se_core::ops::AnyOutput>>,
    Box<dyn std::error::Error>,
> {
    let endpoint = endpoint.clone();
    let credential = copy_secret(credential)?;
    Ok(std::thread::spawn(move || {
        ipc::forward(
            &endpoint,
            se_host::client::lease::ClientCredential::Session(credential),
            op,
            &Default::default(),
            None,
            &options_with_timeout(timeout_ms),
        )
    }))
}

#[test]
fn lost_post_commit_reply_keeps_the_generated_key_and_replay_resolves_one_effect() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let initialized = se_host::initialize_host_process()?;
    let f = std::mem::ManuallyDrop::new(Fixture::new()?);
    let (mut store, lease) = f.direct()?;
    let machine = route::identity::ensure_machine_identity(&f.options.state_directory)?;
    let machine_key = secret()?;
    publish(&f, "credential", machine_key.expose())?;
    let session_key = secret()?;
    let session = SessionId::from_parts(1_700_000_000_000 + serial(), [73; 10])?;
    let transcript = f.home.join("provider.jsonl");
    std::fs::write(&transcript, b"")?;
    let pin = se_proc::NativeSourcePin::open(&transcript)?.ok_or("missing source pin")?;
    prepare_session(
        &f,
        &mut store,
        &lease,
        SessionSetup {
            session: &session,
            conversation: &ProviderSessionId::new("lost-reply-fixture")?,
            source: record(74)?,
            pin: &pin,
            credential: &session_key,
        },
    )?;
    drop((store, lease));
    let op = generated()?;
    let original_key = op
        .idempotency_key()
        .cloned()
        .ok_or("grammar did not generate request identity")?;
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    engine.block_on(async {
        let mut runtime = se_host::HostedRuntime::prepare(initialized, start_options(&f, epoch(machine)?)?, engine.handle().clone(), &bound()?).await?;
        runtime.configure(Default::default())?;
        let mut listener = runtime.listen(engine.handle().clone(), &bound()?).await?;
        let endpoint = listener.endpoint().clone();
        let router = runtime.router()?;
        let lost_client = client(&endpoint, &session_key, op.clone(), 10_000)?;
        let mut exchange = receive(&mut listener, &router).await?;
        let completed = router.execute_call(exchange.take_call()?, &bound()?).await?;
        let committed = completed.committed.as_ref().ok_or("real host did not commit")?;
        let committed_events = committed.committed_events.clone();
        let first = serde_json::to_value(&completed.output)?;
        assert_eq!(first["state"], "committed");
        // The real listener admitted, planned and durably appended this call.
        // Closing its actual channel here loses only the reply, not the effect.
        drop(exchange);
        let lost = lost_client.join().map_err(|_| "lost-reply client panicked")?;
        let reader = present(SqliteFactory::open_reader(&f.options)?)?;
        let mut snapshot = reader.snapshot(f.self_scope(&f.a))?;
        let receipt = present(snapshot.operation_receipt(Actor::Agent(f.a.clone()), original_key.clone())?)?;
        assert_eq!(receipt.events, committed_events);
        snapshot.close()?;
        let replay_client = client(&endpoint, &session_key, op.clone(), 10_000)?;
        let mut exchange = receive(&mut listener, &router).await?;
        let replay = router.execute_call(exchange.take_call()?, &bound()?).await;
        drop(exchange.reply(replay, &bound()?).await?);
        let replay = serde_json::to_value(replay_client.join().map_err(|_| "replay client panicked")??)?;
        assert_eq!(replay["state"], "replayed");
        assert_eq!(replay["event_id"], first["event_id"]);
        assert_eq!(replay["revision"], 1);

        let mut late_op = op.clone();
        let se_core::ops::AnyOp::WorkingStateSet(ref mut input) = late_op else { return Err("wrong late family".into()); };
        input.expect = se_core::commit::ExpectedRevision::Revision(1);
        input.idempotency_key = key("late-host-reply")?;
        input.text = "a late acknowledged effect".into();
        let late_client = client(&endpoint, &session_key, late_op, 1_000)?;
        let mut exchange = receive(&mut listener, &router).await?;
        let late_commit = router.execute_call(exchange.take_call()?, &bound()?).await?;
        let late_fact = serde_json::to_value(&late_commit.output)?;
        // Delay only delivery, after a real durable receipt; neither the store
        // nor the native clock is replaced by a fixture.
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        drop(exchange.reply(Ok(late_commit), &bound()?).await);
        let late = late_client.join().map_err(|_| "late-reply client panicked")?;

        // A complete authoritative refusal is not an unknown transport effect.
        let mut conflict_op = op.clone();
        let se_core::ops::AnyOp::WorkingStateSet(ref mut input) = conflict_op else { return Err("wrong generated family".into()); };
        input.expect = se_core::commit::ExpectedRevision::Revision(999);
        input.idempotency_key = key("definite-host-conflict")?;
        let refused_client = client(&endpoint, &session_key, conflict_op, 10_000)?;
        let mut exchange = receive(&mut listener, &router).await?;
        let refused = router.execute_call(exchange.take_call()?, &bound()?).await.err().ok_or("invalid revision committed")?;
        let authoritative = refused.code();
        drop(exchange.reply(Err(refused), &bound()?).await?);
        let refusal = refused_client.join().map_err(|_| "refusal client panicked")?.err().ok_or("authoritative refusal disappeared")?;
        assert_eq!(refusal.code(), authoritative);
        let mut snapshot = reader.snapshot(f.self_scope(&f.a))?;
        assert_eq!(present(snapshot.working_state(f.a.clone())?)?.revision.value.get(), 2);
        let late_receipt = present(snapshot.operation_receipt(Actor::Agent(f.a.clone()), key("late-host-reply")?)?)?;
        assert_eq!(late_receipt.primary_event.to_string(), late_fact["event_id"].as_str().ok_or("late event absent")?);
        snapshot.close()?;
        drop(router);
        let finished = se_host::HostServeExit { runtime, listener, stop:None, failure:None, failed_connections:Some(0), last_connection_error:None }.finish(&bound()?).await;
        assert!(finished.transport_closed && finished.endpoint_retired, "fixture did not retire its exact listener");
        assert!(finished.errors.is_empty(), "fixture cleanup errors: {:?}", finished.errors);
        drop(finished);
        let unsent = ipc::forward(&endpoint, se_host::client::lease::ClientCredential::Session(copy_secret(&session_key)?), op, &Default::default(), None, &options_with_timeout(100))
            .err().ok_or("closed endpoint accepted an unsent request")?;
        assert!(!matches!(unsent.body.detail(), se_types::Detail::CommitOutcomeUnknown(_)), "definitely unsent request became unknown");
        let lost = lost.err().ok_or("lost reply invented acknowledged success")?;
        rendered_key(&lost, original_key.as_str())?;
        assert!(matches!(lost.body.detail(), se_types::Detail::CommitOutcomeUnknown(value) if value.operation=="working_state.set" && value.key.as_deref()==Some(original_key.as_str())), "post-send loss discarded generated key: {lost}");
        match late {
            Err(error) => assert!(matches!(error.body.detail(),se_types::Detail::CommitOutcomeUnknown(value) if value.operation=="working_state.set" && value.key.as_deref()==Some("late-host-reply")), "late reply discarded its key: {error}"),
            Ok(output) => assert_eq!(serde_json::to_value(output)?["event_id"],late_fact["event_id"],"late complete reply invented a different effect"),
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(pin);
    drop(std::mem::ManuallyDrop::into_inner(f));
    Ok(())
}

/// Only the readback fails: append remains the real FULL SQLite append.
struct ReadbackFailure {
    store: SqliteDirect,
    appended: bool,
    events: Vec<se_types::EventId>,
}
impl ReadStore for ReadbackFailure {
    type Snapshot = <SqliteDirect as ReadStore>::Snapshot;
    fn info(&self) -> StoreResult<StoreInfo> {
        self.store.info()
    }
    fn runtime_owner(&self) -> StoreResult<Read<RuntimeOwnerHead>> {
        self.store.runtime_owner()
    }
    fn inspect_backups(&self, budget: ReadBudget) -> StoreResult<Page<Read<BackupGeneration>>> {
        self.store.inspect_backups(budget)
    }
    fn snapshot(&self, scope: ReadScope) -> StoreResult<Self::Snapshot> {
        if self.appended {
            return Err(Box::new(StoreError {
                code: StoreErrorCode::Unreadable,
                cause: "independent post-append readback failure".into(),
                detail: StoreDetail::None,
                remedy: se_types::Remedy {
                    text: "retry original key".into(),
                    command: None,
                },
                retry: se_types::Retry::AfterReread,
            }));
        }
        self.store.snapshot(scope)
    }
    fn owner_guard(
        &self,
        files: &dyn StateFiles,
        budget: ReadBudget,
    ) -> StoreResult<OwnerGuardInventory> {
        self.store.owner_guard(files, budget)
    }
    fn credential(&self, key: [u8; 32]) -> StoreResult<Read<CredentialRecord>> {
        self.store.credential(key)
    }
}
impl TextStaging for ReadbackFailure {
    fn stage_text(
        &self,
        source: &mut dyn ByteReader,
        maximum: u64,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<StagedText> {
        self.store.stage_text(source, maximum, lease)
    }
}
impl DirectStore for ReadbackFailure {
    fn append(
        &mut self,
        batch: AtomicBatch,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<CommitReceipt> {
        let receipt = self.store.append(batch, lease)?;
        self.events = receipt.events.clone();
        self.appended = true;
        Ok(receipt)
    }
    fn close(self) -> StoreResult<()> {
        self.store.close()
    }
}
#[test]
fn definite_direct_append_cannot_become_an_unreadable_or_unknown_write() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let session = SessionId::from_parts(1_700_000_000_000 + serial(), [75; 10])?;
    let transcript = f.home.join("provider.jsonl");
    std::fs::write(&transcript, b"")?;
    let pin = se_proc::NativeSourcePin::open(&transcript)?.ok_or("missing direct source pin")?;
    prepare_session(
        &f,
        &mut store,
        &lease,
        SessionSetup {
            session: &session,
            conversation: &ProviderSessionId::new("direct-reply-fixture")?,
            source: record(76)?,
            pin: &pin,
            credential: &secret()?,
        },
    )?;
    let mut failing = ReadbackFailure {
        store,
        appended: false,
        events: Vec::new(),
    };
    let op = generated()?;
    let key = op
        .idempotency_key()
        .cloned()
        .ok_or("missing generated key")?;
    let mut admission = f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone()));
    admission.session = Some(session);
    let terminal = se_core::admission::HumanTerminal::Refused {
        reason: "agent write needs no human terminal".into(),
    };
    let kernel = se_core::dispatch::Kernel::new(se_core::dispatch::CallFacts {
        event: event()?,
        message: message()?,
        agent: fixture::agent()?,
        profile_event: fixture::event()?,
        occurred_at_us: 1_700_000_000_000_000,
        door: Door::Cli,
    })?;
    let outcome = direct::execute(
        &mut failing,
        &*lease,
        &admission,
        &terminal,
        &kernel,
        op,
        &Default::default(),
    );
    if failing.events.is_empty() {
        return Err(format!("fixture never reached append: {:?}", outcome.err()).into());
    }
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snapshot = reader.snapshot(f.self_scope(&f.a))?;
    let receipt = present(snapshot.operation_receipt(Actor::Agent(f.a.clone()), key.clone())?)?;
    assert_eq!(receipt.events, failing.events);
    assert_eq!(
        present(snapshot.working_state(f.a.clone())?)?
            .revision
            .value
            .get(),
        1
    );
    snapshot.close()?;
    failing.close()?;
    let error = outcome
        .err()
        .ok_or("missing readback was fabricated as a complete receipt")?;
    rendered_key(&error, key.as_str())?;
    assert!(
        matches!(error.body.detail(),se_types::Detail::CommittedResponseUnavailable(value) if value.operation.as_ref()=="working_state.set" && value.key.as_deref()==Some(key.as_str()) && value.committed_events.as_ref()==receipt.events.as_slice()),
        "known direct commit lost its exact identity: {error}"
    );
    Ok(())
}
