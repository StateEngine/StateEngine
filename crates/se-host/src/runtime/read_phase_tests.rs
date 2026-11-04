use super::{Step, checked_phase, close_read, plan};
use crate::client::{BlockingIpcClient, ClientOptions, lease::ClientCredential, lease::Deadline};
use crate::runtime::*;
use crate::{AuthorizedConnection, HandshakeInput, RawOperation};
use se_core::{admission::read_scope, commit::Cx, ops::CliSelections};
use se_store::*;
use se_types::{
    HostEpoch, HostGeneration, IdempotencyKey, MachineId, ProcessFields, ProcessInstance, Read,
    Secret,
};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    num::{NonZeroU16, NonZeroU32},
    sync::Arc,
    time::Duration,
};
#[path = "../../../se-store/tests/support/store_fixture.rs"]
pub(crate) mod fixture;
use fixture::*;
#[allow(dead_code, reason = "Only session event constructors are needed here.")]
#[path = "../../../se-store/tests/support/capture_fixture.rs"]
mod session_fixture;

fn positive(n: u32) -> Result<NonZeroU32, Box<dyn std::error::Error>> {
    NonZeroU32::new(n).ok_or_else(|| "zero test limit".into())
}
fn options() -> ClientOptions {
    ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(10),
        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}
fn bound() -> Result<Deadline, Box<dyn std::error::Error>> {
    Ok(Deadline::from_options(&options())?)
}
fn full_budget(reader: &SqliteReader, boundary: &str) -> Check {
    let first = reader
        .read_phase()
        .map_err(|e| format!("{boundary}: first reader: {e}"))?;
    let second = reader
        .clone()
        .read_phase()
        .map_err(|e| format!("{boundary}: second reader: {e}"))?;
    assert_eq!(
        reader
            .read_phase()
            .err()
            .ok_or("third reader admitted")?
            .code,
        StoreErrorCode::Backpressure,
        "{boundary}: the production reader must have exactly two slots"
    );
    first.close()?;
    second.close()?;
    Ok(())
}
fn start(f: &Fixture) -> Result<HostStart, Box<dyn std::error::Error>> {
    let machine = MachineId::new("read-phase-native-consumer")?;
    let native = se_proc::current_runtime_identity(machine.clone())
        .map_err(|e| format!("native runtime identity: {e:?}"))?;
    let peer = se_proc::native_ipc::observe_ipc_self()?;
    Ok(HostStart {
        state_directory: f.options.state_directory.clone(),
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
        kind: crate::HostKind::Standalone,
        writer: WriterOptions {
            maximum_requests: NonZeroU16::new(4).ok_or("maximum requests")?,
            queue_requests: NonZeroU16::new(16).ok_or("queue requests")?,
            resident_bytes: positive(1024 * 1024)?,
            group_bytes: positive(1024 * 1024)?,
        },
        limits: crate::HostLimits {
            sessions: positive(2)?,
            active_connections: positive(2)?,
            preauth_connections: positive(2)?,
            parked_mail_waits: positive(2)?,
            resident_queue_bytes: positive(1024 * 1024)?,
            session_notice_ids: positive(16)?,
            aggregate_notice_ids: positive(32)?,
            response_bytes: positive(1024 * 1024)?,
            blocking_jobs: positive(2)?,
        },
    })
}
fn seed(f: &Fixture) -> Check {
    let (mut direct, lease) = f.direct()?;
    let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
    let mut staged = files.create_staging(&f.options.state_directory)?;
    staged.file.write_all(&[23; 32])?;
    staged.file.sync_all()?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, &f.options.state_directory.join("credential"))?;
    let session = session_fixture::session()?;
    let credential = session_fixture::record()?;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    direct.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                session_fixture::prepared(f, &session, &f.a),
                EventBody::CredentialIssued {
                    credential,
                    session: session.clone(),
                    purpose: "session".into(),
                    secret_sha256: Sha256::digest([17; 32]).into(),
                    expires_at_us: now + 300_000_000,
                    activation_deadline_us: now + 60_000_000,
                    expected: Expected::Absent,
                },
                session_fixture::activated(&session)?,
                EventBody::CredentialActivated {
                    credential,
                    session,
                    expected: revision(1)?,
                    first_request: session_fixture::record()?,
                },
            ],
        )?,
        &*lease,
    )?;
    direct.close()?;
    Ok(())
}

/// Protects: real native owner/session handshakes and operation admission, and
/// the actual planner's owned commit plan, release this same capacity-2 reader
/// before network completion or writer submission. No separate reader budget,
/// store double or production pause hook can hide a leaked transaction.
#[test]
fn finite_host_phases_return_both_slots_before_network_and_commit() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    engine.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, engine.handle().clone(), &bound()?)
                .await?;
        let mut listener = host.listen(engine.handle().clone(), &bound()?).await?;
        let context = host.admission_context();
        let reader = &host.execution.reader;
        full_budget(reader, "before handshake")?;
        for owner in [true, false] {
            let endpoint = listener.endpoint().clone();
            let client = std::thread::spawn(move || -> Result<(), String> {
                let secret = Secret::new(vec![if owner { 23 } else { 17 }; 32])
                    .map_err(|e| e.to_string())?;
                let authority = if owner {
                    ClientCredential::Machine(secret)
                } else {
                    ClientCredential::Session(secret)
                };
                BlockingIpcClient::connect_authenticated(
                    &endpoint,
                    authority,
                    NonZeroU32::new(4096).ok_or("reply cap")?,
                    &options(),
                )
                .map(drop)
                .map_err(|e| e.to_string())
            });
            let mut pending = listener
                .accept(options().cancelled)
                .await?
                .handshake()
                .await?;
            let grant = context.handshake(&mut pending)?;
            full_budget(reader, "after handshake, before network finish")?;
            let HandshakeInput::Call(hello) = pending.input() else {
                return Err("operation hello required".into());
            };
            let metadata = || -> Result<_, Box<dyn std::error::Error>> {
                Ok(crate::runtime::admission::OperationMetadata {
                    selections: Some(serde_json::to_value(CliSelections {
                        project: Some(f.project.clone()),
                        agent: owner.then(|| f.a.to_string()),
                        ..CliSelections::default()
                    })?),
                    presence: None,
                })
            };
            assert!(
                context
                    .operation(
                        pending.peer(),
                        &hello.authority,
                        None,
                        &grant,
                        RawOperation {
                            name: "unknown.operation".into(),
                            arguments: serde_json::json!({}),
                            key: None
                        },
                        metadata()?
                    )
                    .is_err()
            );
            full_budget(reader, "after refused operation")?;
            let key = IdempotencyKey::new(if owner {
                "phase-owner"
            } else {
                "phase-session"
            })?;
            let input = se_core::ops::WorkingStateSet {
                text: key.to_string(),
                expect: if owner {
                    se_core::commit::ExpectedRevision::Absent(
                        se_core::commit::AbsentRevision::Absent,
                    )
                } else {
                    se_core::commit::ExpectedRevision::Revision(1)
                },
                idempotency_key: key.clone(),
                owner_agent: None,
            };
            let call = context.operation(
                pending.peer(),
                &hello.authority,
                None,
                &grant,
                RawOperation {
                    name: "working_state.set".into(),
                    arguments: serde_json::to_value(input)?,
                    key: Some(key),
                },
                metadata()?,
            )?;
            full_budget(reader, "after operation, before network finish")?;
            let connection = pending
                .finish(AuthorizedConnection { _private: () }, positive(4096)?)
                .await?;
            client.join().map_err(|_| "native client panicked")??;
            drop(connection);

            let planned = plan(checked_phase(reader, host.generation())?, call)?;
            full_budget(reader, "after plan return with owned plan still alive")?;
            let Step::Commit { batch, then } = planned.step else {
                return Err("write plan required".into());
            };
            full_budget(reader, "pre-commit, before actual writer submission")?;
            let receipt = host.execution.writer.submit(batch)?.await?;
            let mut read = checked_phase(reader, host.generation())?
                .into_snapshot(read_scope(&planned.admission))?;
            let result = planned.kernel.committed(
                then,
                receipt,
                &mut Cx {
                    read: &mut read,
                    admission: &planned.admission,
                },
            );
            close_read(result, read.close())?;
            full_budget(reader, "after committed continuation")?;
        }
        listener
            .close_transport(&host.blocking_pool(), &bound()?)
            .await?
            .retire(&host.blocking_pool(), &bound()?)
            .await?;
        let report = host.drain_storage(&bound()?).await?;
        assert!(report.writer_joined && report.pending.is_empty());
        assert!(matches!(report.backup, Read::Present { .. }));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
