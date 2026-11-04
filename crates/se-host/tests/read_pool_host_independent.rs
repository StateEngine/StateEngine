//! Protects: fresh pooled read authority, native custody and bounded resource closure.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
use se_host::*;
use se_store::*;
use se_types::Read;
use std::{fs, sync::Arc, time::Duration};
#[path = "../../se-store/tests/support/host_fixture.rs"]
#[allow(dead_code)]
mod host_fixture;
#[path = "../../se-store/tests/support/native_read_identity.rs"]
mod native;
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

fn active(f: &Fixture) -> Result<se_store::RecordId, Box<dyn std::error::Error>> {
    let session = session::session()?;
    let issued = credential(
        &session,
        "http",
        "pool-live-bearer",
        now()? + 300_000_000,
        now()? + 60_000_000,
    )?;
    let EventBody::CredentialIssued { credential: id, .. } = &issued else {
        return Err("credential setup".into());
    };
    let id = *id;
    let (mut writer, lease) = direct(f)?;
    writer.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                session::prepared(f, &session, &f.a),
                issued,
                session::activated(&session)?,
                EventBody::CredentialActivated {
                    credential: id,
                    session,
                    expected: revision(1)?,
                    first_request: session::record()?,
                },
                EventBody::WorkingStateSet {
                    agent: f.a.clone(),
                    text: InputText::Inline("pool-private-marker".into()),
                    expected: Expected::Absent,
                },
            ],
        )?,
        &*lease,
    )?;
    writer.close()?;
    Ok(id)
}
async fn working(port: u16) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    rpc(
        port,
        "pool-live-bearer",
        "tools/call",
        serde_json::json!({"name":"stateengine_working_state_get","arguments":{}}),
    )
    .await
}

/// Protects: G1 — a warm HTTP admission pool rereads committed credential revocation.
#[test]
fn real_http_rechecks_committed_revocation_after_warming_the_admission_pool() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let id = active(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        let execution = host.execution_context();
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let port = host.http_port().ok_or("HTTP port absent")?;
        let stop = host.local_stop();
        let consumer = async {
            let result: Check = async {
                for _ in 0..3 {
                    let output = working(port).await?;
                    require(
                        output["result"]["isError"] == false
                            && output.to_string().contains("pool-private-marker"),
                        format!("warm authenticated call: {output}"),
                    )?;
                }
                execution
                    .writer
                    .submit(f.batch(
                        f.owner_project(),
                        None,
                        vec![EventBody::CredentialRevoked {
                            credential: id,
                            expected: revision(2)?,
                            reason: InputText::Inline("committed between cached checkouts".into()),
                        }],
                    )?)?
                    .await?;
                for _ in 0..3 {
                    let output = working(port).await?;
                    require(
                        output["result"]["structuredContent"]["code"] == "capability-invalid"
                            && !output.to_string().contains("pool-private-marker"),
                        format!("cached authority survived revocation: {output}"),
                    )?;
                }
                Ok(())
            }
            .await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), consumer).await;
        drop(execution);
        let report = exit.finish(&bound()?).await;
        require(
            report.pending.is_empty() && report.transport_closed && report.endpoint_retired,
            "revocation fixture cleanup incomplete",
        )?;
        result
    })
}

/// Unix permits replacing this private fixture's active database pathname. On
/// Windows the separate public pool test empties SQL handles before replacement.
#[cfg(target_os = "linux")]
/// Protects: G6 — emptying the SQL cache cannot rebind the host to a replaced database.
#[test]
fn real_http_refuses_a_replaced_inode_even_after_its_first_refusal_empties_idle() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    active(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let port = host.http_port().ok_or("HTTP port absent")?;
        let stop = host.local_stop();
        let consumer = async {
            let result: Check = async {
                require(
                    working(port)
                        .await?
                        .to_string()
                        .contains("pool-private-marker"),
                    "warm call never observed the real project",
                )?;
                let path = f.options.state_directory.join("state.db");
                let original = f.options.state_directory.join("retained-original.db");
                fs::rename(&path, &original)?;
                let copied = fs::copy(&original, &path);
                let checked: Check = async {
                    copied?;
                    for _ in 0..3 {
                        let output = working(port).await?;
                        require(
                            output["result"]["isError"] == true
                                && !output.to_string().contains("pool-private-marker"),
                            format!("replacement was admitted: {output}"),
                        )?;
                    }
                    Ok(())
                }
                .await;
                if path.try_exists()? {
                    fs::remove_file(&path)?;
                }
                fs::rename(&original, &path)?;
                checked?;
                require(
                    working(port)
                        .await?
                        .to_string()
                        .contains("pool-private-marker"),
                    "restored original identity did not recover",
                )
            }
            .await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), consumer).await;
        let report = exit.finish(&bound()?).await;
        require(
            report.pending.is_empty() && report.transport_closed && report.endpoint_retired,
            "replacement fixture cleanup incomplete",
        )?;
        result
    })
}

/// Protects: G6 — host drain joins active pooled reads before storage closure.
#[test]
fn host_drain_joins_an_outstanding_real_pooled_phase_before_storage_close() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        let reader = host.execution_context().reader;
        let phases = reader.phase_pool(native::open_identity)?;
        let blocking = host.blocking_pool();
        let deadline = bound()?;
        let (ready, started) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::sync_channel(1);
        let job = tokio::spawn(async move {
            blocking
                .run(BlockingClass::Foreground, &deadline, move || {
                    let phase = phases
                        .read_phase()
                        .map_err(|e| se_core::store_error::store_error(&e))?;
                    let observed = phase
                        .runtime_owner()
                        .map_err(|e| se_core::store_error::store_error(&e))?;
                    let sent = ready.send(matches!(observed, Read::Present { .. }));
                    let waited = released.recv_timeout(Duration::from_secs(10));
                    let closed = phase
                        .close()
                        .map_err(|e| se_core::store_error::store_error(&e));
                    let sealed = phases
                        .close()
                        .map_err(|e| se_core::store_error::store_error(&e));
                    if sent.is_err() || waited.is_err() {
                        return Err(se_types::SeError::invalid(
                            "phase observer",
                            "bounded ready/release acknowledgement",
                        ));
                    }
                    closed?;
                    sealed
                })
                .await
        });
        require(
            started.await?,
            "outstanding job never pinned the actual runtime owner",
        )?;
        let deadline = bound()?;
        let mut drain = Box::pin(host.drain_storage(&deadline));
        let early = tokio::time::timeout(Duration::from_millis(100), &mut drain).await;
        release.send(())?;
        let returned_early = early.is_ok();
        let report = match early {
            Ok(result) => result?,
            Err(_) => drain.await?,
        };
        job.await??;
        require(
            !returned_early,
            "storage drained before its accepted pooled phase finished",
        )?;
        require(
            report.writer_joined
                && report.pending.is_empty()
                && matches!(report.backup, Read::Present { .. }),
            "drain did not complete after the outstanding phase closed",
        )
    })
}

/// The real OS lease comes from the shared native fixture. Only its public file
/// adapter changes, so backup uses production native publication rather than a stub.
struct NativeLease {
    kept: Arc<support::Lease>,
    files: se_host::state_files::Files,
}
impl RuntimeLease for NativeLease {
    fn identity(&self) -> StoreResult<LeaseIdentity> {
        self.kept.identity()
    }
    fn files(&self) -> &dyn StateFiles {
        &self.files
    }
}

/// Protects: G4 — native backup remains readable with pooled SQL handles active.
#[test]
fn native_backup_publishes_and_reads_back_while_the_pool_has_idle_and_active_phases() -> Check {
    use sha2::{Digest, Sha256};
    let _initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    let (host, lease) = host_fixture::host(&f)?;
    let custody = Arc::new(NativeLease {
        kept: lease,
        files: se_host::state_files::Files::open_with_policy(
            &f.options.state_directory,
            se_host::state_files::FilePolicy::Host,
        )?,
    });
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let pool = reader.phase_pool(native::open_identity)?;
    let idle = pool.read_phase()?;
    let active = pool.read_phase()?;
    idle.close()?;
    let report = SqliteFactory::backup(
        &f.options,
        custody.clone(),
        host.backup_context(),
        Duration::from_secs(10),
    )?;
    let outside = fs::read(&report.published.path)?;
    require(
        outside.len() as u64 == report.published.bytes
            && <[u8; 32]>::from(Sha256::digest(&outside)) == report.published.sha256,
        "published backup differs from independent file readback",
    )?;
    require(
        matches!(active.runtime_owner()?, Read::Present { .. }),
        "backup invalidated the accepted read phase",
    )?;
    active.close()?;
    pool.read_phase()?.close()?;
    pool.close()?;
    let closed = host.close_clean(custody.as_ref(), Duration::from_secs(10))?;
    require(
        closed.published.path.is_file(),
        "clean-close backup was not published",
    )
}

/// Public native credential retirement is the file effect used by remove --all.
/// The store test separately renames the database with its identity pin alive,
/// proving Windows FILE_SHARE_DELETE rather than assuming it from a source flag.
/// Protects: G1 — native credential removal leaves database reads truthful.
#[test]
fn native_credential_removal_preserves_reads_with_the_database_pool_active() -> Check {
    use sha2::{Digest, Sha256};
    let _initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let pool = reader.phase_pool(native::open_identity)?;
    let idle = pool.read_phase()?;
    let active = pool.read_phase()?;
    idle.close()?;
    let credential = f.options.state_directory.join("credential");
    let before = fs::read(&credential)?;
    let files = se_host::state_files::Files::open_with_policy(
        &f.options.state_directory,
        se_host::state_files::FilePolicy::Host,
    )?;
    files.remove_owned(&credential, Sha256::digest(&before).into())?;
    require(
        !credential.try_exists()?,
        "remove's native credential retirement did not read back absence",
    )?;
    require(
        matches!(active.credential([9; 32])?, Read::Absent { .. }),
        "native retirement broke an accepted phase",
    )?;
    active.close()?;
    pool.read_phase()?.close()?;
    require(
        f.options.state_directory.join("state.db").is_file(),
        "credential retirement removed retained history",
    )?;
    pool.close()?;
    Ok(())
}
