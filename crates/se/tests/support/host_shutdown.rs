use crate::*;
use se_host::client::endpoint::RuntimeStopOutcome;

/// Protects: a real authenticated stop client that exits after server admission cannot skip shared shutdown's transport closure and exact endpoint retirement.
pub fn disconnected_stop() -> Check {
    run(StopClient::Disconnected)
}
/// Protects: a real competing SQLite writer keeps checkpoint/drain pending; shared shutdown still returns typed achieved/pending facts and retires transport without claiming clean storage.
pub fn pending_drain() -> Check {
    run(StopClient::Waiting)
}
/// Protects: native client cancellation after authenticated stop admission returns within a bounded child process instead of read_exact retrying Interrupted forever.
pub fn cancelled_stop() -> Check {
    run(StopClient::Cancelled)
}
enum StopClient {
    Disconnected,
    Cancelled,
    Waiting,
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn run(control: StopClient) -> Check {
    let disconnect = !matches!(control, StopClient::Waiting);
    let cancelled = matches!(control, StopClient::Cancelled);
    let f = std::mem::ManuallyDrop::new(Fixture::new()?);
    let (direct, lease) = f.direct()?;
    drop(direct);
    drop(lease);
    let machine = route::identity::ensure_machine_identity(&f.options.state_directory)?;
    let credential = secret()?;
    publish(&f, "credential", credential.expose())?;
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    engine.block_on(async {
        let mut runtime = se_host::HostedRuntime::prepare(
            se_host::initialize_host_process()?,
            start_options(&f, epoch(machine.clone())?)?,
            engine.handle().clone(),
            &bound()?,
        )
        .await?;
        let listener = runtime.listen(engine.handle().clone(), &bound()?).await?;
        let endpoint = listener.endpoint().clone();
        // This independent connection is an actual competing SQLite writer,
        // not a substituted drain result or a native/store/runtime double.
        let competing = if disconnect {
            None
        } else {
            let database = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
            database.execute_batch("BEGIN IMMEDIATE")?;
            Some(database)
        };
        let mut process = if disconnect {
            Some(stop_process(&f, cancelled)?)
        } else {
            None
        };
        let client_options = options();
        let client_key = copy_secret(&credential)?;
        let mut client = if disconnect {
            None
        } else {
            Some(std::thread::spawn(move || {
                let until = se_types::UnixMicros::new(
                    (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|e| e.to_string())?
                        .as_micros()
                        + 10_000_000) as u64,
                )
                .map_err(|e| e.to_string())?;
                se_host::client::BlockingIpcClient::stop(
                    &endpoint,
                    &client_key,
                    key("shutdown-failure-path").map_err(|e| e.to_string())?,
                    until,
                    &client_options,
                )
                .map_err(|e| e.to_string())
            }))
        };
        let exit = tokio::time::timeout(Duration::from_secs(10), runtime.serve(listener))
            .await
            .map_err(|_| "authenticated stop was not admitted")?;
        assert!(
            exit.stop.is_some(),
            "failure control has no authenticated stop"
        );
        if let Some(child) = process.as_mut() {
            let observed = match se_proc::NativeProcessRuntime::read_process(
                machine.clone(),
                se_proc::ProcessId(child.0.id()),
            )
            .map_err(|error| format!("read exact owned stop client: {error:?}"))?
            {
                se_proc::ProcessRead::Present(value) => value,
                other => return Err(format!("stop client is not natively live: {other:?}").into()),
            };
            assert_eq!(observed.identity.image, std::env::current_exe()?);
            if cancelled {
                let mut input = child
                    .0
                    .stdin
                    .take()
                    .ok_or("stop client cancellation channel")?;
                input.write_all(b"x")?;
                drop(input);
                let status = tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        if let Some(status) = child.0.try_wait()? {
                            return Ok::<_, std::io::Error>(status);
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .map_err(
                    |_| "native stop client cancellation did not return within three seconds",
                )??;
                assert!(
                    status.success(),
                    "cancelled stop client did not preserve its bounded refusal"
                );
            } else {
                child.0.kill()?;
                assert!(!child.0.wait()?.success());
            }
            wait_native_exit(&observed.identity)?;
        }
        let mut drain_options = options();
        if !disconnect {
            // Exceed the fixture's two-second native SQLite busy timeout so
            // this control observes a returned busy checkpoint, not a race
            // to start the drain before an exhausted admission deadline.
            drain_options.timeout = Duration::from_secs(3);
        }
        let deadline = se_host::client::lease::Deadline::from_options(&drain_options)?;
        let mut outcome = exit.finish(&deadline).await;
        assert!(
            outcome.transport_closed,
            "transport remained open: {:?}",
            outcome.pending
        );
        assert!(
            outcome.endpoint_retired,
            "endpoint remained published: {:?}",
            outcome.pending
        );
        assert!(
            !f.options
                .state_directory
                .join("endpoint.json")
                .try_exists()?
        );
        if disconnect {
            assert!(
                !outcome.errors.is_empty(),
                "failed reply lost its typed error"
            );
            assert!(
                outcome
                    .pending
                    .iter()
                    .any(|value| value.to_lowercase().contains("reply")),
                "failed reply is not a pending fact: {:?}",
                outcome.pending
            );
        } else {
            let reply = client
                .take()
                .ok_or("stop client")?
                .join()
                .map_err(|_| "stop client panicked")?
                .map_err(|e| format!("pending drain returned untyped stop I/O: {e}"))?;
            let RuntimeStopOutcome::Facts {
                achieved, pending, ..
            } = reply.outcome
            else {
                return Err("pending drain omitted achieved/pending facts".into());
            };
            assert!(achieved.contains(&se_host::client::endpoint::RuntimeStopFact::WriterJoined));
            assert!(
                !achieved.contains(&se_host::client::endpoint::RuntimeStopFact::ResourcesClosed)
            );
            assert!(!achieved.contains(&se_host::client::endpoint::RuntimeStopFact::LeaseReleased));
            assert!(
                !pending.is_empty(),
                "busy checkpoint claimed no pending obligations"
            );
            assert!(!outcome.pending.is_empty(), "busy drain was reported clean");
            let storage = match &outcome.storage {
                Read::Present { value } => value,
                other => return Err(format!("actual busy drain report was lost: {other:?}").into()),
            };
            assert!(storage.writer_joined);
            assert!(!storage.pending.is_empty());
            assert!(
                !matches!(storage.backup, Read::Present { .. }),
                "busy checkpoint fabricated a clean-close backup"
            );
        }
        if let Some(database) = competing {
            database.execute_batch("ROLLBACK")?;
            drop(database);
            let resumed = outcome.runtime.drain_storage(&bound()?).await?;
            assert!(
                resumed.pending.is_empty(),
                "actual released writer did not allow drain retry: {:?}",
                resumed.pending
            );
        }
        drop(outcome);
        drop(Lease::acquire(
            &f.options.state_directory,
            LeaseMode::Host,
            Some(f.store.clone()),
        )?);
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    println!(
        "PASS {}: shared shutdown retired the real endpoint and transport with truthful pending facts",
        if cancelled {
            "cancelled_stop"
        } else if disconnect {
            "disconnected_stop"
        } else {
            "pending_drain"
        }
    );
    drop(std::mem::ManuallyDrop::into_inner(f));
    Ok(())
}

fn stop_process(
    f: &Fixture,
    cancelled: bool,
) -> Result<crate::recovery_judge::OwnedChild, Box<dyn std::error::Error>> {
    use std::io::{BufRead, Read as _};
    let state = &f.options.state_directory;
    let flag = if cancelled {
        "--shutdown-cancel-client"
    } else {
        "--shutdown-stop-client"
    };
    let mut child = crate::recovery_judge::OwnedChild(
        std::process::Command::new(std::env::current_exe()?)
            .arg(flag)
            .arg(state)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()?,
    );
    let stdout = child.0.stdout.take().ok_or("stop client stdout")?;
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let result = std::io::BufReader::new(stdout)
            .take(32768)
            .read_line(&mut line)
            .map(|_| line);
        let _ = sent.send(result);
    });
    let argv: Vec<String> =
        serde_json::from_str(&received.recv_timeout(Duration::from_secs(10))??)?;
    reader
        .join()
        .map_err(|_| "stop client readiness reader panicked")?;
    assert_eq!(argv.get(1).map(String::as_str), Some(flag));
    assert_eq!(argv.get(2).map(std::path::Path::new), Some(state.as_path()));
    Ok(child)
}
pub fn client(args: &[std::ffi::OsString]) -> Check {
    let state = std::path::Path::new(args.get(2).ok_or("stop client state directory")?);
    let endpoint =
        se_host::client::endpoint::decode_endpoint(&std::fs::read(state.join("endpoint.json"))?)?;
    let credential = Secret::new(std::fs::read(state.join("credential"))?)?;
    println!(
        "{}",
        serde_json::to_string(&std::env::args().collect::<Vec<_>>())?
    );
    std::io::stdout().flush()?;
    let until = se_types::UnixMicros::new(
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros()
            + 10_000_000) as u64,
    )?;
    let controls = options();
    let cancelled = args
        .get(1)
        .is_some_and(|value| value == "--shutdown-cancel-client");
    if cancelled {
        let flag = Arc::clone(&controls.cancelled);
        std::thread::spawn(move || {
            let mut byte = [0];
            if std::io::Read::read_exact(&mut std::io::stdin(), &mut byte).is_ok() {
                flag.store(true, std::sync::atomic::Ordering::Release);
            }
        });
    }
    let result = se_host::client::BlockingIpcClient::stop(
        &endpoint,
        &credential,
        key("disconnected-stop-child")?,
        until,
        &controls,
    );
    if cancelled
        && controls
            .cancelled
            .load(std::sync::atomic::Ordering::Acquire)
        && result.is_err()
    {
        return Ok(());
    }
    Err("stop client unexpectedly completed before its controlled exit/cancellation".into())
}
