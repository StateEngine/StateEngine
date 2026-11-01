use crate::*;
use se_host::client::{BlockingIpcClient, lease::ClientCredential};
use std::{future::Future, task::Poll};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const WRITE_KEY: &str = "write-admitted-before-stop";

/// Protects: the real supervisor must deliver an admitted write's committed
/// receipt (or typed committed-unavailable reply) before retiring its transport.
pub fn check() -> Check {
    run(false)
}

/// The same native consumer and readback assertions pass when the write replies
/// before stop, independently checking the regression's success path on base.
pub fn control() -> Check {
    run(true)
}

fn run(serial: bool) -> Check {
    let f = std::mem::ManuallyDrop::new(Fixture::new()?);
    println!("shutdown_write fixture={}", f.home.display());
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
            start_options(&f, epoch(machine)?)?,
            engine.handle().clone(),
            &bound()?,
        )
        .await?;
        runtime.configure(se_core::config_policy::ConfigFile::default())?;
        let listener = runtime.listen(engine.handle().clone(), &bound()?).await?;
        let endpoint = listener.endpoint().clone();
        let generation = runtime.generation();
        let router = runtime.router()?;
        let slots = runtime.blocking_pool().foreground_admission();
        let server = tokio::spawn(runtime.serve(listener));
        let (idle_ready, idle_connected) = tokio::sync::oneshot::channel();
        let (close_idle, idle_closed) = std::sync::mpsc::sync_channel(1);
        let idle_endpoint = endpoint.clone();
        let idle_credential = copy_secret(&credential)?;
        let idle = std::thread::spawn(move || -> Result<(), String> {
            let client = BlockingIpcClient::connect_authenticated(
                &idle_endpoint,
                ClientCredential::Machine(idle_credential),
                NonZeroU32::new(1024 * 1024).ok_or("reply budget")?,
                &options(),
            )
            .map_err(|e| e.to_string())?;
            idle_ready.send(()).map_err(|_| "idle readiness closed")?;
            idle_closed
                .recv_timeout(Duration::from_secs(20))
                .map_err(|e| e.to_string())?;
            drop(client);
            Ok(())
        });
        tokio::time::timeout(Duration::from_secs(10), idle_connected).await??;
        let (ready, connected) = tokio::sync::oneshot::channel();
        let (send, sending) = std::sync::mpsc::sync_channel(1);
        let (replied, mut reply) = tokio::sync::oneshot::channel();
        let write_endpoint = endpoint.clone();
        let write_credential = copy_secret(&credential)?;
        let call = ipc::operation(
            se_core::ops::AnyOp::MessageSend(se_core::ops::MessageSend {
                to: f.b.as_str().into(),
                body: "committed while shutdown owns the reply".into(),
                kind: Default::default(),
                refs: vec![],
                reply_to: None,
                idempotency_key: key(WRITE_KEY)?,
            }),
            &se_core::ops::CliSelections {
                project: Some(f.project.clone()),
                ..Default::default()
            },
            generation,
        )?;
        let writer = std::thread::spawn(move || {
            let result = (|| -> se_types::Result<se_host::OperationOutput> {
                let mut client = BlockingIpcClient::connect_authenticated(
                    &write_endpoint,
                    ClientCredential::Machine(write_credential),
                    positive(1024 * 1024)
                        .map_err(|e| se_core::scope::unreadable("reply budget", &e.to_string()))?,
                    &options(),
                )?;
                ready.send(()).map_err(|_| {
                    se_core::scope::unreadable("judge", "readiness receiver closed")
                })?;
                sending
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(|e| se_core::scope::unreadable("judge", &e.to_string()))?;
                client.exchange(call, &options())
            })();
            let _ = replied.send(result);
        });
        tokio::time::timeout(Duration::from_secs(10), connected).await??;
        let mut held = slots.clone().acquire_owned().await?;
        let idle_count = Arc::strong_count(&slots);
        println!("shutdown_write idle foreground refs={idle_count}");
        send.send(())?;
        // Step the actual FIFO foreground resource through native call admission,
        // planning, and submission. No executor/store/clock is substituted.
        queued(&slots, idle_count + 1, "native admission").await?;
        held = pass(&slots, held).await?;
        queued(&slots, idle_count + 2, "planning").await?;
        held = pass(&slots, held).await?;
        queued(&slots, idle_count + 2, "submission").await?;

        // An actual competing SQLite writer delays this accepted transaction
        // while the stop traverses both native proof and owner authentication.
        let competing = if serial {
            None
        } else {
            let database = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
            database.execute_batch("BEGIN IMMEDIATE")?;
            Some(database)
        };
        held = pass(&slots, held).await?;
        drop(held);
        let serial_reply = if serial {
            Some(tokio::time::timeout(Duration::from_secs(10), &mut reply).await??)
        } else {
            None
        };
        let stop_credential = copy_secret(&credential)?;
        let stopper = std::thread::spawn(move || -> Result<_, String> {
            let until = se_types::UnixMicros::new(
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_micros()
                    + 10_000_000) as u64,
            )
            .map_err(|e| e.to_string())?;
            BlockingIpcClient::stop(
                &endpoint,
                &stop_credential,
                key("stop-with-admitted-write").map_err(|e| e.to_string())?,
                until,
                &options(),
            )
            .map_err(|e| e.to_string())
        });

        // Observe the real admission fence with a harmless metadata read. It
        // refuses synchronously after fencing; dropped queued reads have no
        // effects. Release SQLite immediately after observing the actual fence.
        let until = bound()?;
        loop {
            until.remaining()?;
            let mut probe = std::pin::pin!(router.execute_call(
                se_host::RoutedCall {
                    admitted: se_host::HostedCall {
                        input: se_host::HostedInput::Operation(se_core::ops::AnyOp::MetaVersion(
                            se_core::ops::MetaVersion {}
                        )),
                        kernel: se_core::dispatch::Kernel::new(se_core::dispatch::CallFacts {
                            event: fixture::event()?,
                            message: fixture::message()?,
                            agent: fixture::agent()?,
                            profile_event: fixture::event()?,
                            occurred_at_us: 1_700_000_000_000_000,
                            door: Door::Cli,
                        })?,
                        admission: Admission {
                            generation: generation.get(),
                            ..f.owner_project()
                        },
                        terminal: se_core::admission::HumanTerminal::Refused {
                            reason: "metadata read".into()
                        },
                        selections: None,
                    },
                    hook: None,
                },
                &until
            ));
            if let Poll::Ready(Err(error)) =
                std::future::poll_fn(|cx| Poll::Ready(probe.as_mut().poll(cx))).await
            {
                assert!(
                    error.to_string().contains("host admission"),
                    "unexpected fence probe: {error}"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        drop(router);
        if let Some(database) = competing {
            database.execute_batch("ROLLBACK")?;
            drop(database);
        }
        let reader = present(SqliteFactory::open_reader(&f.options)?)?;
        let committed = loop {
            until.remaining()?;
            let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
            let receipt =
                snapshot.operation_receipt(Actor::Human(f.owner.clone()), key(WRITE_KEY)?)?;
            snapshot.close()?;
            match receipt {
                Read::Present { value } => break value,
                Read::Absent { .. } => tokio::time::sleep(Duration::from_millis(1)).await,
                other => return Err(format!("outside receipt unreadable: {other:?}").into()),
            }
        };
        drop(reader);
        let exit = tokio::time::timeout(Duration::from_secs(12), server).await??;
        assert!(
            exit.stop.is_some(),
            "supervisor lost the authenticated stop"
        );
        let outcome = exit.finish(&bound()?).await;
        writer.join().map_err(|_| "write client panicked")?;
        let write_reply = match serial_reply {
            Some(value) => value,
            None => reply.await?,
        };
        let stop_reply = stopper.join().map_err(|_| "stop client panicked")??;
        close_idle.send(())?;
        idle.join().map_err(|_| "idle client panicked")??;
        assert!(matches!(
            stop_reply.outcome,
            se_host::client::endpoint::RuntimeStopOutcome::Facts { .. }
        ));
        assert!(
            outcome.transport_closed && outcome.endpoint_retired,
            "shutdown retained transport/endpoint: {:?}",
            outcome.pending
        );
        drop(outcome);
        // Check the final state from a newly opened outside reader after close.
        let reader = present(SqliteFactory::open_reader(&f.options)?)?;
        let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
        let receipt =
            present(snapshot.operation_receipt(Actor::Human(f.owner.clone()), key(WRITE_KEY)?)?)?;
        assert_eq!(
            receipt.events, committed.events,
            "shutdown changed the original write identity"
        );
        let event = present(snapshot.event(receipt.primary_event.clone())?)?;
        assert!(
            matches!(event.body, EventBody::MessageSent { body: StoredText::Present(ref body), .. }
            if body == "committed while shutdown owns the reply")
        );
        snapshot.close()?;
        drop(reader);
        drop(Lease::acquire(
            &f.options.state_directory,
            LeaseMode::Host,
            Some(f.store.clone()),
        )?);
        if serial {
            assert!(
                write_reply.is_ok(),
                "serial control lost its normal receipt"
            );
        }
        match write_reply {
            Ok(output) => {
                assert_eq!(output.value["state"], "committed");
                assert_eq!(output.value["idempotency_key"], WRITE_KEY);
                assert_eq!(
                    output.value["event_id"],
                    serde_json::to_value(&receipt.primary_event)?
                );
            }
            Err(error) => {
                assert_eq!(
                    error.code().as_str(),
                    "committed-response-unavailable",
                    "shutdown lost a known committed write's reply: {error}"
                );
                let detail = serde_json::to_value(error.body.detail())?;
                assert_eq!(detail["detail"]["operation"], "message.send");
                assert_eq!(detail["detail"]["key"], WRITE_KEY);
                assert_eq!(
                    detail["detail"]["committed_events"],
                    serde_json::to_value(&receipt.events)?
                );
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(std::mem::ManuallyDrop::into_inner(f));
    println!(
        "PASS shutdown_write_reply serial={serial}: native admitted write delivered its committed identity before transport retirement with an idle peer; outside SQLite readback and lease reacquisition verified"
    );
    Ok(())
}

async fn queued(slots: &Arc<Semaphore>, minimum: usize, stage: &str) -> Check {
    let deadline = bound()?;
    while Arc::strong_count(slots) < minimum {
        deadline.remaining().map_err(|error| {
            format!(
                "{stage}: expected foreground refs >= {minimum}, observed {}: {error}",
                Arc::strong_count(slots)
            )
        })?;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    println!(
        "shutdown_write queued {stage}: refs={} minimum={minimum}",
        Arc::strong_count(slots)
    );
    Ok(())
}

async fn pass(
    slots: &Arc<Semaphore>,
    held: OwnedSemaphorePermit,
) -> Result<OwnedSemaphorePermit, Box<dyn std::error::Error>> {
    let mut next = std::pin::pin!(slots.clone().acquire_owned());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(next.as_mut().poll(cx)))
            .await
            .is_pending(),
        "foreground FIFO permit was not held"
    );
    drop(held);
    Ok(tokio::time::timeout(Duration::from_secs(10), next).await??)
}
