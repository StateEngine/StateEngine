//! Real host used by the independent stop-admission consumer.
#![cfg(all(feature = "listener", target_os = "linux"))]

use se_host::{
    client::{ClientOptions, lease::Deadline},
    *,
};
use se_store::ReadStore;
use se_types::{HostEpoch, HostGeneration, MachineId, NativePath, ProcessFields, ProcessInstance};
use std::{
    num::{NonZeroU16, NonZeroU32},
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

type Check = Result<(), Box<dyn std::error::Error>>;
fn positive(n: u32) -> std::io::Result<NonZeroU32> {
    NonZeroU32::new(n).ok_or_else(|| std::io::Error::other("positive fixture bound required"))
}
fn bound() -> se_types::Result<Deadline> {
    Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(30),
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}

#[test]
#[ignore = "native helper: invoke with the stop_admission_deadline Python consumer"]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn native_admission_host() -> Check {
    let initialized = initialize_host_process()?;
    let root = PathBuf::from(std::env::var_os("STOP_ADMISSION_ROOT").ok_or("fixture root absent")?);
    let home = root.join("state");
    let configuration = home.join("config.toml");
    let config: se_core::config_policy::ConfigFile =
        serde_json::from_slice(&std::fs::read(root.join("config.json"))?)?;
    let machine: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("machine.json"))?)?;
    let machine = MachineId::new(machine["machine_id"].as_str().ok_or("machine ID absent")?)?;
    let native = se_proc::current_runtime_identity(machine.clone())
        .map_err(|e| format!("native self: {e:?}"))?;
    let peer = se_proc::native_ipc::observe_ipc_self()?;
    let start = HostStart {
        state_directory: home.clone(),
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
        writer: se_store::WriterOptions {
            maximum_requests: NonZeroU16::new(4).ok_or("writer bound")?,
            queue_requests: NonZeroU16::new(32).ok_or("writer queue")?,
            resident_bytes: positive(1_048_576)?,
            group_bytes: positive(1_048_576)?,
        },
        limits: HostLimits {
            sessions: positive(4)?,
            active_connections: positive(16)?,
            preauth_connections: positive(16)?,
            parked_mail_waits: positive(8)?,
            resident_queue_bytes: positive(1_048_576)?,
            session_notice_ids: positive(32)?,
            aggregate_notice_ids: positive(128)?,
            response_bytes: positive(1_048_576)?,
            blocking_jobs: positive(2)?,
        },
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    runtime.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start, runtime.handle().clone(), &bound()?).await?;
        host.configure_file(config, configuration)?;
        host.configure_unix_socket_paths(se_proc::native_ipc::UnixSocketPaths {
            runtime_directory: Some(PathBuf::from(
                std::env::var_os("XDG_RUNTIME_DIR").ok_or("private runtime root absent")?,
            )),
            temporary_directory: None,
        })?;
        let helper =
            PathBuf::from(std::env::var_os("STOP_ADMISSION_SE").ok_or("installed CLI absent")?);
        let (_coordinator, reconciliation) = LaunchCoordinator::install(
            &mut host,
            ProcessOptions {
                helper_executable: NativePath::from_local(helper)?,
                linux_delegation: se_proc::LinuxDelegation::CurrentScope,
                maximum_sessions: 4,
            },
            &bound()?,
        )
        .await?;
        assert!(
            reconciliation.unproved.is_empty(),
            "fresh fixture has reconciliation debt"
        );
        let slots = host.blocking_pool().foreground_admission();
        let reader = host.execution_context().reader;
        let files = se_host::state_files::Files::open(&home)?;
        let stop = host.local_stop();
        let control = root.join("control");
        let controller = tokio::spawn(async move {
            let outcome = async move {
                while !control.join("enable").exists() && !control.join("finish").exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                if control.join("enable").exists() {
                    // One reserved slot leaves a single FIFO lane. Each real finite
                    // job queues behind a 700 ms holder without changing its result.
                    let reserved = slots
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(std::io::Error::other)?;
                    let mut rounds = 0_u64;
                    while control.join("enable").exists() && !control.join("finish").exists() {
                        let permit = slots
                            .clone()
                            .acquire_owned()
                            .await
                            .map_err(std::io::Error::other)?;
                        rounds += 1;
                        std::fs::write(control.join("admission-held"), rounds.to_string())?;
                        if control.join("expire").exists() {
                            let inventory = reader
                                .owner_guard(
                                    &files,
                                    se_store::ReadBudget {
                                        page: se_types::PageRequest {
                                            after: None,
                                            limit: positive(16)?,
                                            max_bytes: positive(1_048_576)?,
                                        },
                                        deadline: Duration::from_secs(1),
                                    },
                                )
                                .map_err(std::io::Error::other)?;
                            if inventory
                                .processes
                                .iter()
                                .any(|p| p.state == se_store::ProcessState::StopRequested)
                            {
                                // Stop is already admitted and durably requested. Keep
                                // its next finite job queued beyond its original clock.
                                std::fs::write(control.join("outer-held"), rounds.to_string())?;
                                while control.join("enable").exists()
                                    && !control.join("finish").exists()
                                {
                                    tokio::time::sleep(Duration::from_millis(5)).await;
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(700)).await;
                        drop(permit);
                    }
                    drop(reserved);
                    std::fs::write(control.join("released"), "released")?;
                }
                while !control.join("finish").exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Ok::<(), std::io::Error>(())
            }
            .await;
            stop.request();
            outcome
        });
        let listener = host.listen(runtime.handle().clone(), &bound()?).await?;
        let report = host.serve(listener).await.finish(&bound()?).await;
        controller.await??;
        assert!(
            report.pending.is_empty(),
            "host shutdown: {:?}",
            report.pending
        );
        assert!(
            report.transport_closed && report.endpoint_retired,
            "host resources remain"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
