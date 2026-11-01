use super::*;
use se_types::{HostEpoch, HostGeneration, NativePath, ProcessFields, ProcessInstance, Sha256};
use sha2::{Digest, Sha256 as Hasher};
use std::{
    num::{NonZeroU16, NonZeroU32},
    path::PathBuf,
};

pub(super) fn receive(guard: se_proc::RuntimeBootstrap) -> Result<u8> {
    // An uncommitted native guard exits the process when dropped. Keep it in
    // this caller until the actual public refusal has reached its private
    // diagnostic stream; returning an error first would erase its reason.
    let mut guard = Some(guard);
    let result = receive_inner(&mut guard);
    if let (Err(error), Some(bootstrap)) = (&result, guard.as_mut()) {
        bootstrap
            .report_startup_failure("host preparation", &error.to_string())
            .map_err(native_error)?;
    }
    result
}
fn receive_inner(guard: &mut Option<se_proc::RuntimeBootstrap>) -> Result<u8> {
    let bootstrap = guard
        .as_ref()
        .ok_or_else(|| invalid("the retained authenticated bootstrap"))?;
    let args: Vec<_> = bootstrap.arguments().map(OsString::from).collect();
    let [tag, home, instance, generation, configuration] = args.as_slice() else {
        return Err(invalid(
            "the closed host/home/instance/generation/configuration frame",
        ));
    };
    if tag != "host" {
        return Err(invalid("the private host frame discriminator"));
    }
    let home = PathBuf::from(home);
    let configuration = PathBuf::from(configuration);
    if !home.is_absolute() || !configuration.is_absolute() {
        return Err(invalid("absolute native home and configuration paths"));
    }
    let persisted = machine(&home)?;
    if persisted != bootstrap.identity().machine {
        return Err(invalid(
            "the initialized protected machine identity matching the native bootstrap",
        ));
    }
    let instance = decode_instance(instance)?;
    let generation = HostGeneration::new(
        generation
            .to_str()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| invalid("a nonzero host generation"))?,
    )?;
    let initialized = se_host::initialize_host_process()?;
    let config = crate::config::load::<se_core::config_policy::ConfigFile>(
        &configuration,
        configuration != home.join("config.toml"),
    )?;
    config.value.validate()?;
    let identity = se_proc::current_runtime_identity(bootstrap.identity().machine.clone())
        .map_err(native_error)?;
    if identity.process != *bootstrap.identity() {
        return Err(invalid("the native bootstrap's unchanged process identity"));
    }
    let peer = se_proc::native_ipc::observe_ipc_self().map_err(|e| {
        se_core::scope::unreadable("native host self", &e.to_string()).with_cause(e)
    })?;
    let epoch = HostEpoch {
        owner: ProcessInstance::from_observation(ProcessFields {
            machine: identity.process.machine,
            boot: identity.boot_id,
            pid: positive(peer.pid())?,
            started: peer.started().clone(),
            executable: NativePath::from_local(identity.process.image)?,
            argv_sha256: argv_digest(),
        })?,
        generation,
    };
    peer.verify_instance(&epoch.owner, peer.image_sha256())
        .map_err(|e| {
            se_core::scope::unreadable("native host epoch", &e.to_string()).with_cause(e)
        })?;
    // Standalone owns one runtime; all library methods below use this Handle.
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()
        .map_err(|error| {
            se_core::scope::unreadable("standalone host runtime", &error.to_string())
                .with_cause(error)
        })?;
    engine.block_on(async {
        let bound = deadline(Duration::from_secs(30))?;
        let mut host = se_host::HostedRuntime::prepare(
            initialized,
            se_host::HostStart {
                state_directory: home,
                epoch,
                kind: se_host::HostKind::Standalone,
                writer: se_store::WriterOptions {
                    maximum_requests: NonZeroU16::new(16)
                        .ok_or_else(|| invalid("positive writer requests"))?,
                    queue_requests: NonZeroU16::new(64)
                        .ok_or_else(|| invalid("positive writer queue"))?,
                    resident_bytes: positive(1024 * 1024)?,
                    group_bytes: positive(1024 * 1024)?,
                },
                limits: se_host::HostLimits {
                    sessions: positive(256)?,
                    active_connections: positive(64)?,
                    // Admit the supported 20-client burst with bounded headroom.
                    preauth_connections: positive(32)?,
                    parked_mail_waits: positive(64)?,
                    resident_queue_bytes: positive(1024 * 1024)?,
                    session_notice_ids: positive(128)?,
                    aggregate_notice_ids: positive(4096)?,
                    response_bytes: positive(1024 * 1024)?,
                    blocking_jobs: positive(2)?,
                },
            },
            engine.handle().clone(),
            &bound,
        )
        .await?;
        let restored=host.restore_transcripts(&bound).await?;
        if !restored.unavailable.is_empty() {eprintln!("capture recovery: {} binding(s) unavailable; their original cursors remain protected",restored.unavailable.len());}
        host.configure(config.value)?;
        let bootstrap = guard
            .take()
            .ok_or_else(|| invalid("the retained bootstrap before listener admission"))?;
        let listener = host
            .listen_bootstrap(engine.handle().clone(), bootstrap, instance, &bound)
            .await?;
        let exit = host.serve(listener).await;
        finish(exit).await
    })
}
fn positive(value: u32) -> Result<NonZeroU32> {
    NonZeroU32::new(value).ok_or_else(|| invalid("a positive native limit"))
}
fn argv_digest() -> Sha256 {
    let mut digest = Hasher::new();
    for arg in std::env::args_os() {
        #[cfg(unix)]
        let bytes = {
            use std::os::unix::ffi::OsStrExt;
            arg.as_bytes().to_vec()
        };
        #[cfg(windows)]
        let bytes = {
            use std::os::windows::ffi::OsStrExt;
            arg.encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        };
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Sha256::from_bytes(digest.finalize().into())
}
async fn finish(mut exit: se_host::HostServeExit) -> Result<u8> {
    let bound = deadline(Duration::from_secs(30))?;
    let report = exit.runtime.drain_storage(&bound).await?;
    if !report.pending.is_empty() || !matches!(report.backup, se_types::Read::Present { .. }) {
        return Err(se_core::scope::unreadable(
            "host shutdown",
            &format!("storage closure remains pending: {:?}", report.pending),
        ));
    }
    let pool = exit.runtime.blocking_pool();
    if let Some(stop) = exit.stop {
        let reply=se_host::client::endpoint::RuntimeStopReply {
            epoch:stop.request().expected_epoch.clone(),generation:stop.request().generation,key:stop.request().key.clone(),
            outcome:se_host::client::endpoint::RuntimeStopOutcome::Facts {
                achieved:vec![se_host::client::endpoint::RuntimeStopFact::WriterJoined],retained_resume:vec![],
                pending:vec!["The storage writer joined; native transport release, endpoint retirement and agent/debt/resume/final lease-release witnesses remain pending.".into()],
            },
        };
        stop.reply(&reply, &bound).await?;
    }
    exit.listener
        .close_transport(&pool, &bound)
        .await?
        .retire(&pool, &bound)
        .await?;
    if let Some(error) = exit.failure {
        return Err(error);
    }
    Ok(0)
}
