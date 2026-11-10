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
        let diagnostic = match error.body.remedy(&se_types::RenderCx::default()) {
            Ok(remedy) => format!("{error}\n  fix: {}", remedy.text),
            Err(render_error) => format!("{error}\n  remedy unreadable: {render_error}"),
        };
        bootstrap
            .report_startup_failure("host preparation", &diagnostic)
            .map_err(native_error)?;
    }
    result
}
fn receive_inner(guard: &mut Option<se_proc::RuntimeBootstrap>) -> Result<u8> {
    let bootstrap = guard
        .as_ref()
        .ok_or_else(|| invalid("the retained authenticated bootstrap"))?;
    let args: Vec<_> = bootstrap.arguments().map(OsString::from).collect();
    #[cfg(unix)]
    let [
        tag,
        home,
        instance,
        generation,
        configuration,
        origin,
        runtime_directory,
        temporary_directory,
    ] = args.as_slice()
    else {
        return Err(invalid(
            "the closed host/home/instance/generation/configuration/origin/socket-paths frame",
        ));
    };
    #[cfg(windows)]
    let [tag, home, instance, generation, configuration, origin] = args.as_slice() else {
        return Err(invalid(
            "the closed host/home/instance/generation/configuration/origin frame",
        ));
    };
    if tag != "host" {
        return Err(invalid("the private host frame discriminator"));
    }
    let auto_start = if origin == "automatic" {
        true
    } else if origin == "explicit" {
        false
    } else {
        return Err(invalid(
            "an explicit or automatic authenticated startup origin",
        ));
    };
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
    serve(
        home,
        configuration,
        persisted,
        generation,
        auto_start,
        #[cfg(unix)]
        se_proc::native_ipc::UnixSocketPaths {
            runtime_directory: (!runtime_directory.is_empty())
                .then(|| PathBuf::from(runtime_directory)),
            temporary_directory: (!temporary_directory.is_empty())
                .then(|| PathBuf::from(temporary_directory)),
        },
        Some(instance),
        guard,
        &mut |_| Ok(()),
    )
}

pub(crate) fn foreground(
    home: PathBuf,
    configuration: PathBuf,
    machine: se_types::MachineId,
    ready: &mut (dyn FnMut(&se_host::HostedListener) -> Result<()> + Send),
) -> Result<u8> {
    let mut bytes = [0; 8];
    se_proc::fill_entropy(&mut bytes).map_err(|error| {
        se_core::scope::unreadable("foreground host generation", &error.to_string())
    })?;
    let generation = HostGeneration::new((u64::from_le_bytes(bytes) & i64::MAX as u64).max(1))?;
    serve(
        home,
        configuration,
        machine,
        generation,
        false,
        #[cfg(unix)]
        crate::config::unix_socket_paths()?,
        None,
        &mut None,
        ready,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "One shared host entry retains the authenticated detached frame or the authorized foreground callback."
)]
fn serve(
    home: PathBuf,
    configuration: PathBuf,
    machine: se_types::MachineId,
    generation: HostGeneration,
    auto_start: bool,
    #[cfg(unix)] socket_paths: se_proc::native_ipc::UnixSocketPaths,
    instance: Option<se_proc::HostInstanceId>,
    guard: &mut Option<se_proc::RuntimeBootstrap>,
    ready: &mut (dyn FnMut(&se_host::HostedListener) -> Result<()> + Send),
) -> Result<u8> {
    let mut phases = super::startup_log::StartupLog::success_phases(&home);
    if let Some(log) = &mut phases {
        log.note("Host process preparation started");
    }
    let initialized = se_host::initialize_host_process()?;
    let config = crate::config::load::<se_core::config_policy::ConfigFile>(
        &configuration,
        configuration != home.join("config.toml"),
    )?;
    config.value.validate()?;
    let cores = match std::thread::available_parallelism() {
        Ok(cores) => Some(cores),
        Err(error) => {
            eprintln!(
                "host core count unavailable: {error}; using one foreground and one maintenance slot"
            );
            None
        }
    };
    let blocking_jobs = config.value.runtime.resolve_blocking_jobs(cores)?;
    let identity = se_proc::current_runtime_identity(machine).map_err(native_error)?;
    if guard
        .as_ref()
        .is_some_and(|bootstrap| identity.process != *bootstrap.identity())
    {
        return Err(invalid("the native bootstrap's unchanged process identity"));
    }
    if let Some(log) = &mut phases {
        log.note("Native host executable verification started");
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
    if let Some(log) = &mut phases {
        log.note("Native host executable verification finished");
    }
    // The same native image was just verified against the bootstrap and peer;
    // no PATH/cwd lookup may select a different helper for owned agent custody.
    let helper_executable = epoch.owner.fields().executable.clone();
    let maximum_sessions = positive(256)?;
    // Standalone owns one runtime; all library methods below use this Handle.
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(blocking_jobs.get().max(2) as usize)
        .build()
        .map_err(|error| {
            se_core::scope::unreadable("standalone host runtime", &error.to_string())
                .with_cause(error)
        })?;
    let serve = || {
        engine.block_on(async {
        let bound = deadline(Duration::from_secs(30))?;
        if let Some(log) = &mut phases {
            log.note("Host state preparation started");
        }
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
                    sessions: maximum_sessions,
                    active_connections: positive(64)?,
                    // Admit the supported 20-client burst with bounded headroom.
                    preauth_connections: positive(32)?,
                    parked_mail_waits: positive(64)?,
                    resident_queue_bytes: positive(1024 * 1024)?,
                    session_notice_ids: positive(128)?,
                    aggregate_notice_ids: positive(4096)?,
                    response_bytes: positive(1024 * 1024)?,
                    blocking_jobs,
                },
            },
            engine.handle().clone(),
            &bound,
        )
        .await?;
        if let Some(log) = &mut phases {
            log.note("Host state preparation finished");
        }
        let restored=host.restore_transcripts(&bound).await?;
        if !restored.unavailable.is_empty() {eprintln!("capture recovery: {} binding(s) unavailable; their original cursors remain protected",restored.unavailable.len());}
        match config.origin {
            crate::config::Origin::File(path) => host.configure_file(config.value, path)?,
            crate::config::Origin::BuiltIn => host.configure(config.value)?,
        }
        #[cfg(target_os = "linux")]
        host.install_native_atlas(helper_executable.to_local()?,se_host::NativeAtlasQualification::default())?;
        host.configure_auto_start(auto_start)?;
        #[cfg(unix)]
        host.configure_unix_socket_paths(socket_paths)?;
        let (_coordinator, reconciliation) = se_host::LaunchCoordinator::install(
            &mut host,
            se_host::ProcessOptions {
                helper_executable,
                linux_delegation: se_proc::LinuxDelegation::CurrentScope,
                maximum_sessions: se_host::ProcessOptions::DEFAULT_MAXIMUM_SESSIONS,
            },
            &bound,
        )
        .await?;
        for failure in &reconciliation.unproved {
            eprintln!("Agent recovery incomplete; its custody remains fenced: {failure}");
        }
        // Install the native event source before publishing readiness, so a
        // Ctrl-C sent as soon as ready is printed cannot escape the drain path.
        let interrupt = if guard.is_none() { Some(super::interrupt::listen()?) } else { None };
        if let Some(log) = &mut phases {
            log.note("Listener publication and ownership commit started");
        }
        #[cfg(feature="remote")]
        host.prepare_remote_listener(&bound).await?;
        let listener = match guard.take() {
            Some(bootstrap) => host.listen_bootstrap(
                engine.handle().clone(),
                bootstrap,
                instance.ok_or_else(|| invalid("the authenticated detached host instance"))?,
                &bound,
            ).await?,
            None => host.listen(engine.handle().clone(), &bound).await?,
        };
        if let Some(log) = &mut phases {
            log.note("Listener published and ownership committed");
            log.export_success();
        }
        #[cfg(feature="remote")]
        let announced=host.restore_remote_listener(&bound).await.and_then(|()|ready(&listener));
        #[cfg(not(feature="remote"))]
        let announced = ready(&listener);
        if let Err(error) = announced {
            let stop = host.local_stop();
            stop.request();
            let cleanup = finish(host.serve(listener).await).await;
            return Err(match cleanup {
                Ok(_) => error,
                Err(cleanup) => error.with_cause(cleanup),
            });
        }
        let exit = match interrupt {
            Some(signal) => super::interrupt::serve(host, listener, signal).await,
            None => host.serve(listener).await,
        };
        finish(exit).await
    })
    };
    #[cfg(windows)]
    let result = super::stack::run(serve)?;
    #[cfg(not(windows))]
    let result = serve();
    #[cfg(windows)]
    let started = std::time::Instant::now();
    #[cfg(windows)]
    eprintln!(
        "host shutdown pid={} stage=runtime-drop-start elapsed_ms=0",
        std::process::id()
    );
    drop(engine);
    #[cfg(windows)]
    eprintln!(
        "host shutdown pid={} stage=runtime-drop-return elapsed_ms={}",
        std::process::id(),
        started.elapsed().as_millis()
    );
    result
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
async fn finish(exit: se_host::HostServeExit) -> Result<u8> {
    let report = exit.finish(&deadline(Duration::from_secs(30))?).await;
    if !report.pending.is_empty() {
        return Err(
            se_core::scope::unreadable("host shutdown", &report.pending.join("; ")).with_cause(
                ShutdownPending {
                    reason: report.pending.join("; "),
                    _retained: std::sync::Mutex::new(report),
                },
            ),
        );
    }
    Ok(0)
}
struct ShutdownPending {
    reason: String,
    _retained: std::sync::Mutex<se_host::HostShutdown>,
}
impl std::fmt::Debug for ShutdownPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ShutdownPending")
            .field(&self.reason)
            .finish()
    }
}
impl std::fmt::Display for ShutdownPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}
impl std::error::Error for ShutdownPending {}
