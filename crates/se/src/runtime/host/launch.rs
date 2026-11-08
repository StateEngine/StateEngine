//! Synchronous CLI-side startup. The caller first authorizes native owner or
//! session custody and releases its direct shared lease. Failure returns every
//! child pin; an ambiguous commit can never become an implicit direct write.
use super::*;
use se_proc::{NativeProcessApi, NativeProcessRuntime, RuntimeChild};
use se_types::{HostGeneration, MachineId};
#[cfg(unix)]
use std::path::PathBuf;
use std::{fs::File, io::Read as ByteRead, path::Path};
pub struct StartedHost {
    pub ready: se_proc::RuntimeReady,
    pub endpoint: se_host::EndpointRecord,
    /// A failed status publication never disguises an already committed native
    /// host as a failed launch or invites a second owner/direct-write fallback.
    pub detachment_record: se_types::Read<super::DetachmentObservation>,
}
pub struct StartupFailure {
    pub error: SeError,
    pub child: Option<RuntimeChild>,
}
impl std::fmt::Debug for StartupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartupFailure")
            .field("error", &self.error)
            .field("retained_child", &self.child.is_some())
            .finish()
    }
}
/// `machine` is the initialized protected persisted identity, not a generated
/// startup label. Only the authenticated inherited frame conveys child inputs.
pub fn start(
    home: &Path,
    configuration: &Path,
    machine: MachineId,
    bound: &se_host::client::lease::Deadline,
) -> std::result::Result<StartedHost, Box<StartupFailure>> {
    start_with_origin(home, configuration, machine, StartupOrigin::Explicit, bound)
}
/// Automatic callers select the same native handshake and custody protocol;
/// only the empty-host residency policy differs after authenticated readiness.
pub fn start_with_origin(
    home: &Path,
    configuration: &Path,
    machine: MachineId,
    origin: StartupOrigin,
    bound: &se_host::client::lease::Deadline,
) -> std::result::Result<StartedHost, Box<StartupFailure>> {
    let mut log = super::startup_log::StartupLog::new(home);
    log.note("Preparing protected state and the runtime executable");
    let result = start_recorded(home, configuration, machine, origin, bound, &mut log);
    match result {
        Ok(started) => {
            log.note("Runtime ownership committed and ready");
            log.export_success();
            Ok(started)
        }
        Err(mut failure) => {
            if matches!(
                failure.error.code(),
                se_types::Code::DeadlineExceeded | se_types::Code::RuntimeStartPending
            ) {
                failure.error.body = se_types::ErrorBody::new(
                    se_types::Detail::RuntimeStartPending(se_types::details::RuntimeStartPending {
                        waited_ms: log.elapsed_ms(),
                    }),
                )
                .with_retry(se_types::Retry::WhenRuntimeReady);
            }
            failure.error = log.refusal(failure.error);
            Err(failure)
        }
    }
}
fn start_recorded(
    home: &Path,
    configuration: &Path,
    machine: MachineId,
    origin: StartupOrigin,
    bound: &se_host::client::lease::Deadline,
    log: &mut super::startup_log::StartupLog,
) -> std::result::Result<StartedHost, Box<StartupFailure>> {
    let setup = (|| -> Result<_> {
        bound.remaining()?;
        if !home.is_absolute() || !configuration.is_absolute() {
            return Err(invalid("absolute home and selected configuration"));
        }
        let persisted = super::machine(home)?;
        if persisted != machine {
            return Err(invalid("the initialized protected machine identity"));
        }
        let files = se_proc::NativeStateFiles::open(home).map_err(file_error)?;
        let mut nonce = [0; 16];
        let mut instance = [0; 16];
        let mut epoch = [0; 8];
        se_proc::fill_entropy(&mut nonce)
            .and_then(|()| se_proc::fill_entropy(&mut instance))
            .and_then(|()| se_proc::fill_entropy(&mut epoch))
            .map_err(|error| {
                se_core::scope::unreadable("runtime startup entropy", &error.to_string())
            })?;
        if nonce == [0; 16] || instance == [0; 16] {
            return Err(invalid(
                "nonzero native startup nonce and independent host identifier",
            ));
        }
        let instance = se_proc::HostInstanceId(instance);
        let generation = HostGeneration::new((u64::from_le_bytes(epoch) & i64::MAX as u64).max(1))?;
        let arguments = vec![
            "host".into(),
            home.as_os_str().into(),
            se_types::hex_lower(&instance.0).into(),
            generation.get().to_string().into(),
            configuration.as_os_str().into(),
            origin.frame().into(),
        ];
        #[cfg(unix)]
        let arguments = {
            let mut arguments = arguments;
            let paths = crate::config::unix_socket_paths()?;
            arguments.push(
                paths
                    .runtime_directory
                    .map_or_else(OsString::new, PathBuf::into_os_string),
            );
            arguments.push(
                paths
                    .temporary_directory
                    .map_or_else(OsString::new, PathBuf::into_os_string),
            );
            arguments
        };
        log.note("Preparing protected runtime temporary storage");
        let environment = super::environment::prepare(&files)?;
        log.note("Protected runtime temporary storage ready");
        let spec = se_proc::RuntimeLaunchSpec {
            machine,
            startup_nonce: nonce,
            executable: std::env::current_exe().map_err(|e| {
                se_core::scope::unreadable("installed host image", &e.to_string()).with_cause(e)
            })?,
            arguments,
            // Native bootstrap passes only this fixed block. SQLite retains
            // file-backed temporary storage within the protected state home.
            environment,
            deadline: bound.at(),
        };
        Ok((files, spec, instance, generation))
    })()
    .map_err(|error| Box::new(StartupFailure { error, child: None }))?;
    let (files, spec, instance, generation) = setup;
    let nonce = spec.startup_nonce;
    log.note("Waiting for the detached runtime's authenticated native startup handshake");
    let launched = NativeProcessRuntime::spawn_runtime(spec).map_err(|failure| {
        startup_failure(
            native_startup_error(failure.error),
            failure.remaining,
            bound,
        )
    })?;
    log.note(&format!(
        "Waiting for runtime owner PID {} to publish endpoint.json",
        launched.identity.pid.0
    ));
    let endpoint = match wait_endpoint(&files, &launched.identity, generation, bound) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            return Err(startup_failure(error, Some(launched.child), bound));
        }
    };
    log.note("Authenticating the published runtime endpoint");
    let proof = (|| -> Result<_> {
        // The exclusive host publishes this protected file-identity hint before
        // its endpoint. Reuse it under the original deadline, just as ordinary
        // forwarding does; the native peer proof still rechecks the live image.
        se_proc::native_ipc::restore_image_cache(
            home,
            endpoint.image_sha256,
            &bound.native_bound(),
        )
        .map_err(|error| startup_ipc_error("protected executable cache", error))?;
        #[cfg(unix)]
        let stream = match &endpoint.address {
            se_host::IpcEndpoint::UnixSocket(path) => {
                se_proc::native_ipc::NativeUnixStream::connect(
                    &path.to_local()?,
                    bound.native_bound(),
                )
            }
            _ => return Err(invalid("a native Unix startup endpoint")),
        };
        #[cfg(windows)]
        let stream = match &endpoint.address {
            se_host::IpcEndpoint::WindowsPipe(name) => {
                se_proc::native_ipc::NativePipeStream::connect(
                    std::ffi::OsStr::new(name),
                    bound.native_bound(),
                )
            }
            _ => return Err(invalid("a native Windows startup endpoint")),
        };
        let stream = stream.map_err(|error| startup_ipc_error("runtime ready channel", error))?;
        let peer = se_proc::native_ipc::observe_ipc_peer_bounded(
            stream.channel(),
            se_proc::native_ipc::IpcPeerSide::Server,
            &bound.native_bound(),
        )
        .map_err(|error| startup_ipc_error("runtime ready peer", error))?;
        peer.verify_instance(&endpoint.epoch.owner, endpoint.image_sha256)
            .map_err(|error| {
                se_core::scope::unreadable("runtime ready owner", &error.to_string())
                    .with_cause(error)
            })?;
        let channel = File::from(stream.channel().try_clone_to_owned().map_err(|error| {
            se_core::scope::unreadable("retain runtime ready peer", &error.to_string())
                .with_cause(error)
        })?);
        Ok(se_proc::RuntimeReadyProof {
            startup_nonce: nonce,
            owner: launched.identity,
            host: instance,
            endpoint: channel,
        })
    })();
    let proof = match proof {
        Ok(proof) => proof,
        Err(error) => {
            return Err(startup_failure(error, Some(launched.child), bound));
        }
    };
    log.note("Waiting for the runtime ownership commit");
    let ready = NativeProcessRuntime::commit_runtime(launched.child, proof).map_err(|failure| {
        startup_failure(
            native_startup_error(failure.error),
            Some(failure.child),
            bound,
        )
    })?;
    let detachment_record = match super::detachment::publish(home, &endpoint, &ready, bound) {
        Ok(value) => se_types::Read::Present { value },
        Err(error) => se_types::Read::Unreadable {
            source: "protected runtime detachment publication".into(),
            reason: error.to_string(),
            error: Some(Box::new(error.body)),
        },
    };
    Ok(StartedHost {
        ready,
        endpoint,
        detachment_record,
    })
}
fn startup_failure(
    error: SeError,
    child: Option<RuntimeChild>,
    bound: &se_host::client::lease::Deadline,
) -> Box<StartupFailure> {
    let error = match child.as_ref() {
        Some(child) => {
            // Diagnostics never extend the original startup bound or hold an
            // ambiguous live child open while waiting for its eventual EOF.
            let until = bound
                .at()
                .min(std::time::Instant::now() + Duration::from_millis(100));
            let (observed, no_reported_failure) = match child.startup_stderr(until) {
                Ok(stderr) => (
                    format!(
                        "child startup stderr (complete={}, truncated={}, read_failure={:?}): {}",
                        stderr.complete,
                        stderr.truncated,
                        stderr.failure,
                        String::from_utf8_lossy(&stderr.bytes),
                    ),
                    stderr.bytes.is_empty()
                        && !stderr.truncated
                        && stderr.failure.is_none()
                        && !stderr.complete,
                ),
                Err(failure) => (
                    format!("child startup stderr unreadable: {failure:?}"),
                    false,
                ),
            };
            let timed_out = matches!(
                error.code(),
                se_types::Code::DeadlineExceeded | se_types::Code::RuntimeStartPending
            );
            let diagnostic =
                se_core::scope::unreadable("runtime startup", &format!("{error}; {observed}"))
                    .with_cause(error);
            if timed_out && no_reported_failure {
                SeError::new(se_types::Detail::RuntimeStartPending(
                    se_types::details::RuntimeStartPending { waited_ms: 0 },
                ))
                .with_cause(diagnostic)
            } else {
                diagnostic
            }
        }
        None => error,
    };
    Box::new(StartupFailure { error, child })
}
fn native_startup_error(error: se_proc::ProcError) -> SeError {
    if error.code == se_proc::ProcErrorCode::LaunchTimedOut {
        SeError::new(se_types::Detail::RuntimeStartPending(
            se_types::details::RuntimeStartPending { waited_ms: 0 },
        ))
        .with_cause(native_error(error))
    } else {
        native_error(error)
    }
}
fn startup_ipc_error(source: &str, error: se_proc::native_ipc::IpcNativeError) -> SeError {
    if error.code == se_proc::native_ipc::IpcNativeErrorCode::TimedOut {
        SeError::new(se_types::Detail::RuntimeStartPending(
            se_types::details::RuntimeStartPending { waited_ms: 0 },
        ))
        .with_cause(error)
    } else {
        se_core::scope::unreadable(source, &error.to_string()).with_cause(error)
    }
}
fn wait_endpoint(
    files: &se_proc::NativeStateFiles,
    owner: &se_proc::ProcessIdentity,
    generation: HostGeneration,
    bound: &se_host::client::lease::Deadline,
) -> Result<se_host::EndpointRecord> {
    let mut different_owner = false;
    loop {
        let remaining = bound.remaining().map_err(|error| {
            if different_owner {
                se_core::scope::unreadable("runtime endpoint rendezvous",
                    "deadline expired waiting for the newly pinned runtime owner; a different-owner endpoint was observed and the exact new-owner publication never appeared").with_cause(error)
            } else { error }
        })?;
        if let Some(mut file) = files
            .readback(&files.root().join("endpoint.json"))
            .map_err(file_error)?
        {
            let mut bytes = Vec::new();
            (&mut file)
                .take(se_host::client::wire::MAX_ENDPOINT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    se_core::scope::unreadable("runtime endpoint readback", &error.to_string())
                        .with_cause(error)
                })?;
            let endpoint = se_host::client::endpoint::decode_endpoint(&bytes)?;
            let fields = endpoint.epoch.owner.fields();
            if fields.machine != owner.machine
                || fields.pid.get() != owner.pid.0
                || fields.executable.to_local()? != owner.image
                || endpoint.epoch.generation != generation
            {
                different_owner = true;
            } else {
                return Ok(endpoint);
            }
        }
        // Finite startup rendezvous only; ordinary host work is evented.
        // A native exit refuses now rather than spending the full bound.
        match NativeProcessRuntime::read_process(owner.machine.clone(), owner.pid)
            .map_err(native_error)?
        {
            se_proc::ProcessRead::Present(value)
                if value.identity == *owner
                    && value.state != se_proc::NativeState::ExitedAwaitingReap => {}
            observed => {
                return Err(se_core::scope::unreadable(
                    "runtime child before endpoint publication",
                    &format!(
                        "expected live exact child {owner:?}; native observation: {observed:?}"
                    ),
                ));
            }
        }
        std::thread::park_timeout(remaining.min(Duration::from_millis(10)));
    }
}
fn file_error(error: se_proc::StateFileError) -> SeError {
    se_core::scope::unreadable("protected runtime rendezvous", &error.to_string()).with_cause(error)
}
