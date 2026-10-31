//! Synchronous CLI-side startup. The caller first authorizes native owner or
//! session custody and releases its direct shared lease. Failure returns every
//! child pin; an ambiguous commit can never become an implicit direct write.
use super::*;
use se_proc::{NativeProcessApi, NativeProcessRuntime, RuntimeChild};
use se_types::{HostGeneration, MachineId};
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
        getrandom::fill(&mut nonce)
            .and_then(|()| getrandom::fill(&mut instance))
            .and_then(|()| getrandom::fill(&mut epoch))
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
        let spec = se_proc::RuntimeLaunchSpec {
            machine,
            startup_nonce: nonce,
            executable: std::env::current_exe().map_err(|e| {
                se_core::scope::unreadable("installed host image", &e.to_string()).with_cause(e)
            })?,
            arguments: vec![
                "host".into(),
                home.as_os_str().into(),
                instance
                    .0
                    .iter()
                    .map(|v| format!("{v:02x}"))
                    .collect::<String>()
                    .into(),
                generation.get().to_string().into(),
                configuration.as_os_str().into(),
            ],
            // Native bootstrap owns exact inherited channels. No session/provider
            // credential or public ambient authority is inherited by the host.
            environment: se_proc::Environment { entries: vec![] },
            deadline: bound.at(),
        };
        Ok((files, spec, instance, generation))
    })()
    .map_err(|error| Box::new(StartupFailure { error, child: None }))?;
    let (files, spec, instance, generation) = setup;
    let nonce = spec.startup_nonce;
    let launched = NativeProcessRuntime::spawn_runtime(spec).map_err(|failure| {
        Box::new(StartupFailure {
            error: native_error(failure.error),
            child: failure.remaining,
        })
    })?;
    let endpoint = match wait_endpoint(&files, &launched.identity, generation, bound) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            return Err(Box::new(StartupFailure {
                error,
                child: Some(launched.child),
            }));
        }
    };
    let proof = (|| -> Result<_> {
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
        let stream = stream.map_err(|error| {
            se_core::scope::unreadable("runtime ready channel", &error.to_string())
                .with_cause(error)
        })?;
        let peer = se_proc::native_ipc::observe_ipc_peer_bounded(
            stream.channel(),
            se_proc::native_ipc::IpcPeerSide::Server,
            &bound.native_bound(),
        )
        .map_err(|error| {
            se_core::scope::unreadable("runtime ready peer", &error.to_string()).with_cause(error)
        })?;
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
            return Err(Box::new(StartupFailure {
                error,
                child: Some(launched.child),
            }));
        }
    };
    let ready = NativeProcessRuntime::commit_runtime(launched.child, proof).map_err(|failure| {
        Box::new(StartupFailure {
            error: native_error(failure.error),
            child: Some(failure.child),
        })
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
fn wait_endpoint(
    files: &se_proc::NativeStateFiles,
    owner: &se_proc::ProcessIdentity,
    generation: HostGeneration,
    bound: &se_host::client::lease::Deadline,
) -> Result<se_host::EndpointRecord> {
    loop {
        let remaining = bound.remaining()?;
        match files
            .readback(&files.root().join("endpoint.json"))
            .map_err(file_error)?
        {
            Some(mut file) => {
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
                    return Err(invalid(
                        "the protected publication of the exact newly pinned runtime owner",
                    ));
                }
                return Ok(endpoint);
            }
            None => {
                // Finite startup rendezvous only; ordinary host work is evented.
                // A native exit refuses now rather than spending the full bound.
                match NativeProcessRuntime::read_process(owner.machine.clone(), owner.pid)
                    .map_err(native_error)?
                {
                    se_proc::ProcessRead::Present(value)
                        if value.identity == *owner
                            && value.state != se_proc::NativeState::ExitedAwaitingReap => {}
                    _ => {
                        return Err(invalid(
                            "the still-executing exact runtime child before publication",
                        ));
                    }
                }
                std::thread::park_timeout(remaining.min(Duration::from_millis(10)));
            }
        }
    }
}
fn file_error(error: se_proc::StateFileError) -> SeError {
    se_core::scope::unreadable("protected runtime rendezvous", &error.to_string()).with_cause(error)
}
