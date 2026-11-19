//! One shared Codex app-server per login, launched and owned by the coordinator.
//!
//! Every Codex agent's own process is a forwarder to this server, so a login has
//! one app-server and one token owner however many agents run. The server is
//! launched in its own native scope, like an agent, so it outlives the host. Its
//! custody is a private record beside the host's state, one per login: a host
//! that restarts re-adopts the server from that record, and the server stops when
//! the last Codex agent stops. A server already serving the login that this host
//! did not start is used and never stopped.
//!
//! A record that is unreadable, or whose process cannot be proved to be ours,
//! means the server is neither adopted nor stopped; the refusal names the record.
use super::*;
use se_proc::{
    Checkpoint, CheckpointKind, CheckpointPrincipal, CheckpointSource, LaunchProgress,
    LaunchStart, ProcessRuntime, RecoveryOutcome, RecoverySource, RootPublication,
    StopObservation,
};
use crate::client::lease::Deadline;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{ffi::OsString, io::Write, path::Path, time::Duration};

const RECORD_VERSION: u16 = 1;
const RECORD_BYTES: usize = 1024 * 1024;
/// A first start on a fresh login has been observed to take about 15 seconds.
const READY: Duration = Duration::from_secs(60);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u16,
    login: NativePath,
    checkpoint: Checkpoint,
}

#[derive(Default)]
pub(super) struct CodexServer {
    slot: tokio::sync::Mutex<Option<Arc<se_proc::OwnedProcess>>>,
}

/// What the server needs from the launch that first asks for it.
pub(super) struct ServerLaunch {
    pub executable: PathBuf,
    /// Arguments before the server's own, such as an alias supervisor's.
    pub prefix: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    pub windows_sandbox: Option<&'static str>,
}

impl LaunchCoordinator {
    fn codex_record(&self, login: &Path) -> PathBuf {
        let name = se_types::hex_lower(&Sha256::digest(login.as_os_str().as_encoded_bytes()));
        self.options
            .home
            .join("codex-servers")
            .join(format!("{name}.json"))
    }

    /// Make sure the login's shared server is serving before an agent starts.
    pub(super) async fn ensure_codex_server(
        &self,
        launch: ServerLaunch,
        deadline: &Deadline,
    ) -> Result<()> {
        let login = crate::codex_capture::existing_home()?;
        let control = crate::harness::codex_input::control_socket(&login);
        let path = self.codex_record(&login);
        let mut slot = crate::runtime::pool::within(deadline, self.codex_server.slot.lock()).await?;
        let record = self.read_codex_record(&path, deadline).await?;
        if served(&control).await? {
            match record {
                // Someone else's server on this login: use it, never stop it.
                None => return Ok(()),
                Some(record) => {
                    if slot.is_none() {
                        *slot = Some(self.adopt_codex_server(&path, record, deadline).await?);
                    }
                    return Ok(());
                }
            }
        }
        if let Some(record) = record {
            // Recorded but not serving: still starting, or gone.
            match self.recover_codex_server(&path, &record, deadline).await? {
                Some(owner) => {
                    *slot = Some(owner);
                    return wait_served(&control, deadline).await;
                }
                None => remove_record(&path)?,
            }
        }
        *slot = None;
        let owner = self
            .start_codex_server(&login, &path, launch, deadline)
            .await?;
        *slot = Some(owner);
        wait_served(&control, deadline).await
    }

    /// After restart, take back custody of a server a previous host started,
    /// so it can stop once its agents do.
    pub(super) async fn adopt_recorded_codex_server(&self, deadline: &Deadline) -> Result<()> {
        let login = crate::codex_capture::existing_home()?;
        let path = self.codex_record(&login);
        let mut slot = crate::runtime::pool::within(deadline, self.codex_server.slot.lock()).await?;
        let Some(record) = self.read_codex_record(&path, deadline).await? else {
            return Ok(());
        };
        match self.recover_codex_server(&path, &record, deadline).await? {
            Some(owner) => *slot = Some(owner),
            None => remove_record(&path)?,
        }
        Ok(())
    }

    /// Re-check after every lifecycle change whether the shared server is idle.
    pub(super) fn watch_codex_server(self: &Arc<Self>) {
        let mut activity = self.subscribe_activity();
        let coordinator = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Some(current) = coordinator.upgrade() else {
                    return;
                };
                let retired = async {
                    let deadline = Deadline::idle()?.stage(Duration::from_secs(30))?;
                    current.retire_idle_codex_server(&deadline).await
                }
                .await;
                if let Err(failure) = retired {
                    eprintln!("Codex shared server was not stopped: {}", failure.body);
                }
                drop(current);
                if activity.changed().await.is_err() {
                    return;
                }
            }
        });
    }

    /// Stop the server this host owns once no Codex agent remains.
    pub(super) async fn retire_idle_codex_server(&self, deadline: &Deadline) -> Result<()> {
        let mut slot = crate::runtime::pool::within(deadline, self.codex_server.slot.lock()).await?;
        let Some(owner) = slot.clone() else {
            return Ok(());
        };
        if self.live_codex_agents()? {
            return Ok(());
        }
        let login = crate::codex_capture::existing_home()?;
        let path = self.codex_record(&login);
        let record = self.read_codex_record(&path, deadline).await?.ok_or_else(|| {
            refusal(&path, "the record of the server this host started is missing")
        })?;
        let witness = self.stop_codex_server(&owner, deadline).await?;
        let source = checkpoint_source(&record.checkpoint)?;
        self.save_codex_record(
            &path,
            &Record {
                checkpoint: self.codex_checkpoint(CheckpointKind::Exit {
                    source: Box::new(source),
                    witness: witness.clone(),
                })?,
                ..record
            },
            deadline,
        )
        .await?;
        let native = self.native.clone();
        self.store
            .pool
            .run_owned(deadline, move || {
                native
                    .release(&owner, &witness)
                    .map_err(|e| error("Codex shared server release", e))
            })
            .await?;
        remove_record(&path)?;
        *slot = None;
        Ok(())
    }

    fn live_codex_agents(&self) -> Result<bool> {
        let jobs = self
            .jobs
            .0
            .lock()
            .map_err(|_| error("Codex shared server", "poisoned job registry"))?;
        Ok(jobs.values().any(|job| {
            job.provider == se_store::Provider::Codex
                && !job.settled.load(std::sync::atomic::Ordering::Acquire)
        }))
    }

    async fn adopt_codex_server(
        &self,
        path: &Path,
        record: Record,
        deadline: &Deadline,
    ) -> Result<Arc<se_proc::OwnedProcess>> {
        self.recover_codex_server(path, &record, deadline)
            .await?
            .ok_or_else(|| {
                refusal(
                    path,
                    "the recorded server has exited but another process serves its socket",
                )
            })
    }

    /// Re-adopt the recorded scope. `None` means it has exited.
    async fn recover_codex_server(
        &self,
        path: &Path,
        record: &Record,
        deadline: &Deadline,
    ) -> Result<Option<Arc<se_proc::OwnedProcess>>> {
        let source = match &record.checkpoint.checkpoint {
            CheckpointKind::Reservation(v) => RecoverySource::Reservation(Box::new(v.clone())),
            CheckpointKind::Scope(v) => RecoverySource::Prepared(Box::new(v.clone())),
            CheckpointKind::Root(v) => RecoverySource::RootPrepared(Box::new(v.clone())),
            CheckpointKind::Process(v) => RecoverySource::Record(Box::new(v.clone())),
            _ => return Ok(None),
        };
        let native = self.native.clone();
        let generation = self.options.epoch.generation;
        let outcome = self
            .store
            .pool
            .run_owned(deadline, move || {
                let plan = native
                    .plan_recovery(source)
                    .map_err(|e| error("Codex shared server recovery", e))?;
                native
                    .recover(plan, generation)
                    .map_err(|e| error("Codex shared server recovery", e))
            })
            .await?;
        match outcome {
            RecoveryOutcome::Recovered { process, record: native_record } => {
                self.save_codex_record(
                    path,
                    &Record {
                        checkpoint: self.codex_checkpoint(CheckpointKind::Process(*native_record))?,
                        ..record.clone()
                    },
                    deadline,
                )
                .await?;
                Ok(Some(Arc::new(process)))
            }
            RecoveryOutcome::PendingScope { process, .. } => Ok(Some(Arc::new(process))),
            RecoveryOutcome::Exited(_) => Ok(None),
            _ => Err(refusal(
                path,
                "the recorded server's process cannot be proved to be the one this host started",
            )),
        }
    }

    async fn start_codex_server(
        &self,
        login: &Path,
        path: &Path,
        launch: ServerLaunch,
        deadline: &Deadline,
    ) -> Result<Arc<se_proc::OwnedProcess>> {
        let mut bytes = [0; 10];
        se_proc::fill_entropy(&mut bytes).map_err(|e| error("Codex server lifecycle", e))?;
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| error("Codex server clock", e))?;
        let lifecycle = se_types::LifecycleId::from_parts(created.as_millis() as u64, bytes)?;
        let mut nonce = [0; 16];
        se_proc::fill_entropy(&mut nonce).map_err(|e| error("Codex server scope", e))?;
        let reservation = se_proc::LaunchReservation {
            format_version: 1,
            lifecycle: lifecycle.clone(),
            host: self.host,
            owner: self.owner.clone(),
            generation: self.options.epoch.generation,
            scope_nonce: nonce,
            parent: if cfg!(windows) {
                se_proc::ReservationParent::Windows
            } else if cfg!(target_os = "macos") {
                se_proc::ReservationParent::MacOs
            } else {
                se_proc::ReservationParent::LinuxTracked
            },
            created_at_unix_ns: created.as_nanos(),
        };
        let mut record = Record {
            version: RECORD_VERSION,
            login: NativePath::from_local(login.to_owned())?,
            checkpoint: self.codex_checkpoint(CheckpointKind::Reservation(reservation.clone()))?,
        };
        self.save_codex_record(path, &record, deadline).await?;
        let scratch = path.with_extension("tmp");
        let mut environment = launch.environment;
        environment.retain(|(key, _)| {
            !["TMPDIR", "TMP", "TEMP"]
                .iter()
                .any(|name| key.to_string_lossy().eq_ignore_ascii_case(name))
        });
        for name in ["TMPDIR", "TMP", "TEMP"] {
            environment.push((name.into(), scratch.as_os_str().to_owned()));
        }
        let mut arguments = launch.prefix;
        if let Some(name) = launch.windows_sandbox {
            arguments.push("-c".into());
            arguments.push(format!("windows.sandbox={}", serde_json::json!(name)).into());
        }
        arguments.extend(["app-server".into(), "--listen".into(), "unix://".into()]);
        let spec = se_proc::LaunchSpec {
            executable_custody: None,
            lifecycle,
            generation: self.options.epoch.generation,
            executable: launch.executable,
            arguments,
            cwd: login.to_owned(),
            environment: se_proc::Environment {
                entries: environment,
            },
            stdio: se_proc::StandardIo {
                stdin: None,
                stdout: None,
                stderr: None,
            },
            mode: se_proc::LaunchMode::Headless,
            window: None,
            // Each agent's sandbox is set on its own thread; the server's scope
            // only routes its temporary files.
            policy: se_proc::LaunchPolicy {
                containment: se_proc::ContainmentRequirement::BestAvailable,
                writes: se_proc::WritePolicy::ReadOnly {
                    scratch: scratch.clone(),
                },
                network: se_proc::NetworkPolicy::Allow,
                hardening: se_proc::OptionalHardening::Off,
            },
            deadline: deadline.at(),
            notifications: Arc::new(events::Wake::default()),
        };
        let native = self.native.clone();
        let prepared = self
            .store
            .pool
            .run_owned(deadline, move || {
                se_proc::NativeStateFiles::create(&scratch)
                    .map_err(|e| error("Codex server temporary directory", e))?;
                native
                    .prepare_launch(reservation, spec)
                    .map_err(super::prepare_error)
            })
            .await?;
        let owner = Arc::new(prepared.process);
        record.checkpoint = self.codex_checkpoint(CheckpointKind::Scope(prepared.checkpoint))?;
        self.save_codex_record(path, &record, deadline).await?;
        let native = self.native.clone();
        let mut ticket = self
            .store
            .pool
            .run_owned(deadline, move || match native.begin_launch(prepared.prepared) {
                LaunchStart::Pending { ticket, .. } => Ok(ticket),
                LaunchStart::Failed(failure) => Err(error("Codex shared server launch", failure.error)),
            })
            .await?;
        loop {
            let native = self.native.clone();
            let (returned, progress) = self
                .store
                .pool
                .run_owned(deadline, move || {
                    let progress = native
                        .poll_launch(&ticket)
                        .map_err(|e| error("Codex shared server launch", e))?;
                    Ok((ticket, progress))
                })
                .await?;
            ticket = returned;
            match progress {
                LaunchProgress::AwaitingExecCommit(root) => {
                    record.checkpoint = self.codex_checkpoint(CheckpointKind::Root(*root))?;
                    self.save_codex_record(path, &record, deadline).await?;
                    let native = self.native.clone();
                    ticket = self
                        .store
                        .pool
                        .run_owned(deadline, move || {
                            native
                                .authorize_exec(&ticket)
                                .map_err(|e| error("Codex shared server exec", e))?;
                            Ok(ticket)
                        })
                        .await?;
                }
                LaunchProgress::Started(success) => {
                    record.checkpoint =
                        self.codex_checkpoint(CheckpointKind::Process(success.record))?;
                    self.save_codex_record(path, &record, deadline).await?;
                    return Ok(owner);
                }
                LaunchProgress::Failed(failure) => {
                    return Err(error("Codex shared server launch", failure.error));
                }
                LaunchProgress::Pending => {
                    tokio::time::sleep(deadline.remaining()?.min(Duration::from_millis(25))).await;
                }
            }
        }
    }

    async fn stop_codex_server(
        &self,
        owner: &Arc<se_proc::OwnedProcess>,
        deadline: &Deadline,
    ) -> Result<se_proc::StopWitness> {
        let native = self.native.clone();
        let process = owner.clone();
        let generation = self.options.epoch.generation;
        let at = deadline.at();
        // Already exited: its exit is the witness. Otherwise one stop request.
        let first: std::result::Result<se_proc::StopAttempt, se_proc::StopWitness> = self
            .store
            .pool
            .run_owned(deadline, move || {
                if let StopObservation::Complete(witness) = native
                    .witness_exit(&process)
                    .map_err(|e| error("Codex shared server exit", e))?
                {
                    return Ok(Err(*witness));
                }
                let prepared = native
                    .prepare_stop(&process, generation, at)
                    .map_err(|e| error("Codex shared server stop", e))?;
                native
                    .request_stop(prepared)
                    .map(Ok)
                    .map_err(|e| error("Codex shared server stop", e))
            })
            .await?;
        let mut attempt = match first {
            Err(witness) => return Ok(witness),
            Ok(attempt) => attempt,
        };
        attempt
            .dispatch
            .map_err(|e| error("Codex shared server stop", e))?;
        loop {
            let native = self.native.clone();
            let (ticket, observed) = self
                .store
                .pool
                .run_owned(deadline, move || {
                    let observed = native
                        .witness_stop(&attempt.ticket)
                        .map_err(|e| error("Codex shared server exit", e))?;
                    Ok((attempt.ticket, observed))
                })
                .await?;
            if let StopObservation::Complete(witness) = observed {
                return Ok(*witness);
            }
            attempt = se_proc::StopAttempt {
                ticket,
                dispatch: Ok(se_proc::StopDispatch::Requested),
            };
            tokio::time::sleep(deadline.remaining()?.min(Duration::from_millis(25))).await;
        }
    }

    fn codex_checkpoint(&self, kind: CheckpointKind) -> Result<Checkpoint> {
        let (lifecycle, publication) = match &kind {
            CheckpointKind::Reservation(v) => (v.lifecycle.clone(), RootPublication::NoChildCreated),
            CheckpointKind::Scope(v) => (v.reservation.lifecycle.clone(), RootPublication::Unpublished),
            CheckpointKind::Root(v) => (v.scope.reservation.lifecycle.clone(), RootPublication::Identified),
            CheckpointKind::Process(v) => (v.lifecycle.clone(), RootPublication::Identified),
            CheckpointKind::Exit { witness, .. } => (
                witness.lifecycle.clone(),
                match witness.root {
                    se_proc::RootWitness::NoChildCreated => RootPublication::NoChildCreated,
                    se_proc::RootWitness::UnpublishedScope
                    | se_proc::RootWitness::PinnedUnpublished { .. } => RootPublication::Unpublished,
                    se_proc::RootWitness::Identified { .. } => RootPublication::Identified,
                },
            ),
            _ => {
                return Err(error(
                    "Codex shared server checkpoint",
                    "a native reservation, scope, root, process or exit is required",
                ));
            }
        };
        Ok(Checkpoint {
            format_version: 1,
            lifecycle,
            // The server belongs to the person whose login it serves.
            principal: CheckpointPrincipal::Human(self.human.clone()),
            session: None,
            root_identity: publication,
            checkpoint: kind,
        })
    }

    async fn read_codex_record(&self, path: &Path, deadline: &Deadline) -> Result<Option<Record>> {
        let path = path.to_owned();
        self.store
            .pool
            .run_owned(deadline, move || {
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(refusal(&path, &format!("the record is unreadable: {e}"))),
                };
                if bytes.len() > RECORD_BYTES {
                    return Err(refusal(&path, "the record exceeds its size bound"));
                }
                let record: Record = serde_json::from_slice(&bytes)
                    .map_err(|e| refusal(&path, &format!("the record is unreadable: {e}")))?;
                se_proc::encode_checkpoint(&record.checkpoint)
                    .map_err(|e| refusal(&path, &format!("the record's custody is invalid: {e:?}")))?;
                if record.version != RECORD_VERSION
                    || record.login.to_local().ok().as_deref()
                        != Some(crate::codex_capture::existing_home()?.as_path())
                {
                    return Err(refusal(&path, "the record names a different version or login"));
                }
                Ok(Some(record))
            })
            .await
    }

    /// Write the record whole and in place of the previous one.
    async fn save_codex_record(&self, path: &Path, record: &Record, deadline: &Deadline) -> Result<()> {
        let bytes = serde_json::to_vec(record).map_err(|e| error("Codex server record", e))?;
        let path = path.to_owned();
        self.store
            .pool
            .run_owned(deadline, move || {
                let directory = path
                    .parent()
                    .ok_or_else(|| error("Codex server record", "a parent directory"))?;
                let files = se_proc::NativeStateFiles::create(directory)
                    .map_err(|e| error("Codex server record directory", e))?;
                // An existing record is replaced against the exact bytes read
                // back here; a first record is published without replacing.
                if let Some(mut current) =
                    se_proc::OwnedFile::open(&path).map_err(|e| error("Codex server record", e))?
                {
                    let expected = current
                        .sha256()
                        .map_err(|e| error("Codex server record", e))?;
                    return current
                        .replace(expected, &bytes)
                        .map_err(|e| error("Codex server record", e));
                }
                let mut staging = files
                    .create_staging(directory)
                    .map_err(|e| error("Codex server record", e))?;
                staging
                    .file
                    .write_all(&bytes)
                    .and_then(|()| staging.file.sync_all())
                    .map_err(|e| error("Codex server record", e))?;
                drop(staging.file);
                files
                    .publish_no_replace(&staging.path, &path)
                    .map_err(|e| error("Codex server record", e))
            })
            .await
    }
}

fn checkpoint_source(checkpoint: &Checkpoint) -> Result<CheckpointSource> {
    Ok(match &checkpoint.checkpoint {
        CheckpointKind::Reservation(v) => CheckpointSource::Reservation(v.clone()),
        CheckpointKind::Scope(v) => CheckpointSource::Scope(v.clone()),
        CheckpointKind::Root(v) => CheckpointSource::Root(v.clone()),
        CheckpointKind::Process(v) => CheckpointSource::Process(v.clone()),
        _ => return Err(error("Codex shared server", "an unretired checkpoint")),
    })
}

fn remove_record(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(refusal(path, &format!("the record cannot be removed: {e}"))),
    }
}

fn refusal(path: &Path, reason: &str) -> se_types::SeError {
    crate::codex_rpc::incompatible(
        &format!("{reason} ({})", path.display()),
        "Stop every Codex agent, make sure no StateEngine-started Codex app-server is still running, then remove that record and relaunch.",
    )
}

/// Whether the login's control socket accepts a connection right now.
async fn served(control: &Path) -> Result<bool> {
    #[cfg(unix)]
    let attempt = tokio::net::UnixStream::connect(control).await.map(drop);
    #[cfg(windows)]
    let attempt = {
        let control = control.to_owned();
        tokio::task::spawn_blocking(move || uds_windows::UnixStream::connect(control).map(drop))
            .await
            .map_err(|e| error("Codex control socket", e))?
    };
    match attempt {
        Ok(()) => Ok(true),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(se_core::scope::unreadable("Codex control socket", &e.to_string())),
    }
}

async fn wait_served(control: &Path, deadline: &Deadline) -> Result<()> {
    let until = tokio::time::Instant::now() + READY.min(deadline.remaining()?);
    while !served(control).await? {
        if tokio::time::Instant::now() >= until {
            return Err(crate::codex_rpc::incompatible(
                &format!("the login's app-server did not open {}", control.display()),
                "Check that `codex app-server --listen unix://` starts for this login, then relaunch.",
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}
