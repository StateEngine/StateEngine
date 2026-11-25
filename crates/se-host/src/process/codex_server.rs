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
use crate::client::lease::Deadline;
use se_proc::{
    Checkpoint, CheckpointKind, CheckpointPrincipal, CheckpointSource, LaunchProgress, LaunchStart,
    ProcessRuntime, RecoveryOutcome, RecoverySource, RootPublication, StopObservation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{ffi::OsString, path::Path, time::Duration};

mod record;
use record::{Record, checkpoint_source, refusal, remove_record};

const RECORD_VERSION: u16 = 1;
const RECORD_BYTES: usize = 1024 * 1024;
/// A first start on a fresh login has been observed to take about 15 seconds.
const READY: Duration = Duration::from_secs(60);

enum Recovered {
    Started(Arc<se_proc::OwnedProcess>),
    /// Its scope exists but the server was never allowed to start.
    Unstarted(Arc<se_proc::OwnedProcess>),
    Exited,
}

#[derive(Default)]
pub(super) struct CodexServer {
    /// Servers this host holds native custody of, by the login they serve.
    slot: tokio::sync::Mutex<std::collections::BTreeMap<PathBuf, Arc<se_proc::OwnedProcess>>>,
}

/// The only read of the host environment on the Codex path. It is private to
/// this module so that nothing after a launch can consult the host for a login.
fn host_codex_home() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("CODEX_HOME") {
        return Ok(PathBuf::from(home));
    }
    let home =
        std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).ok_or_else(|| {
            se_types::SeError::invalid("Codex login", "the normal user home or explicit CODEX_HOME")
        })?;
    Ok(PathBuf::from(home).join(".codex"))
}

/// Only a new launch chooses its login; later readers use the recorded login.
pub(super) fn launch_login(_: &super::launch::NewLaunch) -> Result<PathBuf> {
    host_codex_home()
}

/// The login first setup (provider adoption) prepares. Never an agent's login.
pub(crate) fn setup_codex_login(_: &crate::adoption::FirstSetup) -> Result<PathBuf> {
    host_codex_home()
}

/// Every shared-server diagnostic names the login it concerns.
fn for_login(failure: se_types::SeError, login: &Path) -> se_types::SeError {
    se_core::scope::unreadable(
        "Codex shared server",
        &format!("login {}: {}", login.display(), failure.body),
    )
    .with_cause(failure)
}

/// Complete only when nothing remained unresolved; otherwise name each record.
fn settled(unresolved: Vec<String>) -> Result<()> {
    if unresolved.is_empty() {
        return Ok(());
    }
    Err(se_core::scope::unreadable(
        "Codex shared server custody",
        &format!(
            "{} shared-server record(s) remain unsettled: {}",
            unresolved.len(),
            unresolved.join("; ")
        ),
    ))
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
    /// Make sure the login's shared server is serving before an agent starts.
    pub(super) async fn ensure_codex_server(
        &self,
        login: PathBuf,
        launch: ServerLaunch,
        deadline: &Deadline,
    ) -> Result<()> {
        let control = crate::harness::codex_input::control_socket(&login);
        socket_fits(&control)?;
        let path = self.codex_record(&login);
        let mut slot =
            crate::runtime::pool::within(deadline, self.codex_server.slot.lock()).await?;
        // Starting the shared server is not bounded by the one launch that asked
        // for it: a first start on a fresh login can outlast that launch's
        // deadline, and the server must still finish starting for the next one.
        let deadline = &Deadline::idle()?.stage(READY)?;
        let record = self.read_codex_record(&path, deadline).await?;
        if served(&control).await? {
            match record {
                // Someone else's server on this login: use it, never stop it.
                None => return Ok(()),
                Some(record) => {
                    if !slot.contains_key(&login) {
                        let owner = self.adopt_codex_server(&path, record, deadline).await?;
                        slot.insert(login.clone(), owner);
                    }
                    return Ok(());
                }
            }
        }
        if let Some(record) = record {
            // Recorded but not serving: still starting, or gone.
            match self.recover_codex_server(&path, &record, deadline).await? {
                Recovered::Started(owner) => {
                    slot.insert(login.clone(), owner);
                    return wait_served(&control, deadline).await;
                }
                // A start that never reached exec will never serve: end it.
                Recovered::Unstarted(owner) => {
                    let witness = self.stop_codex_server(&owner, deadline).await?;
                    self.release_witnessed_codex_server(owner, witness, deadline)
                        .await?;
                    remove_record(&path)?;
                    slot.remove(&login);
                }
                Recovered::Exited => remove_record(&path)?,
            }
        }
        // A server this host started that has since ended: witness its exit and
        // release its scope before starting another.
        if let Some(previous) = slot.remove(&login) {
            self.release_ended_codex_server(previous, deadline).await?;
        }
        let owner = self
            .start_codex_server(&login, &path, launch, deadline)
            .await?;
        slot.insert(login.clone(), owner);
        wait_served(&control, deadline).await
    }

    /// After restart, take back custody of every server a previous host
    /// started, whichever login each serves, so each can stop with its agents.
    pub(super) async fn adopt_recorded_codex_server(&self, deadline: &Deadline) -> Result<()> {
        let mut slot =
            crate::runtime::pool::within(deadline, self.codex_server.slot.lock()).await?;
        let mut unresolved = Vec::new();
        for path in self.codex_records(deadline).await? {
            match self.adopt_recorded(&path, deadline).await {
                Ok(Some((login, owner))) => {
                    slot.insert(login, owner);
                }
                Ok(None) => {}
                Err(failure) => unresolved.push(failure.body.to_string()),
            }
        }
        settled(unresolved)
    }

    /// One record: its server re-adopted, or ended and the record removed.
    async fn adopt_recorded(
        &self,
        path: &Path,
        deadline: &Deadline,
    ) -> Result<Option<(PathBuf, Arc<se_proc::OwnedProcess>)>> {
        let Some(record) = self.read_codex_record(path, deadline).await? else {
            return Ok(None);
        };
        let login = record.login.to_local()?;
        let settled = async {
            match self.recover_codex_server(path, &record, deadline).await? {
                Recovered::Started(owner) => Ok(Some((login.clone(), owner))),
                Recovered::Unstarted(owner) => {
                    let witness = self.stop_codex_server(&owner, deadline).await?;
                    self.release_witnessed_codex_server(owner, witness, deadline)
                        .await?;
                    remove_record(path).map(|()| None)
                }
                Recovered::Exited => remove_record(path).map(|()| None),
            }
        };
        settled.await.map_err(|failure| for_login(failure, &login))
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

    /// Once no Codex agent remains, stop every server this host holds and
    /// settle every record under the state home, whichever login each names.
    /// Complete only when every record is settled.
    pub(super) async fn retire_idle_codex_server(&self, deadline: &Deadline) -> Result<()> {
        let mut slot =
            crate::runtime::pool::within(deadline, self.codex_server.slot.lock()).await?;
        if self.live_codex_agents()? {
            return Ok(());
        }
        let mut unresolved = Vec::new();
        // Servers held by native custody are ours whatever their records say.
        for (login, owner) in std::mem::take(&mut *slot) {
            if let Err(failure) = self.retire_held(&login, owner, deadline).await {
                unresolved.push(for_login(failure, &login).body.to_string());
            }
        }
        // Every record still present is settled on its own custody.
        for path in self.codex_records(deadline).await? {
            if let Err(failure) = self.retire_recorded(&path, deadline).await {
                unresolved.push(failure.body.to_string());
            }
        }
        settled(unresolved)
    }

    async fn retire_held(
        &self,
        login: &Path,
        owner: Arc<se_proc::OwnedProcess>,
        deadline: &Deadline,
    ) -> Result<()> {
        let path = self.codex_record(login);
        let witness = self.stop_codex_server(&owner, deadline).await?;
        let lifecycle = witness.lifecycle.clone();
        self.release_witnessed_codex_server(owner, witness.clone(), deadline)
            .await?;
        let Some(record) = self.read_codex_record(&path, deadline).await? else {
            return Ok(());
        };
        if record.checkpoint.lifecycle != lifecycle {
            // A record of an earlier server: settled with the others below.
            return Ok(());
        }
        let source = checkpoint_source(&record.checkpoint)?;
        self.save_codex_record(
            &path,
            &Record {
                checkpoint: self.codex_checkpoint(CheckpointKind::Exit {
                    source: Box::new(source),
                    witness,
                })?,
                ..record
            },
            deadline,
        )
        .await?;
        remove_record(&path)
    }

    async fn retire_recorded(&self, path: &Path, deadline: &Deadline) -> Result<()> {
        let Some(record) = self.read_codex_record(path, deadline).await? else {
            return Ok(());
        };
        let login = record.login.to_local()?;
        let settled = async {
            match self.recover_codex_server(path, &record, deadline).await? {
                Recovered::Exited => remove_record(path),
                Recovered::Started(owner) | Recovered::Unstarted(owner) => {
                    let witness = self.stop_codex_server(&owner, deadline).await?;
                    self.release_witnessed_codex_server(owner, witness, deadline)
                        .await?;
                    remove_record(path)
                }
            }
        };
        settled.await.map_err(|failure| for_login(failure, &login))
    }

    async fn release_witnessed_codex_server(
        &self,
        owner: Arc<se_proc::OwnedProcess>,
        witness: se_proc::StopWitness,
        deadline: &Deadline,
    ) -> Result<()> {
        let native = self.native.clone();
        self.store
            .pool
            .run_owned(deadline, move || {
                native
                    .release(&owner, &witness)
                    .map_err(|e| error("Codex shared server release", e))
            })
            .await
    }

    async fn release_ended_codex_server(
        &self,
        owner: Arc<se_proc::OwnedProcess>,
        deadline: &Deadline,
    ) -> Result<()> {
        let native = self.native.clone();
        self.store
            .pool
            .run_owned(deadline, move || {
                match native
                    .witness_exit(&owner)
                    .map_err(|e| error("Codex shared server exit", e))?
                {
                    StopObservation::Complete(witness) => native
                        .release(&owner, &witness)
                        .map_err(|e| error("Codex shared server release", e)),
                    _ => Err(error(
                        "Codex shared server",
                        "the server this host started is not serving but has not exited; preserve it for reconciliation",
                    )),
                }
            })
            .await
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
        match self.recover_codex_server(path, &record, deadline).await? {
            Recovered::Started(owner) => Ok(owner),
            _ => Err(refusal(
                path,
                "the recorded server is not the one serving its socket",
            )),
        }
    }

    /// Re-adopt the recorded scope.
    async fn recover_codex_server(
        &self,
        path: &Path,
        record: &Record,
        deadline: &Deadline,
    ) -> Result<Recovered> {
        let source = match &record.checkpoint.checkpoint {
            CheckpointKind::Reservation(v) => RecoverySource::Reservation(Box::new(v.clone())),
            CheckpointKind::Scope(v) => RecoverySource::Prepared(Box::new(v.clone())),
            CheckpointKind::Root(v) => RecoverySource::RootPrepared(Box::new(v.clone())),
            CheckpointKind::Process(v) => RecoverySource::Record(Box::new(v.clone())),
            _ => return Ok(Recovered::Exited),
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
            RecoveryOutcome::Recovered {
                process,
                record: native_record,
            } => {
                self.save_codex_record(
                    path,
                    &Record {
                        checkpoint: self
                            .codex_checkpoint(CheckpointKind::Process(*native_record))?,
                        ..record.clone()
                    },
                    deadline,
                )
                .await?;
                Ok(Recovered::Started(Arc::new(process)))
            }
            RecoveryOutcome::PendingScope { process, .. } => {
                Ok(Recovered::Unstarted(Arc::new(process)))
            }
            RecoveryOutcome::Exited(_) => Ok(Recovered::Exited),
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
        let reservation = self.codex_reservation()?;
        let lifecycle = reservation.lifecycle.clone();
        let mut record = Record {
            version: RECORD_VERSION,
            login: NativePath::from_local(login.to_owned())?,
            checkpoint: self.codex_checkpoint(CheckpointKind::Reservation(reservation.clone()))?,
        };
        self.save_codex_record(path, &record, deadline).await?;
        let scratch = path.with_extension("tmp");
        let spec = codex_server_spec(
            lifecycle,
            self.options.epoch.generation,
            login,
            launch,
            &scratch,
            deadline,
        );
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
        let ticket = self
            .store
            .pool
            .run_owned(deadline, move || {
                match native.begin_launch(prepared.prepared) {
                    LaunchStart::Pending { ticket, .. } => Ok(ticket),
                    LaunchStart::Failed(failure) => {
                        Err(error("Codex shared server launch", failure.error))
                    }
                }
            })
            .await?;
        self.finish_codex_launch(path, record, ticket, deadline)
            .await?;
        Ok(owner)
    }

    fn codex_reservation(&self) -> Result<se_proc::LaunchReservation> {
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
        Ok(reservation)
    }

    /// Record each exec barrier and authorize it until the server has started.
    async fn finish_codex_launch(
        &self,
        path: &Path,
        mut record: Record,
        mut ticket: se_proc::LaunchTicket,
        deadline: &Deadline,
    ) -> Result<()> {
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
                    return self.save_codex_record(path, &record, deadline).await;
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
}

/// The stock server on the login's default control socket, in its own scope.
fn codex_server_spec(
    lifecycle: se_types::LifecycleId,
    generation: se_proc::GenerationId,
    login: &Path,
    launch: ServerLaunch,
    scratch: &Path,
    deadline: &Deadline,
) -> se_proc::LaunchSpec {
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
    se_proc::LaunchSpec {
        executable_custody: None,
        lifecycle,
        generation,
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
        mode: se_proc::LaunchMode::HeadlessPersistent,
        window: None,
        // Each agent's sandbox is set on its own thread; the server's scope
        // only routes its temporary files.
        policy: se_proc::LaunchPolicy {
            containment: se_proc::ContainmentRequirement::BestAvailable,
            writes: se_proc::WritePolicy::ReadOnly {
                scratch: scratch.to_owned(),
            },
            network: se_proc::NetworkPolicy::Allow,
            hardening: se_proc::OptionalHardening::Off,
        },
        deadline: deadline.at(),
        notifications: Arc::new(events::Wake::default()),
    }
}

/// A local socket address holds a short path: 104 bytes with its terminator on
/// macOS, 108 elsewhere. The stock server refuses a longer one too.
fn socket_fits(control: &Path) -> Result<()> {
    const LIMIT: usize = if cfg!(target_os = "macos") { 103 } else { 107 };
    let length = control.as_os_str().as_encoded_bytes().len();
    if length > LIMIT {
        return Err(crate::codex_rpc::incompatible(
            &format!(
                "the Codex login's control socket path is {length} bytes, longer than the {LIMIT} a local socket allows ({})",
                control.display()
            ),
            "Set CODEX_HOME to a shorter folder (for example one directly under your home folder), sign in to Codex there, and relaunch.",
        ));
    }
    Ok(())
}

/// Whether the login's control socket accepts a connection right now.
async fn served(control: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(control) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(se_core::scope::unreadable(
                "Codex control socket",
                &e.to_string(),
            ));
        }
        Ok(_) => {}
    }
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
        // A socket file nobody listens on: refused, or on Windows WSAENETDOWN.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) || (cfg!(windows) && e.raw_os_error() == Some(10050)) =>
        {
            Ok(false)
        }
        Err(e) => Err(se_core::scope::unreadable(
            "Codex control socket",
            &e.to_string(),
        )),
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
