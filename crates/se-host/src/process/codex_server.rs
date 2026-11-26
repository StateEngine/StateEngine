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
use std::{path::Path, time::Duration};

mod record;
mod socket;
mod spec;
use record::{Record, checkpoint_source, refusal, remove_record};
use socket::{probe_served, socket_fits, verify_peer_identity, wait_served};
pub(super) use spec::ServerLaunch;
use spec::codex_server_spec;

const RECORD_VERSION: u16 = 1;
const RECORD_BYTES: usize = 1024 * 1024;
/// A first start on a fresh login has been observed to take about 15 seconds.
const READY: Duration = Duration::from_secs(60);

enum Recovered {
    Started(Arc<se_proc::OwnedProcess>, se_proc::ProcessIdentity),
    /// Its scope exists but the server was never allowed to start.
    Unstarted(Arc<se_proc::OwnedProcess>),
    Exited,
}

#[derive(Default)]
pub(super) struct CodexServer {
    /// Servers this host holds native custody of, with their verified identity, by login.
    slot: tokio::sync::Mutex<
        std::collections::BTreeMap<PathBuf, (Arc<se_proc::OwnedProcess>, se_proc::ProcessIdentity)>,
    >,
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

/// MCP setup and diagnosis read the same login's configuration that launch would choose.
pub(crate) fn mcp_codex_home() -> Result<PathBuf> {
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

impl LaunchCoordinator {
    fn check_sandbox_restart(
        &self,
        login: &Path,
        record: &Record,
        launch: &ServerLaunch,
        requester: &se_types::LifecycleId,
        state: &str,
    ) -> Result<bool> {
        let mismatch = launch.windows_sandbox.is_some()
            && record.windows_sandbox.as_deref() != launch.windows_sandbox;
        if !mismatch {
            return Ok(false);
        }
        if self.other_live_codex_agents(login, Some(requester))? {
            return Err(crate::codex_rpc::incompatible(
                &format!(
                    "the shared Codex app-server for {} is {state} with Windows sandbox {:?}, not {:?}",
                    login.display(),
                    record.windows_sandbox.as_deref().unwrap_or("none"),
                    launch.windows_sandbox.unwrap_or("none"),
                ),
                "Stop running Codex agents on this login before switching windows.sandbox, then retry.",
            ));
        }
        Ok(true)
    }

    /// Make sure the login's shared server is serving before an agent starts.
    /// Returns the verified server identity when Windows sandbox verification
    /// is required so the forwarder enforces it on every live upstream connection.
    pub(super) async fn ensure_codex_server(
        &self,
        login: PathBuf,
        launch: ServerLaunch,
        requester: &se_types::LifecycleId,
        deadline: &Deadline,
    ) -> Result<Option<se_proc::ProcessIdentity>> {
        self.set_codex_login(requester, &login)?;
        let require_verified = launch.windows_sandbox.is_some();
        let control = crate::harness::codex_input::control_socket(&login);
        socket_fits(&control)?;
        let path = self.codex_record(&login);
        let mut slot =
            crate::runtime::pool::within(deadline, self.codex_server.slot.lock()).await?;
        let deadline = &Deadline::idle()?.stage(READY)?;
        let mut record = self.read_codex_record(&path, deadline).await?;
        if let Some(peer) = probe_served(&control).await? {
            let Some(record) = record.take() else {
                if let Some(wanted) = launch.windows_sandbox {
                    return Err(crate::codex_rpc::incompatible(
                        &format!(
                            "an external Codex app-server is already serving {} with an unknown Windows sandbox mode (launch requires {:?})",
                            login.display(),
                            wanted,
                        ),
                        "Stop that external Codex app-server and retry so StateEngine can start one with the configured windows.sandbox.",
                    ));
                }
                return Ok(None);
            };
            let (owner, verified) = match slot.remove(&login) {
                Some(held) => held,
                None => {
                    self.adopt_codex_server(&path, record.clone(), deadline)
                        .await?
                }
            };
            if let Err(err) = verify_peer_identity(&login, peer, &verified, require_verified) {
                slot.insert(login.clone(), (owner, verified));
                return Err(err);
            }
            match self.check_sandbox_restart(&login, &record, &launch, requester, "running") {
                Ok(true) => self.stop_and_remove_codex(owner, &path, deadline).await?,
                Ok(false) => {
                    slot.insert(login.clone(), (owner, verified.clone()));
                    return Ok(require_verified.then_some(verified));
                }
                Err(err) => {
                    slot.insert(login.clone(), (owner, verified));
                    return Err(err);
                }
            }
        }
        if let Some(record) = record {
            match self.recover_codex_server(&path, &record, deadline).await? {
                Recovered::Started(owner, verified) => {
                    match self
                        .check_sandbox_restart(&login, &record, &launch, requester, "starting")
                    {
                        Ok(true) => {
                            self.stop_and_remove_codex(owner, &path, deadline).await?;
                            slot.remove(&login);
                        }
                        Ok(false) => {
                            slot.insert(login.clone(), (owner, verified.clone()));
                            wait_served(&login, &control, &verified, require_verified, deadline)
                                .await?;
                            return Ok(require_verified.then_some(verified));
                        }
                        Err(err) => {
                            slot.insert(login.clone(), (owner, verified));
                            return Err(err);
                        }
                    }
                }
                Recovered::Unstarted(owner) => {
                    self.stop_and_remove_codex(owner, &path, deadline).await?;
                    slot.remove(&login);
                }
                Recovered::Exited => self.remove_codex_record(&path, deadline).await?,
            }
        }
        if let Some((previous, _)) = slot.remove(&login) {
            self.release_ended_codex_server(previous, deadline).await?;
        }
        let (owner, verified) = self
            .start_codex_server(&login, &path, launch, deadline)
            .await?;
        slot.insert(login.clone(), (owner, verified.clone()));
        wait_served(&login, &control, &verified, require_verified, deadline).await?;
        Ok(require_verified.then_some(verified))
    }

    /// After restart, take back custody of every server a previous host
    /// started, whichever login each serves, so each can stop with its agents.
    pub(super) async fn adopt_recorded_codex_server(&self, deadline: &Deadline) -> Result<()> {
        let mut slot =
            crate::runtime::pool::within(deadline, self.codex_server.slot.lock()).await?;
        let mut unresolved = Vec::new();
        for path in self.codex_records(deadline).await? {
            match self.adopt_recorded(&path, deadline).await {
                Ok(Some((login, owner, pid))) => {
                    slot.insert(login, (owner, pid));
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
    ) -> Result<
        Option<(
            PathBuf,
            Arc<se_proc::OwnedProcess>,
            se_proc::ProcessIdentity,
        )>,
    > {
        let Some(record) = self.read_codex_record(path, deadline).await? else {
            return Ok(None);
        };
        let login = record.login.to_local()?;
        let settled = async {
            match self.recover_codex_server(path, &record, deadline).await? {
                Recovered::Started(owner, identity) => Ok(Some((login.clone(), owner, identity))),
                Recovered::Unstarted(owner) => self
                    .stop_and_remove_codex(owner, path, deadline)
                    .await
                    .map(|()| None),
                Recovered::Exited => self
                    .remove_codex_record(path, deadline)
                    .await
                    .map(|()| None),
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
        for (login, (owner, _)) in std::mem::take(&mut *slot) {
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
        self.remove_codex_record(&path, deadline).await
    }

    async fn retire_recorded(&self, path: &Path, deadline: &Deadline) -> Result<()> {
        let Some(record) = self.read_codex_record(path, deadline).await? else {
            return Ok(());
        };
        let login = record.login.to_local()?;
        let settled = async {
            match self.recover_codex_server(path, &record, deadline).await? {
                Recovered::Exited => self.remove_codex_record(path, deadline).await,
                Recovered::Started(owner, _) | Recovered::Unstarted(owner) => {
                    self.stop_and_remove_codex(owner, path, deadline).await
                }
            }
        };
        settled.await.map_err(|failure| for_login(failure, &login))
    }

    async fn stop_and_remove_codex(
        &self,
        owner: Arc<se_proc::OwnedProcess>,
        path: &Path,
        deadline: &Deadline,
    ) -> Result<()> {
        let witness = self.stop_codex_server(&owner, deadline).await?;
        self.release_witnessed_codex_server(owner, witness, deadline)
            .await?;
        self.remove_codex_record(path, deadline).await
    }

    async fn remove_codex_record(&self, path: &Path, deadline: &Deadline) -> Result<()> {
        let path = path.to_path_buf();
        self.store
            .pool
            .run_owned(deadline, move || remove_record(&path))
            .await
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

    fn set_codex_login(&self, lifecycle: &se_types::LifecycleId, login: &Path) -> Result<()> {
        let jobs = self
            .jobs
            .0
            .lock()
            .map_err(|_| error("Codex shared server", "poisoned job registry"))?;
        if let Some(job) = jobs.values().find(|job| &job.lifecycle == lifecycle)
            && let Ok(mut bound) = job.codex_login.lock()
        {
            *bound = se_proc::canonicalize_path(login).ok();
        }
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

    fn other_live_codex_agents(
        &self,
        login: &Path,
        exclude: Option<&se_types::LifecycleId>,
    ) -> Result<bool> {
        let target = se_proc::canonicalize_path(login).ok();
        let jobs = self
            .jobs
            .0
            .lock()
            .map_err(|_| error("Codex shared server", "poisoned job registry"))?;
        Ok(jobs.values().any(|job| {
            if job.provider != se_store::Provider::Codex
                || exclude.is_some_and(|lifecycle| &job.lifecycle == lifecycle)
                || job.settled.load(std::sync::atomic::Ordering::Acquire)
            {
                return false;
            }
            // Jobs bound to a proved different login do not share this login's
            // server; an uncanonicalized/unknown login on either side stays conservative.
            match (
                &target,
                job.codex_login.lock().ok().and_then(|guard| guard.clone()),
            ) {
                (Some(target), Some(bound)) => bound == *target,
                _ => true,
            }
        }))
    }

    async fn adopt_codex_server(
        &self,
        path: &Path,
        record: Record,
        deadline: &Deadline,
    ) -> Result<(Arc<se_proc::OwnedProcess>, se_proc::ProcessIdentity)> {
        match self.recover_codex_server(path, &record, deadline).await? {
            Recovered::Started(owner, identity) => Ok((owner, identity)),
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
                let identity = native_record.root.clone();
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
                Ok(Recovered::Started(Arc::new(process), identity))
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
    ) -> Result<(Arc<se_proc::OwnedProcess>, se_proc::ProcessIdentity)> {
        let reservation = self.codex_reservation()?;
        let lifecycle = reservation.lifecycle.clone();
        let mut record = Record {
            version: RECORD_VERSION,
            login: NativePath::from_local(login.to_owned())?,
            checkpoint: self.codex_checkpoint(CheckpointKind::Reservation(reservation.clone()))?,
            windows_sandbox: launch.windows_sandbox.map(str::to_owned),
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
        let identity = self
            .finish_codex_launch(path, record, ticket, deadline)
            .await?;
        Ok((owner, identity))
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
    ) -> Result<se_proc::ProcessIdentity> {
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
                    let identity = success.record.root.clone();
                    record.checkpoint =
                        self.codex_checkpoint(CheckpointKind::Process(success.record))?;
                    self.save_codex_record(path, &record, deadline).await?;
                    return Ok(identity);
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
