//! Shared helpers for the two W3 real-host judge test roots (doc 90,
//! black-box): CLI-driven trusted setup, public readback, the linked host
//! judge and the store witness. Test-specific imports stay in each root.
use se_store::{
    Admission, EventBody, ReadBudget, ReadScope, Scope, Snapshot, SqliteFactory, SqliteReader,
    SqliteSnapshot, StoreOptions, StoredEvent, StoredText, Visibility,
};
use se_types::Read;
use secode_stateengine_api as api;
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const TEST_AGENT: &str = "w3judge";
const TEST_NAME: &str = "w3judge";
// ---------------------------------------------------------------- helpers

pub(super) fn require_se() -> Result<PathBuf, ()> {
    match std::env::var_os("SE_W3_SE_BIN") {
        Some(path) if !path.is_empty() => {
            let path = PathBuf::from(path);
            if path.is_file() { Ok(path) } else { Err(()) }
        }
        _ => Err(()),
    }
}
pub(super) fn missing_helper() -> ! {
    panic!("SE_W3_SE_BIN must name a real se binary; W3 was not exercised");
}
pub(super) fn judge_root(label: &str) -> PathBuf {
    // Keep the state home short: the host's protected runtime socket is a
    // Unix domain socket whose full path is capped (~108 bytes), and the home
    // is the base for that path. The deep CARGO_MANIFEST_DIR/target tree
    // overflows the cap, so anchor under the system temp dir with the same
    // per-process, per-test unique name.
    let base = std::env::temp_dir().join("w3j");
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    base.join(format!(
        "{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}
/// A clean owner-terminal environment: no session, no provider markers.
pub(super) fn owner_env(home: &Path) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    let mut env = Vec::new();
    for name in [
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TERM",
        "XDG_RUNTIME_DIR",
        "SYSTEMROOT",
        "WINDIR",
        "LOCALAPPDATA",
        "TMPDIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            env.push((name.into(), value));
        }
    }
    env.push(("TERM".into(), "dumb".into()));
    env.push(("SE_HOME".into(), home.as_os_str().to_os_string()));
    env
}
fn run_se(helper: &Path, home: &Path, args: &[&str]) -> Result<Output, String> {
    let mut command = Command::new(helper);
    command
        .args(args)
        .env_clear()
        .envs(owner_env(home))
        .stdin(std::process::Stdio::null());
    command.output().map_err(|e| {
        format!(
            "se {} failed to start: {e}",
            args.first().copied().unwrap_or_default()
        )
    })
}
fn run_se_ok(helper: &Path, home: &Path, args: &[&str]) -> Result<String, String> {
    // A concurrent install/uninstall on the shared box holds the installation
    // claim; the refusal names retry as the legal alternative, so a bounded
    // retry with backoff is the faithful consumer behavior.
    let mut attempts = 0u32;
    loop {
        let output = run_se(helper, home, args)?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if stderr.contains("installation record is busy") && attempts < 5 {
            attempts += 1;
            std::thread::sleep(Duration::from_secs(2 * u64::from(attempts)));
            continue;
        }
        return Err(format!(
            "se {} exited {}: {}",
            args.first().copied().unwrap_or_default(),
            output.status,
            stderr
        ));
    }
}
fn extract_id(text: &str, prefix: &str) -> Option<String> {
    // Return the full canonical id (prefix + 36-char UUIDv7): the store and
    // the linked api both round-trip the prefixed form, so a bare suffix is
    // rejected by the documented legacy grammar.
    let start = text.find(prefix)?;
    let rest = &text[start + prefix.len()..];
    let suffix: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(36)
        .collect();
    if suffix.len() == 36 {
        Some(format!("{}{}", prefix, suffix))
    } else {
        None
    }
}
pub(super) fn init_project(
    helper: &Path,
    root: &Path,
) -> Result<(PathBuf, String, String), String> {
    let home = root.join("home");
    let repo = root.join("repo");
    for path in [home.clone(), repo.clone()] {
        se_proc::NativeStateFiles::create(&path)
            .map_err(|e| format!("create private {}: {e}", path.display()))?;
    }
    let stdout = run_se_ok(
        helper,
        &home,
        &[
            "init",
            "--json",
            "--repo",
            repo.to_str().ok_or("repo path is not UTF-8")?,
            "--name",
            TEST_NAME,
            "--agent",
            TEST_AGENT,
        ],
    )?;
    let project = extract_id(&stdout, "prj_").ok_or("se init output lost the project id")?;
    let agent = extract_id(&stdout, "ag_").ok_or("se init output lost the agent id")?;
    Ok((home, project, agent))
}

#[derive(Debug, Default)]
pub(super) struct NoopCancellation;
impl api::Cancellation for NoopCancellation {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn cancelled(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}
fn call_options(generation: api::Generation, timeout: Duration) -> api::CallOptions {
    api::CallOptions {
        generation,
        timeout,
        cancellation: Arc::new(NoopCancellation),
    }
}

/// SE Code's service half of the integration. This judge targets the engine
/// side of the linked boundary; services are driven by the product consumer
/// judge, so every method refuses by name instead of inventing an outcome.
struct SilentServices;
fn services_refused() -> api::ApiError {
    api::ApiError {
        kind: api::ApiFailure::NotIncluded,
        code: "judge-services".into(),
        message: "the host-level judge does not exercise SE Code services".into(),
        remedy: api::ApiRemedy {
            text: "Drive services through the product consumer judge.".into(),
            command: None,
        },
        retry: api::ApiRetry::Never,
    }
}
impl api::HostServices for SilentServices {
    fn hold<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _reason: api::HoldReason,
        _key: api::IdempotencyKey,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::HoldReceipt> {
        Box::pin(async { Err(services_refused()) })
    }
    fn interrupt<'a>(
        &'a self,
        _held: &'a api::HoldReceipt,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::InterruptReceipt> {
        Box::pin(async { Err(services_refused()) })
    }
    fn active_session<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<Option<api::ActiveSession>>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn active_sessions<'a>(
        &'a self,
        _epoch: &'a api::HostEpoch,
        _page: api::PageRequest,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::Page<api::ActiveSession>>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn idle<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::SessionActivity>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn binding_state<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::BindingObservation>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn adopt_binding<'a>(
        &'a self,
        _request: api::AdoptBinding,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::BindingObservation>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn update_mail_target<'a>(
        &'a self,
        _transition: api::TargetTransition,
        _key: api::IdempotencyKey,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::TargetReceipt> {
        Box::pin(async { Err(services_refused()) })
    }
    fn deliver_notice<'a>(
        &'a self,
        _notice: &'a api::MailNotice,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::NoticeAdmission> {
        Box::pin(async { Err(services_refused()) })
    }
    fn notice_status<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _notice: &'a api::NoticeId,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::NoticeAdmission>> {
        Box::pin(async { Err(services_refused()) })
    }
}

/// The epoch of this exact judge process at `generation`, observed through the
/// same public native facts the embedded host verifies against.
fn build_epoch(generation: u64, home: &Path) -> Result<api::HostEpoch, String> {
    let files =
        se_host::state_files::Files::open(home).map_err(|e| format!("state files: {e:?}"))?;
    let machine = se_host::state_files::machine_identity(&files)
        .map_err(|e| format!("machine identity: {e}"))?;
    #[cfg(any(target_os = "linux", windows))]
    let boot = se_proc::current_runtime_identity(machine.clone())
        .map_err(|e| format!("runtime identity: {e:?}"))?
        .boot_id;
    #[cfg(target_os = "macos")]
    let boot = se_proc::observe_boot_id().map_err(|e| format!("boot identity: {e:?}"))?;
    // This debug judge binary is ~150 MiB and the workspace SHA-256 is
    // software-only on the shared box, so the one-time self-proof hash needs
    // more than the 5 s default proof bound (measured: a 28 MiB probe hashes
    // in ~2.3 s of user CPU, i.e. ~12 s for this binary). The bound is a
    // latency guard, not the integrity check: the full executable hash is
    // still computed and verified, just on a harness-sized budget.
    let bound = se_proc::native_ipc::IpcIoBound {
        deadline: std::time::Instant::now() + Duration::from_secs(120),
        cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let peer = se_proc::native_ipc::observe_ipc_self_bounded(&bound)
        .map_err(|e| format!("native self proof: {e:?}"))?;
    let pid = std::num::NonZeroU32::new(peer.pid()).ok_or("the judge process has a zero pid")?;
    let owner = se_types::ProcessInstance::from_observation(se_types::ProcessFields {
        machine,
        boot,
        pid,
        started: peer.started().clone(),
        executable: peer.image().clone(),
        argv_sha256: argv_digest(),
    })
    .map_err(|e| format!("process observation: {e}"))?;
    peer.verify_instance(&owner, peer.image_sha256())
        .map_err(|e| format!("instance verification: {e}"))?;
    let core = se_types::HostEpoch {
        owner,
        generation: se_types::HostGeneration::new(generation)
            .map_err(|e| format!("host generation: {e}"))?,
    };
    se_host::linked::host_epoch(&core).map_err(|e| format!("linked epoch: {e}"))
}
/// Length-prefixed native argv bytes, the same digest the standalone child uses.
fn argv_digest() -> se_types::Sha256 {
    let mut hasher = Sha256::new();
    for arg in std::env::args_os() {
        #[cfg(unix)]
        let bytes = arg.as_encoded_bytes().to_vec();
        #[cfg(not(unix))]
        let bytes: Vec<u8> = arg.encode_wide().flat_map(u16::to_le_bytes).collect();
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    se_types::Sha256::from_bytes(hasher.finalize().into())
}

// ---------------------------------------------------------------- judge

pub(super) struct Judge {
    pub(super) runtime: tokio::runtime::Runtime,
    pub(super) factory: Arc<dyn api::HostFactory>,
    pub(super) helper: PathBuf,
    pub(super) root: PathBuf,
    pub(super) home: PathBuf,
    pub(super) project: String,
    pub(super) agent: String,
    pub(super) retain: bool,
}
impl Drop for Judge {
    fn drop(&mut self) {
        if self.retain || std::thread::panicking() {
            eprintln!("W3 retained fixture: {}", self.root.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}
// The judge helpers carry the public ApiError by value so refusals can be
// asserted by code and message, and capture's arguments mirror the public
// capture surface 1:1.
#[allow(clippy::result_large_err)]
#[allow(clippy::too_many_arguments)]
impl Judge {
    pub(super) fn new(label: &str) -> Result<Self, String> {
        let helper = require_se().map_err(|_| "se binary missing".to_owned())?;
        let root = judge_root(label);
        let (home, project, agent) = init_project(&helper, &root)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("judge runtime: {e}"))?;
        let factory = se_host::embedded_factory(runtime.handle().clone());
        Ok(Self {
            runtime,
            factory,
            helper,
            root,
            home,
            project,
            agent,
            retain: false,
        })
    }
    fn config(&self) -> api::HostConfig {
        api::HostConfig {
            state_home: self.home.clone(),
            helper_executable: self.helper.clone(),
            linux_delegation: api::LinuxDelegation::AutoUserManager,
            api: api::API_VERSION,
            kind: api::HostKind::EmbeddedSecode,
            features: vec![api::Feature::LocalListener],
            limits: api::Limits {
                page_items: std::num::NonZeroU32::new(100).ok_or_missing(),
                payload_bytes: std::num::NonZeroU32::new(256 * 1024).ok_or_missing(),
                notice_ids: std::num::NonZeroU32::new(100).ok_or_missing(),
            },
        }
    }
    pub(super) fn open(&self) -> Result<api::OpenedHost, String> {
        let factory = self.factory.clone();
        let config = self.config();
        let options = api::OpenOptions {
            expected_generation: None,
            timeout: Duration::from_secs(10),
            cancellation: Arc::new(NoopCancellation),
        };
        self.runtime
            .block_on(async move {
                factory
                    .open(config, options)
                    .await
                    .map_err(|e| format!("open: {e:?}"))
            })
            .and_then(|read| match read {
                api::Read::Present { value } => Ok(value),
                api::Read::Absent { checked } => Err(format!("store absent: {checked}")),
                api::Read::Unreadable { source, reason, .. } => {
                    Err(format!("store unreadable: {source}: {reason}"))
                }
                api::Read::Unknown { what } => Err(format!("store unknown: {what}")),
            })
    }
    pub(super) fn activate(&self, opened: &api::OpenedHost) -> Result<api::Generation, String> {
        let generation = opened.negotiated.generation;
        let epoch = build_epoch(generation.0, &self.home)?;
        let host = opened.host.clone();
        let services = Arc::new(SilentServices);
        let options = call_options(generation, Duration::from_secs(30));
        self.runtime.block_on(async move {
            let readiness = host
                .activate(
                    api::HostIntegration::Secode { epoch, services },
                    options.clone(),
                )
                .await
                .map_err(|e| format!("activate: {e:?}"))?;
            if !matches!(readiness, api::Readiness::Ready) {
                return Err(format!("readiness: {readiness:?}"));
            }
            // activate blocks until the generation is Ready and sets the
            // health to Ready before returning Readiness::Ready, so the
            // non-blocking health snapshot must already agree.
            let health = host.health();
            if health != api::GenerationHealth::Ready {
                return Err(format!("health: {health:?}"));
            }
            Ok(())
        })?;
        Ok(generation)
    }
    pub(super) fn bind(
        &self,
        host: &Arc<dyn api::Host>,
        generation: api::Generation,
        conversation: &str,
        key: &str,
    ) -> Result<api::IssuedSession, api::ApiError> {
        let request = api::BindingRequest {
            project: api::ProjectId(self.project.clone()),
            agent: api::AgentId(self.agent.clone()),
            harness: api::Harness::Secode,
            model: api::ModelIdentity {
                provider: "deterministic".into(),
                model: "local-script".into(),
            },
            conversation: api::ProviderSessionId(conversation.into()),
            target: None,
            expected_binding_revision: None,
            capture_consent: true,
            idempotency_key: api::IdempotencyKey(key.into()),
        };
        let authority = api::BindingAuthority::Owner(api::OwnerAuthority);
        let options = call_options(generation, Duration::from_secs(20));
        self.runtime
            .block_on(host.bind_session(&authority, request, options))
    }
    pub(super) fn capture(
        &self,
        host: &Arc<dyn api::Host>,
        session: &api::BoundSession,
        generation: api::Generation,
        conversation: &str,
        role: api::TurnRole,
        vendor_turn: &str,
        text: &str,
        key: &str,
    ) -> Result<api::Receipt<api::EventRef>, api::ApiError> {
        let turn = api::CapturedTurn {
            conversation: api::ProviderSessionId(conversation.into()),
            vendor_turn: vendor_turn.into(),
            vendor_event: Some(format!("evt-{vendor_turn}")),
            machine_id: None,
            source_ref: Some(format!("secode-event:{vendor_turn}")),
            source_cli: "secode".into(),
            nesting: None,
            role,
            occurred_at: api::UnixMicros(turn_occurred_micros(vendor_turn)),
            content: api::BoundedText {
                text: text.into(),
                utf8_bytes: text.len() as u64,
                complete: true,
                omitted_bytes: Some(0),
            },
            source_sha256: api::Sha256(Sha256::digest(text.as_bytes()).into()),
            idempotency_key: api::IdempotencyKey(key.into()),
        };
        self.capture_with(host, session, generation, turn)
    }
    pub(super) fn capture_with(
        &self,
        host: &Arc<dyn api::Host>,
        session: &api::BoundSession,
        generation: api::Generation,
        turn: api::CapturedTurn,
    ) -> Result<api::Receipt<api::EventRef>, api::ApiError> {
        let options = call_options(generation, Duration::from_secs(20));
        self.runtime
            .block_on(host.capture_turn(session, turn, options))
    }
    pub(super) fn continuity(
        &self,
        host: &Arc<dyn api::Host>,
        session: &api::BoundSession,
        generation: api::Generation,
    ) -> Result<api::SessionContext, api::ApiError> {
        let request = api::ContinuityRequest {
            page: api::PageRequest {
                after: None,
                limit: 50,
                max_bytes: 128 * 1024,
            },
            acknowledge_packet: None,
        };
        let options = call_options(generation, Duration::from_secs(20));
        self.runtime
            .block_on(host.continuity(session, request, options))
    }
    pub(super) fn revoke(
        &self,
        host: &Arc<dyn api::Host>,
        generation: api::Generation,
        session: &str,
        key: &str,
    ) -> Result<api::Receipt<api::SessionIdentity>, api::ApiError> {
        let request = api::RevokeRequest {
            session: api::SessionId(session.into()),
            reason: api::EndReason::Replaced,
            key: api::IdempotencyKey(key.into()),
        };
        let authority = api::Authority::Owner(api::OwnerAuthority);
        let options = call_options(generation, Duration::from_secs(20));
        self.runtime
            .block_on(host.revoke_session(&authority, request, options))
    }
    pub(super) fn drain_close(
        &self,
        host: &Arc<dyn api::Host>,
        generation: api::Generation,
    ) -> Result<api::DrainReceipt, String> {
        let options = call_options(generation, Duration::from_secs(30));
        self.runtime.block_on(async move {
            let receipt = host
                .drain(options.clone())
                .await
                .map_err(|e| format!("drain: {e:?}"))?;
            let closed = host
                .close(receipt.clone(), options)
                .await
                .map_err(|e| format!("close: {e:?}"))?;
            if closed != receipt {
                return Err("close returned a different drain receipt".to_owned());
            }
            Ok(receipt)
        })
    }
    fn public_turn(&self, event: &str) -> Result<serde_json::Value, String> {
        let output = run_se_ok(
            &self.helper,
            &self.home,
            &[
                "history",
                "--event",
                event,
                "--project",
                &self.project,
                "--json",
            ],
        )?;
        serde_json::from_str(&output).map_err(|e| format!("public history JSON: {e}"))
    }
}

pub(super) fn api_read_kind<T>(read: &api::Read<T>) -> &'static str {
    match read {
        api::Read::Present { .. } => "Present",
        api::Read::Absent { .. } => "Absent",
        api::Read::Unreadable { .. } => "Unreadable",
        api::Read::Unknown { .. } => "Unknown",
    }
}
pub(super) fn stored_text_kind(text: &StoredText) -> &'static str {
    match text {
        StoredText::Present(_) => "Present",
        StoredText::Erased { .. } => "Erased",
    }
}
pub(super) fn body_kind(body: &EventBody<StoredText>) -> &'static str {
    match body {
        EventBody::SessionPrepared { .. } => "SessionPrepared",
        EventBody::SessionActivated { .. } => "SessionActivated",
        EventBody::SessionEnded { .. } => "SessionEnded",
        EventBody::SessionRevoked { .. } => "SessionRevoked",
        EventBody::SessionTurn { .. } => "SessionTurn",
        _ => "another event kind",
    }
}
fn hex_lower_sha256(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
pub(super) fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Stable per vendor turn: the capture natural key embeds occurred_at, so the
/// original and its replay must name the same source.
fn turn_occurred_micros(vendor_turn: &str) -> u64 {
    let index: u64 = vendor_turn
        .rsplit_once('-')
        .and_then(|(_, suffix)| suffix.parse().ok())
        .unwrap_or(1);
    1_700_000_000_000_000 + index * 1_000_000
}

// ---------------------------------------------------------------- store witness

fn open_reader(home: &Path) -> Result<SqliteReader, String> {
    let options = StoreOptions {
        state_directory: home.to_path_buf(),
        busy_timeout: Duration::from_secs(5),
    };
    // Reader capacity is bounded 2..=8 by the store; match the candidate's
    // own test convention.
    match SqliteFactory::open_reader_with_capacity(
        &options,
        std::num::NonZeroU32::new(8).ok_or_missing(),
    ) {
        Ok(Read::Present { value }) => Ok(value),
        Ok(Read::Absent { checked }) => Err(format!("store absent: {checked}")),
        Ok(Read::Unreadable { source, reason, .. }) => {
            Err(format!("store unreadable: {source}: {reason}"))
        }
        Ok(Read::Unknown { what }) => Err(format!("store unknown: {what}")),
        Err(error) => Err(format!("store open: {error:?}")),
    }
}
fn agent_scope(judge: &Judge, generation: u64) -> Result<ReadScope, String> {
    let project = se_types::ProjectId::try_from(judge.project.clone())
        .map_err(|e| format!("project id: {e}"))?;
    let agent =
        se_types::AgentId::try_from(judge.agent.clone()).map_err(|e| format!("agent id: {e}"))?;
    Ok(ReadScope {
        admission: Admission {
            scope: Scope::Project(project),
            actor: se_store::Actor::Agent(agent.clone()),
            session: None,
            generation,
        },
        visibility: Visibility::SelfOnly(agent),
    })
}
pub(super) fn witness<T: Send, E: std::fmt::Display + Send>(
    judge: &Judge,
    generation: u64,
    work: impl FnOnce(&mut SqliteSnapshot) -> Result<T, E> + Send + 'static,
) -> Result<T, String> {
    let reader = open_reader(&judge.home)?;
    use se_store::ReadStore;
    let mut snapshot = reader
        .snapshot(agent_scope(judge, generation)?)
        .map_err(|e| format!("snapshot: {e:?}"))?;
    let result = work(&mut snapshot);
    match (result, snapshot.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(format!("store read: {error}")),
        (Ok(_), Err(error)) => Err(format!("snapshot close: {error:?}")),
    }
}
pub(super) fn turn_rows(judge: &Judge, generation: u64) -> Result<Vec<StoredEvent>, String> {
    let agent =
        se_types::AgentId::try_from(judge.agent.clone()).map_err(|e| format!("agent id: {e}"))?;
    let budget = ReadBudget {
        page: se_types::PageRequest {
            after: None,
            limit: std::num::NonZeroU32::new(100).ok_or_missing(),
            max_bytes: std::num::NonZeroU32::new(1024 * 1024).ok_or_missing(),
        },
        deadline: Duration::from_secs(5),
    };
    let page = witness(judge, generation, move |snap| {
        snap.turns(agent.clone(), budget)
    })?;
    Ok(page.into_items())
}
pub(super) fn session_record(
    judge: &Judge,
    generation: u64,
    session: &str,
) -> Result<se_store::ProjectionRecord, String> {
    let id = se_types::SessionId::try_from(session.to_owned())
        .map_err(|e| format!("session id: {e}"))?;
    witness(judge, generation, move |snap| {
        let read = snap
            .session(id.clone())
            .map_err(|e| format!("session read: {e:?}"))?;
        match read {
            Read::Present { value } => Ok(value),
            Read::Absent { checked } => Err(format!("session absent: {checked}")),
            Read::Unreadable { source, reason, .. } => {
                Err(format!("session unreadable: {source}: {reason}"))
            }
            Read::Unknown { what } => Err(format!("session unknown: {what}")),
        }
    })
}
pub(super) fn body_text(body: &EventBody<StoredText>, name: &str) -> Result<String, String> {
    match body {
        EventBody::SessionRevoked {
            reason: StoredText::Present(text),
            ..
        } => {
            let _ = name;
            Ok(text.clone())
        }
        other => Err(format!(
            "{name}: expected SessionRevoked, got {}",
            body_kind(other)
        )),
    }
}
pub(super) fn assert_public_turn(
    judge: &Judge,
    event: &str,
    conversation: &str,
    role: &str,
    vendor: &str,
    text: &str,
) -> Result<(), String> {
    let public = judge.public_turn(event)?;
    if public["schema"] != "se.event/v1"
        || public["kind"] != "session.turn"
        || public["event_id"] != event
    {
        return Err("public history returned a different event or family".into());
    }
    let payload = public.get("payload").ok_or("public event has no payload")?;
    let source = payload
        .get("source")
        .and_then(|v| v.as_str())
        .ok_or("public history has no capture source")?;
    if source != "app-server" {
        return Err(format!(
            "public history source is {source:?}, not the native app-server provenance"
        ));
    }
    let got_role = payload
        .get("role")
        .and_then(|v| v.as_str())
        .ok_or("public history has no turn role")?;
    if got_role != role {
        return Err(format!(
            "public history role is {got_role:?}, expected {role:?}"
        ));
    }
    let body = payload
        .get("body")
        .and_then(|v| v.as_object())
        .ok_or("public history has no turn body object")?;
    let got_body = body
        .get("text")
        .and_then(|v| v.as_str())
        .ok_or("public history body has no text")?;
    if got_body != text {
        return Err("public history body differs from the captured text".into());
    }
    if body.get("complete") != Some(&serde_json::json!(true)) {
        return Err("public history body is not marked complete".into());
    }
    if body.get("sha256") != Some(&serde_json::json!(hex_lower_sha256(text))) {
        return Err("public history body sha256 differs from the captured text".into());
    }
    let got_turn = payload
        .get("turn_id")
        .and_then(|v| v.as_str())
        .ok_or("public history has no turn id")?;
    if got_turn != vendor {
        return Err(format!(
            "public history turn id is {got_turn:?}, expected {vendor:?}"
        ));
    }
    let provider_session = payload
        .get("provider_session")
        .and_then(|v| v.as_str())
        .ok_or("public history has no provider session")?;
    if provider_session != conversation {
        return Err(format!(
            "public provider session is {provider_session:?}, expected {conversation:?}"
        ));
    }
    if body.get("bytes").and_then(|v| v.as_u64()) != Some(text.len() as u64) {
        return Err("public history UTF-8 byte count differs from the captured text".into());
    }
    Ok(())
}

pub trait OkOrMissing<T> {
    fn ok_or_missing(self) -> T;
}
impl<T> OkOrMissing<T> for Option<T> {
    fn ok_or_missing(self) -> T {
        match self {
            Some(value) => value,
            None => panic!("a positive constant cannot be zero"),
        }
    }
}
// All fallible setup and product calls must fail this test, never end the
// entire harness with a successful exit before the remaining assertions run.
pub trait Required<T> {
    fn required(self) -> T;
}
impl<T, E: std::fmt::Debug> Required<T> for Result<T, E> {
    fn required(self) -> T {
        match self {
            Ok(value) => value,
            Err(error) => panic!("W3 setup or product call failed: {error:?}"),
        }
    }
}
pub(super) fn committed_value<T: Clone + std::fmt::Debug>(
    receipt: api::Receipt<T>,
    name: &str,
) -> Result<(api::Commit<T>, T), String> {
    match receipt {
        api::Receipt::Committed { commit } => Ok((commit.clone(), commit.value)),
        other => Err(format!("{name}: expected Committed, got {other:?}")),
    }
}
pub(super) fn replayed_value<T: Clone + std::fmt::Debug>(
    receipt: api::Receipt<T>,
    name: &str,
) -> Result<(api::Commit<T>, T), String> {
    match receipt {
        api::Receipt::Replayed { original } => Ok((original.clone(), original.value)),
        other => Err(format!("{name}: expected Replayed, got {other:?}")),
    }
}
pub(super) fn refusal_contains(error: &api::ApiError, needle: &str) -> Result<(), String> {
    if error.message.contains(needle) || error.code.contains(needle) {
        Ok(())
    } else {
        Err(format!(
            "refusal {needle:?} not found in {{code: {}, message: {}}}",
            error.code, error.message
        ))
    }
}
