//! W3 real-host judge (doc 90, black-box).
//!
//! Drives the linked embedded StateEngine host through public surfaces only:
//! the `se` CLI for trusted setup and public event readback, the public
//! `secode_stateengine_api` `HostFactory`/`Host` over `se_host::embedded_factory`,
//! and independent public reads of the Rust store as the bound agent. The native
//! task consumer additionally invokes the published SE Code driver with a fresh
//! judge nonce and verifies its real file effects and public durable captures.
//!
//! Required inputs: real binaries at `SE_W3_SE_BIN` and `SE_W3_SECODE_SERVER`,
//! the published `SE_W3_NATIVE_DRIVER` and its `SE_W3_PRODUCT_COMMIT`. Missing
//! inputs, setup failures and product errors all fail the test.

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

#[path = "support/w3_timestamp_replay.rs"]
mod timestamp_replay;

// ---------------------------------------------------------------- helpers

fn require_se() -> Result<PathBuf, ()> {
    match std::env::var_os("SE_W3_SE_BIN") {
        Some(path) if !path.is_empty() => {
            let path = PathBuf::from(path);
            if path.is_file() { Ok(path) } else { Err(()) }
        }
        _ => Err(()),
    }
}
fn missing_helper() -> ! {
    panic!("SE_W3_SE_BIN must name a real se binary; W3 was not exercised");
}
fn judge_root(label: &str) -> PathBuf {
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
fn owner_env(home: &Path) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
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
fn init_project(helper: &Path, root: &Path) -> Result<(PathBuf, String, String), String> {
    let home = root.join("home");
    let repo = root.join("repo");
    for path in [home.clone(), repo.clone()] {
        std::fs::create_dir_all(&path).map_err(|e| format!("create {}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("chmod {}: {e}", path.display()))?;
        }
    }
    let stdout = run_se_ok(
        helper,
        &home,
        &[
            "init",
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
struct NoopCancellation;
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
    let native = se_proc::current_runtime_identity(machine)
        .map_err(|e| format!("runtime identity: {e:?}"))?;
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
        machine: native.process.machine,
        boot: native.boot_id,
        pid,
        started: peer.started().clone(),
        executable: se_types::NativePath::from_local(native.process.image.clone())
            .map_err(|e| format!("native image: {e}"))?,
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

struct Judge {
    runtime: tokio::runtime::Runtime,
    factory: Arc<dyn api::HostFactory>,
    helper: PathBuf,
    root: PathBuf,
    home: PathBuf,
    project: String,
    agent: String,
    retain: bool,
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
    fn new(label: &str) -> Result<Self, String> {
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
    fn open(&self) -> Result<api::OpenedHost, String> {
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
    fn activate(&self, opened: &api::OpenedHost) -> Result<api::Generation, String> {
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
    fn bind(
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
    fn capture(
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
    fn capture_with(
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
    fn continuity(
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
    fn revoke(
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
    fn drain_close(
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

fn api_read_kind<T>(read: &api::Read<T>) -> &'static str {
    match read {
        api::Read::Present { .. } => "Present",
        api::Read::Absent { .. } => "Absent",
        api::Read::Unreadable { .. } => "Unreadable",
        api::Read::Unknown { .. } => "Unknown",
    }
}
fn stored_text_kind(text: &StoredText) -> &'static str {
    match text {
        StoredText::Present(_) => "Present",
        StoredText::Erased { .. } => "Erased",
    }
}
fn body_kind(body: &EventBody<StoredText>) -> &'static str {
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
fn now_micros() -> u64 {
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
fn witness<T: Send, E: std::fmt::Display + Send>(
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
fn turn_rows(judge: &Judge, generation: u64) -> Result<Vec<StoredEvent>, String> {
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
fn session_record(
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
fn body_text(body: &EventBody<StoredText>, name: &str) -> Result<String, String> {
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
fn assert_public_turn(
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

trait OkOrMissing<T> {
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
fn committed_value<T: Clone + std::fmt::Debug>(
    receipt: api::Receipt<T>,
    name: &str,
) -> Result<(api::Commit<T>, T), String> {
    match receipt {
        api::Receipt::Committed { commit } => Ok((commit.clone(), commit.value)),
        other => Err(format!("{name}: expected Committed, got {other:?}")),
    }
}
fn replayed_value<T: Clone + std::fmt::Debug>(
    receipt: api::Receipt<T>,
    name: &str,
) -> Result<(api::Commit<T>, T), String> {
    match receipt {
        api::Receipt::Replayed { original } => Ok((original.clone(), original.value)),
        other => Err(format!("{name}: expected Replayed, got {other:?}")),
    }
}
fn refusal_contains(error: &api::ApiError, needle: &str) -> Result<(), String> {
    if error.message.contains(needle) || error.code.contains(needle) {
        Ok(())
    } else {
        Err(format!(
            "refusal {needle:?} not found in {{code: {}, message: {}}}",
            error.code, error.message
        ))
    }
}

// ---------------------------------------------------------------- tests

/// Protects: a cold embedded open over a home without the trusted setup
/// reports the setup-required refusal by name, and a home prepared through
/// `se init` opens with its real store facts before any activation.
#[test]
fn open_refuses_an_uninitialized_home_by_name() {
    let helper = match require_se() {
        Ok(path) => path,
        Err(()) => missing_helper(),
    };
    let root = judge_root("open");
    let empty = root.join("home");
    std::fs::create_dir_all(&empty).required();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o700)).required();
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .required();
    let factory = se_host::embedded_factory(runtime.handle().clone());
    let config = api::HostConfig {
        state_home: empty.clone(),
        helper_executable: helper.clone(),
        linux_delegation: api::LinuxDelegation::AutoUserManager,
        api: api::API_VERSION,
        kind: api::HostKind::EmbeddedSecode,
        features: vec![api::Feature::LocalListener],
        limits: api::Limits {
            page_items: std::num::NonZeroU32::new(100).ok_or_missing(),
            payload_bytes: std::num::NonZeroU32::new(256 * 1024).ok_or_missing(),
            notice_ids: std::num::NonZeroU32::new(100).ok_or_missing(),
        },
    };
    let options = api::OpenOptions {
        expected_generation: None,
        timeout: Duration::from_secs(10),
        cancellation: Arc::new(NoopCancellation),
    };
    let opened = runtime.block_on(factory.open(config, options)).required();
    let kind = api_read_kind(&opened);
    let checked = match opened {
        api::Read::Absent { checked } => checked,
        _ => panic!("an uninitialized home must open Absent, got {kind}"),
    };
    assert!(
        checked.contains("setup-required"),
        "the refusal must name the setup requirement: {checked}"
    );
    assert!(
        checked.contains("se init"),
        "the refusal must name the trusted setup flow: {checked}"
    );

    let (home, _project, _agent) = init_project(&helper, &root).required();
    let config = api::HostConfig {
        state_home: home.clone(),
        helper_executable: helper.clone(),
        linux_delegation: api::LinuxDelegation::AutoUserManager,
        api: api::API_VERSION,
        kind: api::HostKind::EmbeddedSecode,
        features: vec![api::Feature::LocalListener],
        limits: api::Limits {
            page_items: std::num::NonZeroU32::new(100).ok_or_missing(),
            payload_bytes: std::num::NonZeroU32::new(256 * 1024).ok_or_missing(),
            notice_ids: std::num::NonZeroU32::new(100).ok_or_missing(),
        },
    };
    let options = api::OpenOptions {
        expected_generation: None,
        timeout: Duration::from_secs(10),
        cancellation: Arc::new(NoopCancellation),
    };
    let factory = se_host::embedded_factory(runtime.handle().clone());
    let opened = runtime.block_on(factory.open(config, options)).required();
    let kind = api_read_kind(&opened);
    let opened = match opened {
        api::Read::Present { value } => value,
        _ => panic!("an initialized home must open Present, got {kind}"),
    };
    assert_eq!(
        opened.negotiated.api,
        api::API_VERSION,
        "the negotiated API must be the linked major"
    );
    assert_eq!(
        opened.store.version.application_id, 0x5345_4E47,
        "the store readback must carry the StateEngine application id"
    );
    assert!(
        opened
            .negotiated
            .features
            .contains(&api::Feature::LocalListener),
        "the embedded host offers its local listener"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Protects: one Owner bind commits a fresh SE Code session exactly once; the
/// original key and intent replay to the original committed identity with a
/// single prepared/activated store pair; and a second binding for the same
/// agent is refused by name until the first is revoked.
#[test]
fn bind_commits_once_and_replays_the_original_identity() {
    let judge = Judge::new("bind").required();
    let opened = judge.open().required();
    let generation = judge.activate(&opened).required();
    let host = opened.host.clone();

    let issued = judge
        .bind(&host, generation, "conv-bind-1", "judge-bind-1")
        .required();
    let (commit, identity) = committed_value(issued.receipt.clone(), "bind").required();
    assert_eq!(
        commit.idempotency_key.0, "judge-bind-1",
        "the receipt carries the original key"
    );
    assert_eq!(
        identity.project.0, judge.project,
        "the identity names the bound project"
    );
    assert_eq!(
        identity.agent.0, judge.agent,
        "the identity names the bound agent"
    );
    assert!(
        identity.session.0.starts_with("ses_") && identity.session.0.len() == 40,
        "the session is a fresh canonical id: {:?}",
        identity.session.0
    );
    assert_eq!(
        issued.session.identity,
        identity.clone(),
        "the issued grant carries the committed identity"
    );

    let replay = judge
        .bind(&host, generation, "conv-bind-1", "judge-bind-1")
        .required();
    let (replay_commit, replay_identity) = replayed_value(replay.receipt, "bind replay").required();
    assert_eq!(
        replay_identity, identity,
        "the replay returns the original committed identity"
    );
    assert_eq!(
        replay_commit.event, commit.event,
        "the replay names the original committed event"
    );

    let record = session_record(&judge, generation.0, &identity.session.0).required();
    match &record.current.body {
        EventBody::SessionActivated { session, .. } => {
            assert_eq!(
                session.as_str(),
                identity.session.0,
                "the store head is the activated session"
            )
        }
        other => panic!(
            "the store head must be SessionActivated, got {}",
            body_kind(other)
        ),
    }
    let prepared = record.original.as_deref().unwrap_or(&record.current);
    match &prepared.body {
        EventBody::SessionPrepared {
            provider,
            consent,
            native_ref,
            generation: written,
            ..
        } => {
            assert_eq!(
                *provider,
                se_store::Provider::SeCode,
                "the session is prepared for SE Code"
            );
            assert_eq!(
                *consent,
                se_store::Consent::Capture,
                "capture consent is recorded"
            );
            assert_eq!(
                native_ref.as_str(),
                "conv-bind-1",
                "the native conversation is recorded"
            );
            assert_eq!(
                *written, generation.0,
                "the preparation carries the host generation"
            );
        }
        other => panic!(
            "the original must be SessionPrepared, got {}",
            body_kind(other)
        ),
    }
    assert_eq!(
        record.revision.value.get(),
        2,
        "one prepared and one activated event, nothing else"
    );

    let second = judge.bind(&host, generation, "conv-bind-2", "judge-bind-2");
    let second_error = second
        .err()
        .unwrap_or_else(|| panic!("a second live binding for the same agent must be refused"));
    refusal_contains(&second_error, "no existing active or prepared session").required();

    let receipt = judge.drain_close(&host, generation).required();
    assert!(
        receipt.writer_flushed && receipt.unresolved_effects == 0,
        "the drain must report a flushed writer: {receipt:?}"
    );
}

/// Protects: native turn capture commits the exact canonical text with a
/// matching SHA-256 and no invented transcript path; the same natural key
/// replays to the original committed turn; a mismatched digest or a foreign
/// conversation is refused by name; continuity reads the captured turns back
/// under the bound identity; and the public history shows both turns with the
/// app-server provenance.
#[test]
fn capture_replays_by_natural_key_without_inventing_a_transcript_path() {
    let judge = Judge::new("capture").required();
    let opened = judge.open().required();
    let generation = judge.activate(&opened).required();
    let host = opened.host.clone();
    let issued = judge
        .bind(&host, generation, "conv-capture-1", "judge-bind-3")
        .required();
    let session = issued.session;

    let user_text = "judge user turn: π and café";
    let assistant_text = "judge assistant turn";
    let user_receipt = judge
        .capture(
            &host,
            &session,
            generation,
            "conv-capture-1",
            api::TurnRole::User,
            "vt-1",
            user_text,
            "judge-capture-1",
        )
        .required();
    let (user_commit, user_event) = committed_value(user_receipt, "user capture").required();
    let assistant_receipt = judge
        .capture(
            &host,
            &session,
            generation,
            "conv-capture-1",
            api::TurnRole::Assistant,
            "vt-2",
            assistant_text,
            "judge-capture-2",
        )
        .required();
    let (_assistant_commit, assistant_event) =
        committed_value(assistant_receipt, "assistant capture").required();
    assert_ne!(
        user_event.id.0, assistant_event.id.0,
        "each capture commits its own turn event"
    );

    let replay = judge
        .capture(
            &host,
            &session,
            generation,
            "conv-capture-1",
            api::TurnRole::User,
            "vt-1",
            user_text,
            "judge-capture-1",
        )
        .required();
    let (replay_commit, replay_event) = replayed_value(replay, "capture replay").required();
    assert_eq!(
        replay_event, user_event,
        "the natural replay returns the original committed turn"
    );
    assert_eq!(
        replay_commit.event, user_commit.event,
        "the replay names the original event position"
    );

    let natural_replay = judge
        .capture(
            &host,
            &session,
            generation,
            "conv-capture-1",
            api::TurnRole::User,
            "vt-1",
            user_text,
            "judge-capture-distinct-key",
        )
        .required();
    let (natural_commit, natural_event) =
        replayed_value(natural_replay, "distinct-key natural replay").required();
    assert_eq!(
        natural_event, user_event,
        "natural identity replays despite a distinct request key"
    );
    assert_eq!(
        natural_commit.event, user_commit.event,
        "natural replay preserves the first committed event"
    );

    let bad_digest = judge.capture_with(
        &host,
        &session,
        generation,
        api::CapturedTurn {
            conversation: api::ProviderSessionId("conv-capture-1".into()),
            vendor_turn: "vt-9".into(),
            vendor_event: Some("evt-vt-9".into()),
            machine_id: None,
            source_ref: Some("secode-event:vt-9".into()),
            source_cli: "secode".into(),
            nesting: None,
            role: api::TurnRole::User,
            occurred_at: api::UnixMicros(now_micros()),
            content: api::BoundedText {
                text: "judge user turn".into(),
                utf8_bytes: "judge user turn".len() as u64,
                complete: true,
                omitted_bytes: Some(0),
            },
            source_sha256: api::Sha256([7; 32]),
            idempotency_key: api::IdempotencyKey("judge-capture-9".into()),
        },
    );
    refusal_contains(
        &bad_digest
            .err()
            .unwrap_or_else(|| panic!("a mismatched digest must be refused")),
        "SHA-256 of the exact canonical text",
    )
    .required();

    let foreign = judge.capture_with(
        &host,
        &session,
        generation,
        api::CapturedTurn {
            conversation: api::ProviderSessionId("conv-other".into()),
            vendor_turn: "vt-10".into(),
            vendor_event: Some("evt-vt-10".into()),
            machine_id: None,
            source_ref: Some("secode-event:vt-10".into()),
            source_cli: "secode".into(),
            nesting: None,
            role: api::TurnRole::User,
            occurred_at: api::UnixMicros(now_micros()),
            content: api::BoundedText {
                text: "judge foreign conversation".into(),
                utf8_bytes: "judge foreign conversation".len() as u64,
                complete: true,
                omitted_bytes: Some(0),
            },
            source_sha256: api::Sha256(
                Sha256::digest("judge foreign conversation".as_bytes()).into(),
            ),
            idempotency_key: api::IdempotencyKey("judge-capture-10".into()),
        },
    );
    refusal_contains(
        &foreign
            .err()
            .unwrap_or_else(|| panic!("a foreign conversation must be refused")),
        "original bound generation and provider conversation",
    )
    .required();

    let rows = turn_rows(&judge, generation.0).required();
    let turns: Vec<&StoredEvent> = rows
        .iter()
        .filter(|row| matches!(row.body, EventBody::SessionTurn { .. }))
        .collect();
    assert_eq!(
        turns.len(),
        2,
        "exactly two captured turns exist in the store"
    );
    for (role, vendor, text, digest) in [
        (
            "user",
            "vt-1",
            user_text,
            Sha256::digest(user_text.as_bytes()),
        ),
        (
            "assistant",
            "vt-2",
            assistant_text,
            Sha256::digest(assistant_text.as_bytes()),
        ),
    ] {
        let row = turns
            .iter()
            .copied()
            .find(|row| {
                if let EventBody::SessionTurn { vendor_ref, .. } = &row.body {
                    vendor_ref.as_str() == vendor
                } else {
                    false
                }
            })
            .unwrap_or_else(|| panic!("the store has no captured turn for {vendor}"));
        let EventBody::SessionTurn {
            vendor_ref,
            role: stored_role,
            text: stored_text,
            evidence,
            ..
        } = &row.body
        else {
            panic!("the found row is not a session turn");
        };
        assert_eq!(
            vendor_ref.as_str(),
            vendor,
            "the vendor ref survives in the store"
        );
        match (stored_role, stored_text) {
            (se_store::Role::User, StoredText::Present(body)) if role == "user" => {
                assert_eq!(body, text);
            }
            (se_store::Role::Assistant, StoredText::Present(body)) if role == "assistant" => {
                assert_eq!(body, text);
            }
            other => panic!(
                "row {}: role/text mismatch: {:?}/{}",
                row.header.event.as_str(),
                other.0,
                stored_text_kind(other.1)
            ),
        }
        assert!(
            evidence.path.is_none(),
            "native capture must not invent a transcript path: {evidence:?}"
        );
        assert_eq!(
            evidence.sha256,
            Some(digest.into()),
            "the store records the SHA-256 of the exact text"
        );
        assert_eq!(
            evidence.length,
            text.len() as u64,
            "the evidence length is the text length"
        );
    }

    let context = judge.continuity(&host, &session, generation).required();
    assert_eq!(
        context.identity, issued.identity,
        "continuity returns the bound identity"
    );
    assert!(
        context.model_input.text.contains(user_text)
            && context.model_input.text.contains(assistant_text),
        "continuity carries both captured turns: {}",
        context.model_input.text
    );
    assert_eq!(
        context.continuity_summary.rows, 2,
        "the continuity summary counts both turns"
    );
    match context.packet {
        api::Read::Absent { checked } => {
            assert!(
                checked.contains("No boot packet"),
                "the packet refusal must name the reason: {checked}"
            );
        }
        other => panic!("the linked W3 binding issues no packet, got {other:?}"),
    }

    assert_public_turn(
        &judge,
        &user_event.id.0,
        "conv-capture-1",
        "user",
        "vt-1",
        user_text,
    )
    .required();
    assert_public_turn(
        &judge,
        &assistant_event.id.0,
        "conv-capture-1",
        "assistant",
        "vt-2",
        assistant_text,
    )
    .required();

    let receipt = judge.drain_close(&host, generation).required();
    assert!(receipt.writer_flushed, "the drain must flush: {receipt:?}");
}

/// Protects: Owner revocation commits the session transition once and is
/// retryable under its original key; the old grant is fenced and every later
/// call with it is refused by name without any credential; after revocation
/// the agent may bind a replacement.
#[test]
fn revoke_is_retryable_and_fences_the_old_grant_by_name() {
    let judge = Judge::new("revoke").required();
    let opened = judge.open().required();
    let generation = judge.activate(&opened).required();
    let host = opened.host.clone();
    let issued = judge
        .bind(&host, generation, "conv-revoke-1", "judge-bind-4")
        .required();
    let session = issued.session;
    let identity = issued.identity.clone();
    let _ = judge
        .capture(
            &host,
            &session,
            generation,
            "conv-revoke-1",
            api::TurnRole::User,
            "vt-1",
            "judge revoked session turn",
            "judge-capture-11",
        )
        .required();

    let receipt = judge
        .revoke(&host, generation, &identity.session.0, "judge-revoke-1")
        .required();
    let (_commit, revoked) = committed_value(receipt, "revoke").required();
    assert_eq!(
        revoked, identity,
        "the revoke receipt names the revoked identity"
    );

    let retry = judge
        .revoke(&host, generation, &identity.session.0, "judge-revoke-1")
        .required();
    let (_retry_commit, retried) = replayed_value(retry, "revoke retry").required();
    assert_eq!(
        retried, identity,
        "the retryable revocation returns the original identity"
    );

    let fenced_capture = judge.capture(
        &host,
        &session,
        generation,
        "conv-revoke-1",
        api::TurnRole::Assistant,
        "vt-2",
        "judge after revocation",
        "judge-capture-12",
    );
    refusal_contains(
        &fenced_capture
            .err()
            .unwrap_or_else(|| panic!("the fenced grant must be refused")),
        "revoked or replaced",
    )
    .required();

    let fenced_continuity = judge.continuity(&host, &session, generation);
    refusal_contains(
        &fenced_continuity
            .err()
            .unwrap_or_else(|| panic!("the fenced grant must be refused for continuity")),
        "revoked or replaced",
    )
    .required();

    let replacement = judge
        .bind(&host, generation, "conv-revoke-2", "judge-bind-5")
        .required();
    let (_commit2, replacement_identity) =
        committed_value(replacement.receipt.clone(), "replacement bind").required();
    assert_ne!(
        replacement_identity.session.0, identity.session.0,
        "the replacement is a fresh session"
    );

    let old_record = session_record(&judge, generation.0, &identity.session.0).required();
    let reason = body_text(&old_record.current.body, "revoked session").required();
    assert!(
        reason.contains("Replaced"),
        "the revoke reason keeps the end reason: {reason}"
    );

    let receipt = judge.drain_close(&host, generation).required();
    assert!(receipt.writer_flushed, "the drain must flush: {receipt:?}");
}

/// Protects: after drain and close, a fresh generation binds atomically over
/// the previous generation's process-free SE Code session — the old session is
/// revoked in the same committed batch and the replacement names it as
/// incumbent; the old grant is refused by name against the new host; and a
/// live same-generation session is never auto-replaced.
#[test]
fn restart_recovers_only_a_process_free_older_generation_binding() {
    let judge = Judge::new("restart").required();
    let opened = judge.open().required();
    let generation = judge.activate(&opened).required();
    let first = opened.negotiated.generation;
    assert_eq!(first.0, generation.0, "the first host owns generation one");
    let host = opened.host.clone();
    let issued = judge
        .bind(&host, generation, "conv-restart-1", "judge-bind-6")
        .required();
    let old_session = issued.session;
    let old_identity = issued.identity.clone();
    let drain = judge.drain_close(&host, generation).required();
    assert_eq!(drain.generation, first, "the drain names its generation");

    let reopened = judge.open().required();
    assert_eq!(
        reopened.negotiated.generation.0,
        first.0 + 1,
        "the reopened host negotiates the next store generation"
    );
    let second_generation = judge.activate(&reopened).required();
    let second_host = reopened.host.clone();

    let replacement = judge
        .bind(
            &second_host,
            second_generation,
            "conv-restart-2",
            "judge-bind-7",
        )
        .required();
    let (_commit, new_identity) =
        committed_value(replacement.receipt.clone(), "replacement bind").required();
    assert_ne!(
        new_identity.session.0, old_identity.session.0,
        "the restart replacement is a fresh session"
    );

    let old_record =
        session_record(&judge, second_generation.0, &old_identity.session.0).required();
    let reason = body_text(&old_record.current.body, "recovered session").required();
    assert!(
        reason.contains("Previous SE Code host generation ended"),
        "the atomic replacement revokes the old generation by name: {reason}"
    );
    let new_record =
        session_record(&judge, second_generation.0, &new_identity.session.0).required();
    match &new_record.current.body {
        EventBody::SessionActivated {
            incumbent: Some((incumbent, _)),
            ..
        } => {
            assert_eq!(
                incumbent.as_str(),
                old_identity.session.0,
                "the replacement names the replaced session as incumbent"
            );
        }
        other => panic!(
            "the replacement must record the incumbent, got {}",
            body_kind(other)
        ),
    }

    let stale_capture = judge.capture(
        &second_host,
        &old_session,
        second_generation,
        "conv-restart-1",
        api::TurnRole::Assistant,
        "vt-1",
        "judge against a restarted host",
        "judge-capture-13",
    );
    let stale_error = stale_capture
        .err()
        .unwrap_or_else(|| panic!("the old grant must be refused against the new host"));
    let named = refusal_contains(
        &stale_error,
        "grant does not match the original binding and generation",
    )
    .or_else(|_| refusal_contains(&stale_error, "not issued by this host generation"));
    named.required();

    let live = judge.bind(
        &second_host,
        second_generation,
        "conv-restart-3",
        "judge-bind-8",
    );
    refusal_contains(
        &live.err().unwrap_or_else(|| {
            panic!("a live same-generation session must refuse a third binding")
        }),
        "no existing active or prepared session",
    )
    .required();

    let receipt = judge
        .drain_close(&second_host, second_generation)
        .required();
    assert!(receipt.writer_flushed, "the drain must flush: {receipt:?}");
}

// All fallible setup and product calls must fail this test, never end the
// entire harness with a successful exit before the remaining assertions run.
trait Required<T> {
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

#[path = "support/w3_native_task.rs"]
mod native_task;
