//! Protects: Windows Codex endpoint path fallback (>107 bytes), strict recovery
//! refusal when the leaf identity journal is absent, and failed-launch cleanup
//! of unpinned AF_UNIX sockets while preserving regular files.
#![cfg(all(windows, feature = "listener"))]

#[path = "../../test-support/directory.rs"]
mod directory;

use se_config::config_policy::{ConfigFile, Provider as ConfigProvider};
use se_harness::{
    BlockingPool, CallContext, CodexHarness, Harness, HarnessRequest, HostFuture, ProviderIo,
    ProviderIoPlatform, ProviderStream, ProviderTransport, SessionIdentity, StreamRead,
    StreamWrite,
};
use se_local_socket::identity::ObjectId;
use se_proc::{
    ContainmentRequirement, LaunchMode, LaunchPolicy, NativeStateFiles, NetworkPolicy,
    OptionalHardening, OwnedProcess, WritePolicy,
};
use se_types::{
    AgentId, Body, Detail, Generation, IdempotencyKey, NativePath, ProjectId, ProviderSessionId,
    Read, SeError, Secret, SessionId,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    num::NonZeroU32,
    path::{Component, Path, PathBuf},
    process::Command,
    sync::{Arc, OnceLock},
    time::Duration,
};

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Refusing provider I/O stand-in: these endpoint tests never touch stdio pipes.
struct RefusingIo;

impl RefusingIo {
    fn refuse(&self, op: &str) -> SeError {
        SeError::new(Detail::StateConflict(se_types::details::StateConflict {
            subject: "windows endpoint review fixture".into(),
            reason: format!("provider {op} is refused in endpoint custody tests"),
            next_step: "Use local-socket endpoint methods only.".into(),
        }))
    }
}

impl ProviderIoPlatform for RefusingIo {
    fn open(&self, _: &OwnedProcess, _: &SessionIdentity) -> se_types::Result<ProviderIo> {
        Err(self.refuse("open"))
    }
    fn read<'a>(
        &'a self,
        _: &'a ProviderTransport,
        _: ProviderStream,
        _: NonZeroU32,
        _: CallContext,
    ) -> HostFuture<'a, StreamRead> {
        Box::pin(async { Err(self.refuse("read")) })
    }
    fn write<'a>(
        &'a self,
        _: &'a ProviderTransport,
        _: Vec<u8>,
        _: CallContext,
    ) -> HostFuture<'a, StreamWrite> {
        Box::pin(async { Err(self.refuse("write")) })
    }
    fn finish_input<'a>(&'a self, _: &'a ProviderTransport, _: CallContext) -> HostFuture<'a, ()> {
        Box::pin(async { Err(self.refuse("finish_input")) })
    }
    fn close<'a>(&'a self, _: &'a ProviderTransport, _: CallContext) -> HostFuture<'a, ()> {
        Box::pin(async { Err(self.refuse("close")) })
    }
}

/// Tiny zero-dependency Rust helper compiled once with `rustc` to create a
/// genuine Windows `IO_REPARSE_TAG_AF_UNIX` socket reparse point on disk.
const AF_UNIX_BINDER_SOURCE: &str = r#"
#[repr(C, align(8))]
struct WsaData {
    _pad: [u8; 512],
}

#[repr(C)]
struct SockAddrUn {
    sun_family: u16,
    sun_path: [u8; 108],
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSAStartup(version: u16, data: *mut WsaData) -> i32;
    fn WSACleanup() -> i32;
    fn WSAGetLastError() -> i32;
    fn socket(af: i32, kind: i32, protocol: i32) -> usize;
    fn bind(sock: usize, name: *const SockAddrUn, namelen: i32) -> i32;
    fn listen(sock: usize, backlog: i32) -> i32;
    fn closesocket(sock: usize) -> i32;
}

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        std::process::exit(2);
    };
    let bytes = path.as_bytes();
    if bytes.is_empty() || bytes.len() >= 108 {
        eprintln!("socket path length out of range: {}", bytes.len());
        std::process::exit(3);
    }
    let mut wsa = WsaData { _pad: [0; 512] };
    let started = unsafe { WSAStartup(0x0202, &mut wsa) };
    if started != 0 {
        eprintln!("WSAStartup failed: {started}");
        std::process::exit(4);
    }
    let sock = unsafe { socket(1, 1, 0) };
    if sock == usize::MAX {
        eprintln!("socket failed: {}", unsafe { WSAGetLastError() });
        unsafe { WSACleanup() };
        std::process::exit(5);
    }
    let mut addr = SockAddrUn {
        sun_family: 1,
        sun_path: [0; 108],
    };
    addr.sun_path[..bytes.len()].copy_from_slice(bytes);
    let len = (2 + bytes.len() + 1) as i32;
    if unsafe { bind(sock, &addr, len) } != 0 {
        eprintln!("bind failed: {}", unsafe { WSAGetLastError() });
        unsafe {
            closesocket(sock);
            WSACleanup();
        }
        std::process::exit(6);
    }
    if unsafe { listen(sock, 1) } != 0 {
        eprintln!("listen failed: {}", unsafe { WSAGetLastError() });
        unsafe {
            closesocket(sock);
            WSACleanup();
        }
        std::process::exit(7);
    }
    unsafe {
        closesocket(sock);
        WSACleanup();
    }
}
"#;

struct BinderTool {
    _root: directory::PrivateDirectory,
    exe: PathBuf,
}

fn binder_executable() -> Check<&'static Path> {
    static TOOL: OnceLock<Result<BinderTool, String>> = OnceLock::new();
    let entry = TOOL.get_or_init(|| {
        let root = directory::private_directory().map_err(|e| e.to_string())?;
        let source = root.join("bind_af_unix.rs");
        let exe = root.join("bind_af_unix.exe");
        fs::write(&source, AF_UNIX_BINDER_SOURCE).map_err(|e| e.to_string())?;
        let output = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
            .args(["--edition=2024", "-C", "debuginfo=0"])
            .arg(&source)
            .arg("-o")
            .arg(&exe)
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "compiling AF_UNIX binder helper failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(BinderTool { _root: root, exe })
    });
    match entry {
        Ok(tool) => Ok(tool.exe.as_path()),
        Err(message) => Err(message.clone().into()),
    }
}

fn bind_af_unix_socket(path: &Path) -> Check {
    let exe = binder_executable()?;
    let output = Command::new(exe).arg(path).output()?;
    if !output.status.success() {
        return Err(format!(
            "binding AF_UNIX socket at {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let _ = ObjectId::local_socket(path)?;
    Ok(())
}

fn context() -> Check<CallContext> {
    Ok(CallContext::new(
        Generation::new(1)?,
        Duration::from_secs(10),
    ))
}

fn build_runtime() -> Check<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?)
}

fn make_harness(runtime: &tokio::runtime::Runtime, state_home: PathBuf) -> CodexHarness {
    CodexHarness::new(
        Arc::new(RefusingIo),
        BlockingPool::new(runtime.handle().clone()),
        state_home.clone(),
        state_home,
        21345,
        ConfigFile::default(),
    )
}

fn make_request(cwd: &Path, seed: u8) -> Check<HarnessRequest> {
    let config = ConfigFile::default();
    let resolved = config.resolve_profile("default", ConfigProvider::Codex, true)?;
    let writes = WritePolicy::Workspace {
        roots: vec![cwd.to_path_buf()],
        scratch: cwd.to_path_buf(),
    };
    let network = if resolved.network {
        NetworkPolicy::Allow
    } else {
        NetworkPolicy::Offline
    };
    Ok(HarnessRequest {
        identity: SessionIdentity {
            project: ProjectId::from_parts(1_700_000_000_000, [1; 10])?,
            agent: AgentId::from_parts(1_700_000_000_000, [2; 10])?,
            session: SessionId::from_parts(1_700_000_000_000, [seed; 10])?,
        },
        executable: NativePath::from_local(cwd.join("codex.exe"))?,
        cwd: NativePath::from_local(cwd.to_path_buf())?,
        profile: se_store::Profile {
            provider_settings: Default::default(),
            provider: se_store::Provider::Codex,
            model: None,
            permission: se_store::PermissionProfile::WorkspaceWrite,
            harness: None,
            named_profile: "default".into(),
            effort: None,
            external: false,
        },
        policy: LaunchPolicy {
            containment: ContainmentRequirement::BestAvailable,
            writes,
            network,
            hardening: OptionalHardening::Off,
        },
        mode: LaunchMode::Headless,
        resume: Read::Absent {
            checked: "fresh review fixture".into(),
        },
        transcript_roots: vec![],
        replay: None,
        initial_input: Body::new("review check")?,
        launch_credential: Secret::new(b"sec1.synthetic-review-credential".to_vec())?,
        mcp_bearer: Secret::new(b"sels-synthetic-review-bearer".to_vec())?,
        key: IdempotencyKey::new(format!("review-key-{seed}"))?,
        sign_in: None,
    })
}

fn planned_socket(
    runtime: &tokio::runtime::Runtime,
    harness: &CodexHarness,
    request: &HarnessRequest,
) -> se_types::Result<PathBuf> {
    let cx = CallContext::new(Generation::new(1)?, Duration::from_secs(10));
    let plan = runtime.block_on(harness.configuration(request, cx))?;
    let value: serde_json::Value =
        serde_json::from_slice(plan.ephemeral_files[0].contents.expose())
            .map_err(|e| SeError::invalid("codex-plan.json", &e.to_string()))?;
    let socket: NativePath = serde_json::from_value(value["socket"].clone())
        .map_err(|e| SeError::invalid("codex-plan socket", &e.to_string()))?;
    socket.to_local()
}

fn drive_root(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => out.push(component.as_os_str()),
            _ => break,
        }
    }
    out
}

fn pad_state_home(base: &Path, target_len: usize) -> Check<PathBuf> {
    let mut current = base.to_path_buf();
    let current_len = current.as_os_str().as_encoded_bytes().len();
    if target_len < current_len {
        return Err(format!("base {current_len} already exceeds target {target_len}").into());
    }
    let remaining = target_len - current_len;
    if remaining == 0 {
        return Ok(current);
    }
    // Subtract 1 for the path separator added by `join`.
    if remaining < 2 {
        return Err("cannot pad by 1 byte with a directory component".into());
    }
    let mut left = remaining;
    while left > 0 {
        // Choose segment lengths <= 24 so each path component stays small.
        let chunk = if left <= 25 { left - 1 } else { 20 };
        current.push("p".repeat(chunk));
        left -= chunk + 1;
        if left == 1 {
            // Adjust by backing up one char in the previous push would be messy;
            // prevented by picking chunk so left != 1.
            return Err("internal padding alignment error".into());
        }
    }
    assert_eq!(current.as_os_str().as_encoded_bytes().len(), target_len);
    Ok(current)
}

fn create_private_launch_dir(state_home: &Path, session: &SessionId) -> Check<PathBuf> {
    let launch_id = se_proc::session_launch_id(session)?;
    let launch_root = state_home.join("launch");
    let launch_dir = launch_root.join(launch_id.as_str());
    drop(NativeStateFiles::create(state_home)?);
    drop(NativeStateFiles::create(&launch_root)?);
    drop(NativeStateFiles::create(&launch_dir)?);
    Ok(launch_dir)
}

fn read_runtime_socket(launch_dir: &Path) -> Check<PathBuf> {
    let bytes = fs::read(launch_dir.join("codex-runtime.json"))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let socket: NativePath = serde_json::from_value(value["socket"].clone())?;
    Ok(socket.to_local()?)
}

#[test]
fn windows_socket_path_falls_back_past_107_bytes_and_refuses_overlong_home() -> Check {
    let root = directory::private_directory()?;
    let runtime = build_runtime()?;
    let request = make_request(&root, 11)?;
    let session = &request.identity.session;
    let launch_id = se_proc::session_launch_id(session)?;
    let hash16 = &se_types::hex_lower(&Sha256::digest(launch_id.as_str().as_bytes()))[..16];

    let preferred_suffix_len = format!("\\launch\\{}\\cx\\s", launch_id.as_str()).len();
    let fallback_suffix_len = format!("\\cx\\{hash16}\\s").len();
    let anchor = drive_root(&root).join("se");

    // 1) Preferred path length == 107 stays at `launch\cx\s`.
    let fit_home = pad_state_home(&anchor, 107 - preferred_suffix_len)?;
    let fit_harness = make_harness(&runtime, fit_home.clone());
    let fit_socket = planned_socket(&runtime, &fit_harness, &request)?;
    let expected_fit = fit_home
        .join("launch")
        .join(launch_id.as_str())
        .join("cx")
        .join("s");
    assert_eq!(fit_socket, expected_fit);
    assert_eq!(fit_socket.as_os_str().as_encoded_bytes().len(), 107);

    // 2) Preferred path length == 108 falls back to `state_home\cx\<16hex>\s`.
    let fallback_home = pad_state_home(&anchor, 108 - preferred_suffix_len)?;
    let fallback_harness = make_harness(&runtime, fallback_home.clone());
    let fallback_socket = planned_socket(&runtime, &fallback_harness, &request)?;
    let expected_fallback = fallback_home.join("cx").join(hash16).join("s");
    assert_eq!(fallback_socket, expected_fallback);
    assert!(fallback_socket.as_os_str().as_encoded_bytes().len() <= 107);

    // 3) Even the fallback exceeds 107 bytes -> ProviderIncompatible.
    let overlong_home = pad_state_home(&anchor, 108 - fallback_suffix_len)?;
    let overlong_harness = make_harness(&runtime, overlong_home);
    let refused = planned_socket(&runtime, &overlong_harness, &request);
    assert!(
        matches!(
            &refused,
            Err(error) if matches!(error.body.detail(), Detail::ProviderIncompatible(_))
        ),
        "overlong fallback path did not return ProviderIncompatible: {refused:?}"
    );

    // 4) Exercise real on-disk prepare_socket + retire_socket on the fallback layout.
    let root_len = root.as_os_str().as_encoded_bytes().len();
    let needed_home_len = (108usize.saturating_sub(preferred_suffix_len)).max(root_len + 3);
    if needed_home_len + fallback_suffix_len <= 107 {
        let on_disk_home = root.join("h".repeat(needed_home_len - root_len - 1));
        let launch_dir = create_private_launch_dir(&on_disk_home, session)?;
        let harness = make_harness(&runtime, on_disk_home.clone());
        runtime.block_on(harness.prepare_socket(&request, &context()?))?;
        let recorded_socket = read_runtime_socket(&launch_dir)?;
        assert_eq!(
            recorded_socket,
            on_disk_home.join("cx").join(hash16).join("s")
        );
        assert!(recorded_socket.parent().is_some_and(Path::is_dir));
        harness.retire_socket(session)?;
        assert!(!recorded_socket.parent().is_some_and(Path::exists));
    }
    Ok(())
}

#[test]
fn recover_refuses_absent_leaf_pin_without_inferring_custody() -> Check {
    let root = directory::private_directory()?;
    let runtime = build_runtime()?;
    let state_home = root.join("st");
    let request = make_request(&root, 22)?;
    let session = &request.identity.session;
    let launch_dir = create_private_launch_dir(&state_home, session)?;
    let harness = make_harness(&runtime, state_home);

    runtime.block_on(harness.prepare_socket(&request, &context()?))?;
    let socket = read_runtime_socket(&launch_dir)?;
    bind_af_unix_socket(&socket)?;

    let leaf_journal = launch_dir.join("codex-endpoint-leaf.json");
    assert!(
        fs::symlink_metadata(&leaf_journal).is_err(),
        "leaf journal should be absent before launch check"
    );

    let conversation = ProviderSessionId::new("thread-review-absent-pin")?;
    let recovered = runtime.block_on(harness.recover(
        &request.identity,
        &conversation,
        None,
        false,
        context()?,
    ));
    let err = match recovered {
        Ok(_) => return Err("recover succeeded without a leaf identity journal".into()),
        Err(error) => error,
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains(
            "the original endpoint identity journal is absent; no new custody was inferred"
        ),
        "unexpected recover error without leaf pin: {rendered}"
    );
    assert!(
        fs::symlink_metadata(&leaf_journal).is_err(),
        "recover must not create codex-endpoint-leaf.json when refusing absent custody"
    );

    harness.retire_socket(session)?;
    Ok(())
}

#[test]
fn retire_cleans_unpinned_af_unix_socket_and_preserves_regular_file() -> Check {
    let root = directory::private_directory()?;
    let runtime = build_runtime()?;

    // Part 1: failed launch with a genuine unpinned AF_UNIX socket cleans up cleanly.
    let state_home_a = root.join("sta");
    let harness_a = make_harness(&runtime, state_home_a.clone());
    let request_a = make_request(&root, 33)?;
    let session_a = &request_a.identity.session;
    let launch_a = create_private_launch_dir(&state_home_a, session_a)?;
    runtime.block_on(harness_a.prepare_socket(&request_a, &context()?))?;
    let socket_a = read_runtime_socket(&launch_a)?;
    let parent_a = socket_a
        .parent()
        .ok_or("socket_a missing parent")?
        .to_path_buf();
    bind_af_unix_socket(&socket_a)?;
    assert!(fs::symlink_metadata(launch_a.join("codex-endpoint-leaf.json")).is_err());

    harness_a.retire_socket(session_a)?;
    assert!(
        fs::symlink_metadata(&socket_a).is_err(),
        "unpinned AF_UNIX socket was not removed by retire"
    );
    assert!(
        fs::symlink_metadata(&parent_a).is_err(),
        "private socket directory was not removed by retire"
    );
    assert!(fs::symlink_metadata(launch_a.join("codex-endpoint.json")).is_err());
    assert!(fs::symlink_metadata(launch_a.join("codex-runtime.json")).is_err());

    // Part 2: regular file at `s` with no leaf pin is refused and preserved.
    let state_home_b = root.join("stb");
    let harness_b = make_harness(&runtime, state_home_b.clone());
    let request_b = make_request(&root, 44)?;
    let session_b = &request_b.identity.session;
    let launch_b = create_private_launch_dir(&state_home_b, session_b)?;
    runtime.block_on(harness_b.prepare_socket(&request_b, &context()?))?;
    let socket_b = read_runtime_socket(&launch_b)?;
    let parent_b = socket_b
        .parent()
        .ok_or("socket_b missing parent")?
        .to_path_buf();
    fs::write(&socket_b, b"preserve-regular-file")?;

    let refused = harness_b.retire_socket(session_b);
    assert!(
        refused.is_err(),
        "retire must refuse when an unpinned regular file sits at the socket path"
    );
    assert_eq!(fs::read(&socket_b)?, b"preserve-regular-file");
    assert!(parent_b.is_dir(), "parent directory should be preserved");
    Ok(())
}
