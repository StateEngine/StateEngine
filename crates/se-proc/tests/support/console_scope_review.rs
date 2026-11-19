//! Real Windows scope, interrupt helper, descendant tools and redirected streams.
use super::*;
use std::path::Path;
use std::process::{Command, Stdio};

const PAYLOADS: [(&str, &str); 2] = [
    ("tool.py", include_str!("console_scope_review/tool.py")),
    ("tool.ps1", include_str!("console_scope_review/tool.ps1")),
];
const TOOLS: [&str; 2] = ["powershell", "python"];
const MEMBERS: [&str; 3] = ["root", "powershell", "python"];
const OUT: &[u8] = b"PROTOCOL-OUT:0\x00\xff\n";
const ERR: &[u8] = b"PROTOCOL-ERR:0\x00\xfe\n";

fn compile_scope_root(home: &Home) -> Check<PathBuf> {
    let source = home.0.join("root.rs");
    fs::write(&source, include_str!("console_scope_review/root.rs"))?;
    let image = home.0.join("scope-root.exe");
    let output = Command::new("rustc")
        .args(["--edition", "2024"])
        .arg(source)
        .arg("-o")
        .arg(&image)
        .stdin(Stdio::null())
        .output()?;
    assert!(
        output.status.success(),
        "fixture root compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(image)
}

fn start<'a>(
    runtime: &'a NativeProcessRuntime,
    reservation: LaunchReservation,
    home: &Home,
    executable: &Path,
    deadline: Instant,
) -> Check<Scope<'a>> {
    for (name, source) in PAYLOADS {
        fs::write(home.0.join(name), source)?;
    }
    let keys = [
        "SYSTEMROOT",
        "WINDIR",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "COMSPEC",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "PROGRAMFILES",
    ];
    let mut entries: Vec<_> = std::env::vars_os()
        .filter(|(key, _)| {
            key.to_str()
                .is_some_and(|key| keys.iter().any(|name| name.eq_ignore_ascii_case(key)))
        })
        .collect();
    entries.push(("BINDING_SCOPE_HOME".into(), home.0.as_os_str().to_owned()));
    let generation = reservation.generation;
    let lifecycle = reservation.lifecycle.clone();
    let prepared = runtime
        .prepare_launch(
            reservation,
            LaunchSpec {
                executable_custody: None,
                lifecycle,
                generation,
                executable: executable.to_path_buf(),
                arguments: Vec::new(),
                cwd: home.0.clone(),
                environment: Environment { entries },
                stdio: empty(),
                mode: LaunchMode::HeadlessConsole,
                window: None,
                policy: LaunchPolicy {
                    containment: ContainmentRequirement::BestAvailable,
                    writes: WritePolicy::Workspace {
                        roots: vec![home.0.clone()],
                        scratch: home.0.clone(),
                    },
                    network: NetworkPolicy::Allow,
                    hardening: OptionalHardening::Off,
                },
                deadline,
                notifications: Arc::new(Notices),
            },
        )
        .map_err(error)?;
    let scope = Scope {
        runtime,
        process: prepared.process,
        generation,
        released: false,
    };
    runtime
        .bind_stdio(&prepared.prepared, home.endpoints("console")?)
        .map_err(error)?;
    let ticket = match runtime.begin_launch(prepared.prepared) {
        LaunchStart::Pending { ticket, .. } => ticket,
        LaunchStart::Failed(failure) => {
            return Err(format!("native launch failed: {:?}", failure.error).into());
        }
    };
    loop {
        match runtime.poll_launch(&ticket).map_err(error)? {
            LaunchProgress::Started(_) => return Ok(scope),
            LaunchProgress::AwaitingExecCommit(_) => {
                runtime.authorize_exec(&ticket).map_err(error)?;
            }
            LaunchProgress::Failed(failure) => {
                return Err(format!("native exec failed: {:?}", failure.error).into());
            }
            _ if Instant::now() < deadline => std::thread::park_timeout(Duration::from_millis(10)),
            _ => return Err("native launch did not finish".into()),
        }
    }
}

fn exact_streams(home: &Home) -> Check {
    assert_eq!(fs::read(home.0.join("output-console"))?, OUT);
    assert_eq!(fs::read(home.0.join("error-console"))?, ERR);
    Ok(())
}

fn ready(home: &Home, deadline: Instant) -> Check {
    while MEMBERS
        .iter()
        .any(|name| !home.0.join(format!("{name}.ready")).is_file())
    {
        if Instant::now() >= deadline {
            return Err(format!(
                "tool readiness missing; root stderr={:?}; PowerShell stderr={:?}; Python stderr={:?}",
                fs::read_to_string(home.0.join("error-console")),
                fs::read_to_string(home.0.join("powershell.stderr")),
                fs::read_to_string(home.0.join("python.stderr"))
            )
            .into());
        }
        std::thread::park_timeout(Duration::from_millis(20));
    }
    assert_eq!(fs::read_to_string(home.0.join("root.visible"))?, "False");
    exact_streams(home)
}

#[test]
fn windowless_console_interrupts_root_and_descendants_without_crossing_scopes() -> Check {
    let machine = MachineId::new("windows-console-scope-review")?;
    let seed: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
    let host = HostInstanceId(seed);
    let generation = GenerationId::new(1)?;
    let helper_executable =
        PathBuf::from(std::env::var_os("SE_W3_SE_BIN").ok_or("candidate CLI pin")?);
    let runtime = NativeProcessRuntime::open(HostConfig {
        machine: machine.clone(),
        instance: host,
        helper_executable,
        linux_delegation: LinuxDelegation::CurrentScope,
        limits: ResourceLimits {
            max_lifecycles: 2,
            max_diagnostic_members: 8,
            max_observation_bytes: 65536,
            max_stdio_buffer_bytes: 4096,
        },
    })
    .map_err(error)?;
    let owner = current_process_identity(machine).map_err(error)?;
    let reserve = |index| -> Check<LaunchReservation> {
        let mut scope_nonce = seed;
        scope_nonce[0] = index;
        Ok(LaunchReservation {
            format_version: 1,
            lifecycle: LifecycleId::from_parts(1_700_000_000_000, scope_nonce[..10].try_into()?)?,
            host,
            owner: owner.clone(),
            generation,
            scope_nonce,
            parent: ReservationParent::Windows,
            created_at_unix_ns: 1,
        })
    };
    let target_home = Home::new()?;
    let guard_home = Home::new()?;
    let compiler_home = Home::new()?;
    let image = compile_scope_root(&compiler_home)?;
    let deadline = Instant::now() + Duration::from_secs(55);
    let mut target = start(&runtime, reserve(1)?, &target_home, &image, deadline)?;
    let mut guard = start(&runtime, reserve(2)?, &guard_home, &image, deadline)?;
    ready(&target_home, deadline)?;
    ready(&guard_home, deadline)?;

    let token = runtime
        .prepare_stop(&target.process, generation, deadline)
        .map_err(error)?;
    let attempt = runtime.request_interrupt(token).map_err(error)?;
    assert_eq!(attempt.dispatch.map_err(error)?, StopDispatch::Requested);
    let witness = loop {
        let observed = runtime.witness_stop(&attempt.ticket).map_err(error)?;
        match observed {
            StopObservation::Complete(witness) => break witness,
            _ if Instant::now() < deadline => std::thread::park_timeout(Duration::from_millis(15)),
            other => {
                let marks = MEMBERS.map(|name| {
                    (
                        name,
                        fs::read_to_string(target_home.0.join(format!("{name}.interrupt"))).ok(),
                    )
                });
                let pids = TOOLS.map(|name| {
                    (
                        name,
                        fs::read_to_string(target_home.0.join(format!("{name}.pid"))).ok(),
                    )
                });
                return Err(format!("scope remained open after requested interrupt; markers={marks:?}, tools={pids:?}, witness={other:?}").into());
            }
        }
    };
    assert_eq!(witness.scope_exit.remaining.population, Population::Empty);
    for name in MEMBERS {
        let marker = format!("{name}.interrupt");
        assert_eq!(fs::read_to_string(target_home.0.join(&marker))?, "0");
        assert!(!guard_home.0.join(marker).exists());
    }
    let guard_live = runtime.observe(&guard.process).map_err(error)?;
    assert!(matches!(guard_live.root, ProcessObservation::Live(_)));
    for name in TOOLS {
        let pid: u32 = fs::read_to_string(guard_home.0.join(format!("{name}.pid")))?.parse()?;
        assert!(
            guard_live
                .scope
                .remaining
                .known_live
                .iter()
                .any(|identity| identity.pid == ProcessId(pid)),
            "foreign descendant {name} was not observed live"
        );
    }

    runtime.release(&target.process, &witness).map_err(error)?;
    target.released = true;
    fs::write(guard_home.0.join("normal-exit"), b"exit")?;
    guard.release()?;
    assert!(runtime.arena_snapshot().map_err(error)?.entries.is_empty());
    exact_streams(&target_home)?;
    exact_streams(&guard_home)?;
    let diagnostics = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics/windows-console-scope");
    fs::create_dir_all(&diagnostics)?;
    fs::write(
        diagnostics.join("review.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "os": "nt",
            "run_id": std::env::var("GITHUB_RUN_ID").ok(),
            "target_ctrl_c": MEMBERS,
            "foreign_live_members": MEMBERS,
            "stdout_bytes_each": OUT.len(),
            "stderr_bytes_each": ERR.len(),
            "window_visible_in_runner": false,
            "arena_empty_after_release": true,
        }))?,
    )?;
    println!(
        "Ctrl+C reached target root, PowerShell and Python; foreign root and both tools stayed live; redirected bytes exact; arena empty after release"
    );
    Ok(())
}
