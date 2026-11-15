#![cfg(feature = "remote")]
//! Discovery through the real staging consumer, stopping before any installation.
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[path = "../../test-support/directory.rs"]
mod directory;

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
const CHILD: &str = "SE_PLATFORM_CASE";
const TEST: &str = "destination_discovery_preserves_native_platforms";
const TARGETS: [&str; 4] = [
    "x86_64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    uname: &'static str,
    uname_ok: bool,
    architecture: &'static str,
    architecture_ok: bool,
    target: Option<usize>,
}

fn cases() -> Vec<Case> {
    let windows = Case {
        name: "msys",
        uname: "MSYS_NT-10.0-26100 x86_64\n",
        uname_ok: true,
        architecture: "X64\r\n",
        architecture_ok: true,
        target: Some(3),
    };
    vec![
        windows,
        Case {
            name: "cygwin",
            uname: "CYGWIN_NT-10.0-26100 x86_64\n",
            ..windows
        },
        Case {
            name: "mingw",
            uname: "MINGW64_NT-10.0-26100 x86_64\n",
            ..windows
        },
        Case {
            name: "windows_without_uname",
            uname: "",
            uname_ok: false,
            ..windows
        },
        Case {
            name: "linux",
            uname: "Linux x86_64\n",
            target: Some(0),
            ..windows
        },
        Case {
            name: "darwin_arm",
            uname: "Darwin arm64\n",
            target: Some(1),
            ..windows
        },
        Case {
            name: "darwin_intel",
            uname: "Darwin x86_64\n",
            target: Some(2),
            ..windows
        },
        Case {
            name: "unsupported_os",
            uname: "FreeBSD x86_64\n",
            architecture: "",
            architecture_ok: false,
            target: None,
            ..windows
        },
        Case {
            name: "unsupported_unix_arch",
            uname: "Linux aarch64\n",
            architecture: "",
            architecture_ok: false,
            target: None,
            ..windows
        },
        Case {
            name: "unsupported_windows_arch",
            architecture: "Arm64\n",
            target: None,
            ..windows
        },
        Case {
            name: "failed_windows_probe",
            architecture: "",
            architecture_ok: false,
            target: None,
            ..windows
        },
        // An interrupted or failed SSH command can leave plausible stdout.
        // Its text alone must not become a successful Unix discovery receipt.
        Case {
            name: "failed_linux_uname",
            uname: "Linux x86_64\n",
            uname_ok: false,
            architecture: "",
            architecture_ok: false,
            target: None,
            ..windows
        },
        Case {
            name: "failed_darwin_arm_uname",
            uname: "Darwin arm64\n",
            uname_ok: false,
            architecture: "",
            architecture_ok: false,
            target: None,
            ..windows
        },
        Case {
            name: "failed_darwin_intel_uname",
            uname: "Darwin x86_64\n",
            uname_ok: false,
            architecture: "",
            architecture_ok: false,
            target: None,
            ..windows
        },
    ]
}

#[test]
fn destination_discovery_preserves_native_platforms() -> Result {
    if let Ok(name) = std::env::var(CHILD) {
        let case = cases()
            .into_iter()
            .find(|c| c.name == name)
            .ok_or("unknown case")?;
        return exercise(
            case,
            &PathBuf::from(std::env::var_os("SE_PLATFORM_ROOT").ok_or("missing root")?),
        );
    }
    let root = directory::private_case_directory()?;
    let result = run_cases(&root);
    root.finish(result)
}

fn run_cases(root: &Path) -> Result {
    let reports = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics/remote-platform");
    fs::create_dir_all(&reports)?;
    let bin = root.join("bin");
    fs::create_dir(&bin)?;
    let source = root.join("ssh_fixture.rs");
    fs::write(&source, include_str!("support/platform_ssh_fixture.rs"))?;
    let executable = bin.join(if cfg!(windows) { "ssh.exe" } else { "ssh" });
    let mut compiler = Command::new("rustc");
    compiler
        .arg("--edition=2024")
        .arg("--crate-name=platform_ssh_fixture")
        .arg(&source)
        .arg("-o")
        .arg(&executable);
    if !run_bounded(&mut compiler, root, "compiler", Duration::from_secs(60))?.success() {
        return Err("native SSH fixture compilation failed; see retained compiler output".into());
    }
    let mut failures = Vec::new();
    for case in cases() {
        let case_root = root.join(case.name);
        fs::create_dir(&case_root)?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env(CHILD, case.name)
            .env("SE_PLATFORM_ROOT", &case_root)
            .env("SE_PLATFORM_UNAME", case.uname)
            .env("SE_PLATFORM_UNAME_OK", case.uname_ok.to_string())
            .env("SE_PLATFORM_ARCH", case.architecture)
            .env("SE_PLATFORM_ARCH_OK", case.architecture_ok.to_string())
            .env("PATH", &bin)
            .env("HOME", &case_root)
            .env("USERPROFILE", &case_root)
            .env("XDG_CONFIG_HOME", &case_root)
            .env("XDG_STATE_HOME", &case_root)
            .current_dir(&case_root);
        let status = run_bounded(&mut command, &case_root, "consumer", Duration::from_secs(8));
        let passed = status.as_ref().is_ok_and(|s| s.success());
        let mut observed = Vec::new();
        for index in 0..8 {
            let path = case_root.join(format!("command-{index}"));
            if !path.exists() {
                break;
            }
            observed.push(decoded_command(&fs::read_to_string(path)?)?);
        }
        fs::write(
            reports.join(format!("{}.json", case.name)),
            serde_json::to_vec_pretty(&serde_json::json!({
                "case": case.name, "passed": passed, "status": format!("{status:?}"),
                "expected_target": case.target.map(|index| TARGETS[index]),
                "commands": observed,
                "stdout": fs::read_to_string(case_root.join("consumer.stdout"))?,
                "stderr": fs::read_to_string(case_root.join("consumer.stderr"))?,
            }))?,
        )?;
        println!("{} {}", if passed { "PASS" } else { "FAIL" }, case.name);
        if !passed {
            eprintln!(
                "{}: {status:?}\n{}\n{}",
                case.name,
                fs::read_to_string(case_root.join("consumer.stdout"))?,
                fs::read_to_string(case_root.join("consumer.stderr"))?
            );
            failures.push(case.name);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("discovery cases failed: {failures:?}").into())
    }
}

fn run_bounded(
    command: &mut Command,
    root: &Path,
    label: &str,
    budget: Duration,
) -> Result<ExitStatus> {
    command
        .stdin(Stdio::null())
        .stdout(fs::File::create(root.join(format!("{label}.stdout")))?)
        .stderr(fs::File::create(root.join(format!("{label}.stderr")))?);
    let mut child = command.spawn()?;
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let kill = child.kill();
            let reap = child.wait();
            return Err(format!(
                "owned {label} child exceeded {budget:?}; kill={kill:?}, reap={reap:?}"
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn local_target() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => TARGETS[0],
        ("macos", "aarch64") => TARGETS[1],
        ("macos", "x86_64") => TARGETS[2],
        ("windows", "x86_64") => TARGETS[3],
        _ => panic!("review fixture requires a supported source platform"),
    }
}

fn install_fixture(root: &Path, target: usize) -> Result<String> {
    let target = TARGETS[target];
    let path = if target == local_target() {
        root.join("distribution")
    } else {
        root.join("remote-images")
            .join(target)
            .join(if target.contains("windows") {
                "se.exe"
            } else {
                "se"
            })
    };
    fs::create_dir_all(path.parent().ok_or("image has no parent")?)?;
    let payload = format!("synthetic native image for {target}\n");
    fs::write(path, &payload)?;
    Ok(se_types::hex_lower(&Sha256::digest(payload.as_bytes())))
}

fn decoded_command(command: &str) -> Result<String> {
    if let Some((_, encoded)) = command.split_once("-EncodedCommand ") {
        let bytes = base64::engine::general_purpose::STANDARD.decode(encoded.trim())?;
        if bytes.len() % 2 != 0 {
            return Err("odd encoded command length".into());
        }
        let words: Vec<_> = bytes
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        Ok(String::from_utf16(&words)?)
    } else {
        Ok(command.to_owned())
    }
}

fn exercise(case: Case, root: &Path) -> Result {
    let digest = if let Some(target) = case.target {
        Some(install_fixture(root, target)?)
    } else {
        // Wrongly accepting a refusal case must reach cache preparation, rather
        // than be hidden by an absent distribution file.
        for target in 0..TARGETS.len() {
            install_fixture(root, target)?;
        }
        None
    };
    let mut stages = Vec::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(se_host::remote::ssh::prepare_image(
        "127.0.0.1",
        &root.join("distribution"),
        &AtomicBool::new(false),
        &mut |progress| {
            stages.push(format!("{:?}", progress.stage));
            Ok(())
        },
    ));
    let error = result
        .expect_err("the fixture always refuses cache preparation")
        .to_string();
    assert_eq!(stages, ["Discovering"], "must not claim staging success");
    let mut commands = Vec::new();
    for index in 0..8 {
        let path = root.join(format!("command-{index}"));
        if !path.exists() {
            break;
        }
        commands.push(decoded_command(&fs::read_to_string(path)?)?);
    }
    assert_eq!(commands.first().map(String::as_str), Some("uname -sm"));
    let architecture_probes = commands
        .iter()
        .filter(|s| s.contains("OSArchitecture"))
        .count();
    if let Some(target) = case.target {
        assert!(
            error.contains("cache ownership or permissions refused"),
            "{error}"
        );
        assert_eq!(commands.len(), if target == 3 { 3 } else { 2 });
        assert_eq!(architecture_probes, usize::from(target == 3));
        let stage = commands.last().ok_or("cache command absent")?;
        assert!(
            stage.contains(&format!(
                ".stateengine-runtime/{}",
                digest.ok_or("missing digest")?
            )),
            "selected image digest absent: {stage}"
        );
        if target == 3 {
            assert!(stage.contains("WindowsIdentity"));
        } else {
            assert!(stage.contains(if target == 0 { "stat -c" } else { "stat -f" }));
        }
    } else {
        assert!(
            error.contains("platform") || error.contains("unsupported"),
            "wrong refusal: {error}"
        );
        assert!(
            commands
                .iter()
                .all(|s| s == "uname -sm" || s.contains("OSArchitecture")),
            "unsupported destination reached cache preparation"
        );
        assert!(commands.len() <= 2);
    }
    println!(
        "witnessed {}: {} observed SSH commands; expected refusal: {error}",
        case.name,
        commands.len()
    );
    Ok(())
}
