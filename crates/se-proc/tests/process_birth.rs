//! Independent native time/identity reader; no process is signalled or killed.
use se_proc::{
    BootIdentity, MachineId, ProcErrorCode, ProcessId, ProcessIdentity, StartIdentity,
    observe_process_birth,
};
use std::{
    io::{BufRead, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        if let Err(e) = self.0.wait() {
            eprintln!("join exact owned birth fixture: {e}");
        }
    }
}
fn start() -> Result<ChildGuard> {
    let child = Command::new(std::env::current_exe()?)
        .arg("--birth-child")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut guard = ChildGuard(child);
    let mut line = String::new();
    std::io::BufReader::new(guard.0.stdout.take().ok_or("owned child stdout absent")?)
        .read_line(&mut line)?;
    assert_eq!(line, "NATIVE-BIRTH-READY\n");
    Ok(guard)
}
#[cfg(target_os = "linux")]
fn outside_identity(pid: u32) -> Result<ProcessIdentity> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = raw
        .rsplit_once(") ")
        .ok_or("proc stat comm terminator absent")?
        .1
        .split_whitespace()
        .collect();
    let ticks: u64 = fields.get(19).ok_or("proc start ticks absent")?.parse()?;
    let uuid = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    assert_eq!(uuid.len(), 32);
    let mut boot = [0; 16];
    for (index, byte) in boot.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&uuid[index * 2..index * 2 + 2], 16)?;
    }
    Ok(ProcessIdentity {
        machine: MachineId::new("native-birth-fixture")?,
        boot: BootIdentity::Linux { boot_id: boot },
        pid: ProcessId(pid),
        start: StartIdentity::Linux { start_ticks: ticks },
        image: std::fs::read_link(format!("/proc/{pid}/exe"))?,
    })
}
#[cfg(target_os = "linux")]
fn outside(pid: u32, rate: Option<u64>) -> Result<(ProcessIdentity, i64, Duration)> {
    let expected = outside_identity(pid)?;
    let StartIdentity::Linux { start_ticks: ticks } = expected.start else {
        return Err("outside Linux ticks absent".into());
    };
    let stat = std::fs::read_to_string("/proc/stat")?;
    let boot_seconds: u64 = stat
        .lines()
        .find_map(|line| line.strip_prefix("btime "))
        .ok_or("outside btime absent")?
        .parse()?;
    let hz = match rate {
        Some(value) => value,
        None => {
            let result = Command::new("getconf").arg("CLK_TCK").output()?;
            assert!(result.status.success());
            String::from_utf8(result.stdout)?.trim().parse()?
        }
    };
    assert!(hz > 0);
    let micros = i64::try_from(
        u128::from(boot_seconds) * 1_000_000 + u128::from(ticks) * 1_000_000 / u128::from(hz),
    )?;
    Ok((expected, micros, Duration::from_secs(1)))
}
#[cfg(windows)]
fn outside(pid: u32, _rate: Option<u64>) -> Result<(ProcessIdentity, i64, Duration)> {
    let script = std::env::temp_dir().join(format!("se-birth-outside-{}.ps1", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&script)?;
    file.write_all(include_bytes!("support/process_birth_outside.ps1"))?;
    file.sync_all()?;
    drop(file);
    let result = Command::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(&script)
        .arg(pid.to_string())
        .output()?;
    std::fs::remove_file(script)?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&result.stdout)?;
    let filetime: u64 = value["creation_filetime"]
        .as_str()
        .ok_or("outside creation clock absent")?
        .parse()?;
    let micros = i64::try_from((i128::from(filetime) - 116_444_736_000_000_000).div_euclid(10))?;
    Ok((
        ProcessIdentity {
            machine: MachineId::new("native-birth-fixture")?,
            boot: BootIdentity::WindowsAbsoluteCreationClock,
            pid: ProcessId(pid),
            start: StartIdentity::Windows {
                creation_filetime: filetime,
            },
            image: PathBuf::from(value["image"].as_str().ok_or("outside image absent")?),
        },
        micros,
        Duration::from_micros(1),
    ))
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
#[cfg(any(target_os = "linux", windows))]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn run() -> Result {
    let args: Vec<_> = std::env::args().collect();
    let rate = if args.get(1).is_some_and(|v| v == "--expect-native-rate") {
        Some(
            args.get(2)
                .ok_or("expected native tick rate missing")?
                .parse()?,
        )
    } else {
        None
    };
    let mut child = start()?;
    #[cfg(target_os = "linux")]
    if args.get(1).is_some_and(|v| {
        v == "--expect-tick-failure"
            || v == "--expect-boot-failure"
            || v == "--expect-mixed-epochs"
            || v == "--expect-source-limit"
    }) {
        let expected = outside_identity(child.0.id())?;
        let error = observe_process_birth(&expected, deadline())
            .err()
            .ok_or("unreadable/mixed source returned a fabricated birth")?;
        let mixed = args[1] == "--expect-mixed-epochs";
        assert_eq!(
            error.code,
            if mixed {
                ProcErrorCode::IdentityChanged
            } else if args[1] == "--expect-source-limit" {
                ProcErrorCode::ResourceLimit
            } else {
                ProcErrorCode::IdentityUnreadable
            }
        );
        if args[1] == "--expect-tick-failure" {
            assert!(format!("{error:?}").contains("sysconf(_SC_CLK_TCK)"));
        }
        println!(
            "1 passed, 0 failed; unavailable native birth source refuses without a clock fallback"
        );
        return Ok(());
    }
    let (expected, micros, precision) = outside(child.0.id(), rate)?;
    let actual = observe_process_birth(&expected, deadline())
        .map_err(|error| format!("native birth observation: {error:?}"))?;
    assert_eq!(
        actual.unix_micros(),
        micros,
        "birth differs from independent native read"
    );
    assert_eq!(actual.precision(), precision);
    if rate.is_some() {
        println!("1 passed, 0 failed; conversion honors the reported native tick rate");
        return Ok(());
    }
    let mut start = expected.clone();
    start.start = match start.start {
        StartIdentity::Linux { start_ticks } => StartIdentity::Linux {
            start_ticks: start_ticks + 1,
        },
        StartIdentity::Windows { creation_filetime } => StartIdentity::Windows {
            creation_filetime: creation_filetime + 1,
        },
        _ => return Err("unexpected native start identity".into()),
    };
    let mut boot = expected.clone();
    boot.boot = match boot.boot {
        BootIdentity::Linux { .. } => BootIdentity::WindowsAbsoluteCreationClock,
        _ => BootIdentity::Linux { boot_id: [0; 16] },
    };
    let mut image = expected.clone();
    image.image = image.image.with_file_name("unowned-birth-image");
    for wrong in [&start, &boot, &image] {
        assert_eq!(
            observe_process_birth(wrong, deadline())
                .err()
                .ok_or("changed process identity accepted")?
                .code,
            ProcErrorCode::IdentityChanged
        );
    }
    assert_eq!(
        observe_process_birth(&expected, Instant::now())
            .err()
            .ok_or("expired birth read returned a time")?
            .code,
        ProcErrorCode::LaunchTimedOut
    );
    let mut invalid = expected.clone();
    invalid.pid = ProcessId(0);
    assert_eq!(
        observe_process_birth(&invalid, deadline())
            .err()
            .ok_or("zero PID accepted")?
            .code,
        ProcErrorCode::InvalidInput
    );
    invalid = expected.clone();
    invalid.image = PathBuf::from("relative-image");
    assert_eq!(
        observe_process_birth(&invalid, deadline())
            .err()
            .ok_or("relative image accepted")?
            .code,
        ProcErrorCode::InvalidInput
    );
    drop(child.0.stdin.take());
    assert!(child.0.wait()?.success());
    assert!(
        observe_process_birth(&expected, deadline()).is_err(),
        "exited process received a fabricated current birth"
    );
    println!(
        "native birth: 8 passed, 0 failed; exact outside time/precision, identity/deadline/absence refusals; CLI started_at NOT GRADED"
    );
    Ok(())
}
fn main() -> Result {
    if std::env::args().any(|v| v == "--list") {
        if !std::env::args().any(|v| v == "--ignored") {
            println!("process_birth: test");
        }
        return Ok(());
    }
    if std::env::args().nth(1).as_deref() == Some("--birth-child") {
        println!("NATIVE-BIRTH-READY");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        return Ok(());
    }
    #[cfg(any(target_os = "linux", windows))]
    run()?;
    #[cfg(not(any(target_os = "linux", windows)))]
    println!("NOT GRADED: native Windows/Linux birth observation");
    Ok(())
}
