//! A detached runtime deliberately outlives the process that started it, so a
//! test that starts one must stop it on every exit. Drop guards cover returns
//! and panics; a test process killed outright runs none of them. The reaper is
//! a separate process holding the read end of a private pipe: a normal drop
//! disarms it, while the owner's death closes the pipe and the reaper runs the
//! fixture's own `down` command, the same graceful stop a person would use.
use std::{
    io::{self, Write},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

/// What the owner writes when it leaves normally; anything else is a death.
const DISARM: &[u8] = b"disarm\n";

/// A command the dead test left running can still publish a runtime after the
/// first stop, so the reaper keeps stopping whatever appears for longer than
/// one CLI command's 30-second deadline.
const WATCH_SECONDS: u32 = 60;

#[cfg(unix)]
const SCRIPT: &str = r#"IFS= read -r word
[ "$word" = disarm ] && exit 0
home=$1
watch=$2
shift 2
[ -d "$home" ] || exit 0
"$@" >/dev/null 2>&1
while [ "$watch" -gt 0 ]; do
  sleep 1
  watch=$((watch - 1))
  [ -d "$home" ] || exit 0
  [ -e "$home/endpoint.json" ] && "$@" >/dev/null 2>&1
done
exit 0"#;

/// Stops `home`'s runtime with `down` if this test process dies without
/// disarming it. It never acts while the owner is alive.
pub struct HomeReaper {
    disarm: Option<io::PipeWriter>,
    child: Option<Child>,
}

impl HomeReaper {
    /// Arm before the first command that can start a runtime for `home`.
    /// `down` is the fixture's own command with its `down` arguments. `Command`
    /// does not reveal `env_clear`, so `cleared` states whether `down` called
    /// it: the stop must see the socket directory and session markers that
    /// the runtime's own commands saw, no more and no fewer.
    pub fn arm(down: &Command, home: &Path, cleared: bool) -> io::Result<Self> {
        let (reader, writer) = io::pipe()?;
        let mut command = reaper_command(down, home);
        if let Some(directory) = down.get_current_dir() {
            command.current_dir(directory);
        }
        if cleared {
            command.env_clear();
        }
        for (key, value) in down.get_envs() {
            match value {
                Some(value) => command.env(key, value),
                None => command.env_remove(key),
            };
        }
        command
            .stdin(Stdio::from(reader))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = spawn(&mut command)?;
        // The read end now lives only in the reaper; our copy closed with it.
        Ok(Self {
            disarm: Some(writer),
            child: Some(child),
        })
    }
}

#[cfg(unix)]
fn reaper_command(down: &Command, home: &Path) -> Command {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(SCRIPT)
        .arg("se-test-home-reaper")
        .arg(home)
        .arg(WATCH_SECONDS.to_string())
        .arg(down.get_program())
        .args(down.get_args())
        // A runner that signals the test's process group must not take the
        // reaper with it: the reaper exists for exactly that death.
        .process_group(0);
    command
}

#[cfg(windows)]
fn reaper_command(down: &Command, home: &Path) -> Command {
    let quoted =
        |value: &std::ffi::OsStr| format!("'{}'", value.to_string_lossy().replace('\'', "''"));
    let mut call = format!("& {}", quoted(down.get_program()));
    for argument in down.get_args() {
        call.push(' ');
        call.push_str(&quoted(argument));
    }
    let home = quoted(home.as_os_str());
    let script = format!(
        "if ([Console]::In.ReadLine() -eq 'disarm') {{ exit 0 }}\n\
         if (-not (Test-Path -LiteralPath {home} -PathType Container)) {{ exit 0 }}\n\
         {call} *> $null\n\
         for ($watch = {WATCH_SECONDS}; $watch -gt 0; $watch--) {{\n\
           Start-Sleep -Seconds 1\n\
           if (-not (Test-Path -LiteralPath {home} -PathType Container)) {{ exit 0 }}\n\
           if (Test-Path -LiteralPath (Join-Path {home} 'endpoint.json')) {{ {call} *> $null }}\n\
         }}\n\
         exit 0"
    );
    let mut command = Command::new("powershell.exe");
    command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]);
    command.arg(script);
    command
}

#[cfg(unix)]
fn spawn(command: &mut Command) -> io::Result<Child> {
    command.spawn()
}

#[cfg(windows)]
fn spawn(command: &mut Command) -> io::Result<Child> {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const ERROR_ACCESS_DENIED: i32 = 5;
    // A runner that closes the test's job must not take the reaper with it.
    // A job that forbids breakaway still gets a reaper for every other death.
    let quiet = CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW;
    match command
        .creation_flags(quiet | CREATE_BREAKAWAY_FROM_JOB)
        .spawn()
    {
        Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
            command.creation_flags(quiet).spawn()
        }
        outcome => outcome,
    }
}

impl Drop for HomeReaper {
    fn drop(&mut self) {
        if let Some(mut writer) = self.disarm.take()
            && let Err(error) = writer.write_all(DISARM)
        {
            eprintln!("test home reaper could not be disarmed: {error}");
        }
        let Some(mut child) = self.child.take() else {
            return;
        };
        // A disarmed reaper exits at once; reap it so no zombie outlives us.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    eprintln!("test home reaper {} is still running", child.id());
                    return;
                }
                Err(error) => {
                    eprintln!("test home reaper {} is unobservable: {error}", child.id());
                    return;
                }
            }
        }
    }
}
