//! Own a Windows fixture host without assuming the runner permits job breakaway.
use crate::executable::ExecutableCommand;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);

pub struct ForegroundHost {
    child: Mutex<Child>,
    down: Command,
    ready: serde_json::Value,
    stdout: PathBuf,
    stderr: PathBuf,
}

fn copy_command(source: &Command) -> Command {
    let mut command = Command::new(source.get_program());
    command.args(source.get_args());
    if let Some(directory) = source.get_current_dir() {
        command.current_dir(directory);
    }
    for (key, value) in source.get_envs() {
        match value {
            Some(value) => {
                command.env(key, value);
            }
            None => {
                command.env_remove(key);
            }
        }
    }
    command
}

impl ForegroundHost {
    pub fn start(mut command: Command, home: &Path) -> Result<Self> {
        let label = format!(
            "fixture-host-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let stdout = home.join(format!("{label}.stdout"));
        let stderr = home.join(format!("{label}.stderr"));
        let mut down = copy_command(&command);
        down.arg("down");
        let child = command
            .args(["up", "--foreground"])
            .stdin(Stdio::null())
            .stdout(
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&stdout)?,
            )
            .stderr(
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&stderr)?,
            )
            .spawn_executable()?;
        let mut host = Self {
            child: Mutex::new(child),
            down,
            ready: serde_json::Value::Null,
            stdout,
            stderr,
        };
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            let mut child = host
                .child
                .lock()
                .map_err(|_| "fixture child lock poisoned")?;
            if let Some(status) = child.try_wait()? {
                return Err(format!(
                    "foreground host exited before readiness ({status}): {}",
                    fs::read_to_string(&host.stderr)?
                )
                .into());
            }
            let bytes = fs::read(&host.stdout)?;
            if let Ok(ready) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if ready["schema"] != "se.runtime-start/v1"
                    || ready["state"] != "running"
                    || ready["process"]["pid"].as_u64() != Some(u64::from(child.id()))
                {
                    return Err(format!(
                        "foreground readiness did not identify its exact child: {ready}"
                    )
                    .into());
                }
                drop(child);
                host.ready = ready;
                return Ok(host);
            }
            if Instant::now() >= until {
                return Err(format!(
                    "foreground readiness missing; stdout={}, stderr={}",
                    host.stdout.display(),
                    host.stderr.display()
                )
                .into());
            }
            drop(child);
            std::thread::park_timeout(Duration::from_millis(10));
        }
    }

    pub fn ready(&self) -> &serde_json::Value {
        &self.ready
    }

    pub fn wait(&self) -> Result {
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self
                .child
                .lock()
                .map_err(|_| "fixture child lock poisoned")?
                .try_wait()?
            {
                return if status.success() {
                    Ok(())
                } else {
                    Err(format!(
                        "foreground host exited with {status}: {}",
                        fs::read_to_string(&self.stderr)?
                    )
                    .into())
                };
            }
            if Instant::now() >= until {
                return Err("owned foreground host did not exit after public shutdown".into());
            }
            std::thread::park_timeout(Duration::from_millis(10));
        }
    }
}

impl Drop for ForegroundHost {
    fn drop(&mut self) {
        let exited = self
            .child
            .get_mut()
            .ok()
            .and_then(|child| child.try_wait().ok())
            .flatten()
            .is_some();
        if exited {
            return;
        }
        let stopped = self.down.output_executable().and_then(|output| {
            if output.status.success() {
                Ok(())
            } else {
                Err(std::io::Error::other(format!(
                    "public shutdown failed: {output:?}"
                )))
            }
        });
        if let Err(error) = stopped
            .map_err(|error| -> Box<dyn Error> { Box::new(error) })
            .and_then(|()| self.wait())
        {
            eprintln!(
                "retaining foreground fixture after cleanup failure: {error}; stderr={}",
                self.stderr.display()
            );
        }
    }
}
