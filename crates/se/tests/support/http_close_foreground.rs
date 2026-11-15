//! Retain the public foreground process instead of waiting for detached `up`.
use crate::{Check, command, executable::ExecutableCommand};
use std::{
    fs::File,
    path::{Path, PathBuf},
    process::{Child, Stdio},
    time::{Duration, Instant},
};

pub struct Foreground {
    child: Child,
    image: PathBuf,
    home: PathBuf,
}
impl Foreground {
    pub fn start(
        image: &Path,
        home: &Path,
        output: &Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let stdout = output.join("foreground.stdout");
        let stderr = output.join("foreground.stderr");
        let child = command(image, home, true)
            .args(["up", "--foreground"])
            .stdin(Stdio::null())
            .stdout(File::create(&stdout)?)
            .stderr(File::create(&stderr)?)
            .spawn_executable()?;
        let mut held = Self {
            child,
            image: image.into(),
            home: home.into(),
        };
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            let bytes = std::fs::read(&stdout)?;
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if value["state"] == "running" {
                    if value["process"]["pid"].as_u64() != Some(u64::from(held.child.id())) {
                        return Err("foreground readiness names another process".into());
                    }
                    println!(
                        "PUBLIC_CLOSE stage=foreground-ready pid={}",
                        held.child.id()
                    );
                    return Ok(held);
                }
                return Err(format!("foreground startup did not report running: {value}").into());
            }
            if let Some(status) = held.child.try_wait()? {
                return Err(format!(
                    "foreground exited before ready: {status}; {}",
                    String::from_utf8_lossy(&std::fs::read(&stderr)?)
                )
                .into());
            }
            if Instant::now() >= until {
                return Err(format!(
                    "foreground readiness exceeded its bound; {}",
                    String::from_utf8_lossy(&std::fs::read(&stderr)?)
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    pub fn join(&mut self) -> Check {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait()? {
                if !status.success() {
                    return Err(format!("foreground exited unsuccessfully: {status}").into());
                }
                println!("PUBLIC_CLOSE stage=foreground-joined exit=0");
                return Ok(());
            }
            if Instant::now() >= until {
                return Err("foreground did not join after authenticated host stop".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Foreground {
    fn drop(&mut self) {
        if self.child.try_wait().is_ok_and(|status| status.is_some()) {
            return;
        }
        let stopped = command(&self.image, &self.home, true)
            .arg("down")
            .output_executable()
            .is_ok_and(|output| {
                output.status.success()
                    && serde_json::from_slice::<serde_json::Value>(&output.stdout)
                        .is_ok_and(|value| value["complete"] == true)
            });
        if !stopped || self.join().is_err() {
            eprintln!(
                "retaining exact foreground fixture process {}; cleanup unproved",
                self.child.id()
            );
        }
    }
}
