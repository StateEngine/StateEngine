use crate::executable::ExecutableCommand;
use crate::{Check, checked, command};
use se_types::Secret;
use std::{
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

/// Holds the exact observed native instance; PID reuse never proves its exit.
pub struct RunningHost {
    image: std::path::PathBuf,
    home: std::path::PathBuf,
    foreground: Option<crate::venue::Foreground>,
    endpoint: se_host::EndpointRecord,
    key: Secret,
    identity: se_proc::ProcessIdentity,
}
struct StartupCleanup<'a> {
    image: &'a Path,
    home: &'a Path,
    armed: bool,
}
impl Drop for StartupCleanup<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // `up` can publish a detached runtime before its reply or our outside
        // observation fails. No RunningHost exists to drop yet. The home's
        // authenticated route checks its native instance; never guess a PID.
        let result = command(self.image, self.home, true)
            .arg("down")
            .output_executable();
        let closed = result.as_ref().is_ok_and(|output| {
            output.status.success()
                && serde_json::from_slice::<serde_json::Value>(&output.stdout)
                    .is_ok_and(|value| value["complete"] == true)
        });
        if !closed {
            eprintln!(
                "retaining failed runtime fixture {} after shutdown: {result:?}",
                self.home.display()
            );
        }
    }
}
impl RunningHost {
    pub fn start(image: &Path, home: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut cleanup = StartupCleanup {
            image,
            home,
            armed: true,
        };
        let result = Self::start_observed(image, home);
        cleanup.armed = result.is_err();
        result
    }
    fn start_observed(image: &Path, home: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut foreground = None;
        if crate::venue::probe(Some(home))?.is_no_broker() {
            // This venue cannot launch a detached host; drive the product's
            // own reported foreground host instead.
            let host = crate::venue::Foreground::spawn(command(image, home, true).arg("up"))?;
            host.start_up(
                Instant::now() + Duration::from_secs(30),
                Instant::now() + Duration::from_secs(15),
                || {
                    let value = checked(command(image, home, true).arg("status").output_executable()?)?;
                    Ok(crate::venue::status_pid(&value)?)
                },
                || Ok(command(image, home, true).arg("down").output_executable()?),
            )?;
            foreground = Some(host);
        } else {
            checked(command(image, home, true).arg("up").output_executable()?)?;
        }
        let endpoint = se_host::client::endpoint::decode_endpoint(&std::fs::read(
            home.join("endpoint.json"),
        )?)?;
        let expected = endpoint.epoch.owner.fields();
        let observed = se_proc::NativeProcessRuntime::read_process_until(
            expected.machine.clone(),
            se_proc::ProcessId(expected.pid.get()),
            Instant::now() + Duration::from_secs(10),
        )
        .map_err(|error| format!("outside native host observation during start: {error:?}"))?;
        let se_proc::ProcessRead::Present(observed) = observed else {
            return Err(format!("fixture host is not live: {observed:?}").into());
        };
        assert_eq!(
            std::fs::canonicalize(&observed.identity.image)?,
            std::fs::canonicalize(image)?,
            "published host is not this fixture's copied image"
        );
        Ok(Self {
            image: image.into(),
            home: home.into(),
            foreground,
            endpoint,
            key: Secret::new(std::fs::read(home.join("credential"))?)?,
            identity: observed.identity,
        })
    }
    pub fn live(&self) -> Result<bool, Box<dyn std::error::Error>> {
        self.live_until(Instant::now() + Duration::from_secs(10), "live")
    }
    fn live_until(
        &self,
        deadline: Instant,
        phase: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match se_proc::NativeProcessRuntime::read_process_until(
            self.identity.machine.clone(),
            self.identity.pid,
            deadline,
        )
        .map_err(|error| format!("outside native host observation during {phase}: {error:?}"))?
        {
            se_proc::ProcessRead::Present(observed) if observed.identity == self.identity => {
                Ok(!matches!(
                    observed.state,
                    se_proc::NativeState::Exited | se_proc::NativeState::ExitedAwaitingReap
                ))
            }
            se_proc::ProcessRead::Absent { .. } => Ok(false),
            se_proc::ProcessRead::ExitedRecord {
                pid, boot, start, ..
            } if pid == self.identity.pid
                && boot == self.identity.boot
                && start == self.identity.start =>
            {
                Ok(false)
            }
            _ => Err(format!(
                "host identity changed during {phase}; refusing to act on another instance"
            )
            .into()),
        }
    }
    pub fn stop(&self) -> Check {
        if !self
            .live()
            .map_err(|error| format!("stop preflight: {error}"))?
        {
            return Ok(());
        }
        if let Some(foreground) = &self.foreground {
            // The foreground host is stopped through the public CLI from this
            // separate client, exactly as the pinned no-broker contract requires.
            let output = command(&self.image, &self.home, true)
                .arg("down")
                .output_executable()?;
            if !matches!(output.status.code(), Some(0) | Some(2)) {
                return Err(format!(
                    "public down refused the foreground host: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
            foreground.wait_for_exit(Instant::now() + Duration::from_secs(10))?;
            return Ok(());
        }
        let until = se_types::UnixMicros::new(
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_micros()
                + 5_000_000) as u64,
        )?;
        se_host::client::BlockingIpcClient::stop(
            &self.endpoint,
            &self.key,
            se_types::IdempotencyKey::new("runtime-refusal-cleanup")?,
            until,
            &se_host::client::ClientOptions {
                expected_generation: Some(self.endpoint.generation),
                timeout: Duration::from_secs(5),
                cancelled: Arc::new(AtomicBool::new(false)),
            },
        )?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.live_until(deadline, "stop exit")? {
            if Instant::now() >= deadline {
                return Err("exact fixture host did not exit after graceful stop".into());
            }
            std::thread::park_timeout(Duration::from_millis(10));
        }
        Ok(())
    }
}
impl Drop for RunningHost {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!(
                "retaining exact runtime fixture host {}: {error}",
                self.identity.pid.0
            );
        }
    }
}
