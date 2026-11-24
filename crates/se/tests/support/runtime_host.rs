#[cfg(not(windows))]
use crate::checked;
use crate::executable::ExecutableCommand;
use crate::{Check, command};
use se_types::Secret;
use std::{
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

/// Remove the static `listen_port` written by `se init` so parallel test hosts
/// bind OS-selected ephemeral loopback ports (port 0) instead of colliding in
/// `20000..=29999`. Callers that test explicit `runtime.listen_port` behavior
/// must not call this.
#[allow(
    dead_code,
    reason = "Explicit-port tests include runtime_host without stripping runtime.listen_port."
)]
pub fn use_ephemeral_listen_port(home: &Path) -> Check {
    let path = home.join("config.toml");
    let text = std::fs::read_to_string(&path)?;
    let mut table: toml::Table = toml::from_str(&text)?;
    if let Some(runtime) = table.get_mut("runtime").and_then(toml::Value::as_table_mut) {
        runtime.remove("listen_port");
    }
    std::fs::write(&path, toml::to_string_pretty(&table)?)?;
    Ok(())
}

/// Holds the exact observed native instance; PID reuse never proves its exit.
pub struct RunningHost {
    #[cfg(windows)]
    child: foreground_host::ForegroundHost,
    endpoint: se_host::EndpointRecord,
    key: Secret,
    identity: se_proc::ProcessIdentity,
    // Declared last: it disarms only after Drop has stopped the host. Windows
    // fixtures own a foreground host, which carries its own reaper.
    #[cfg(not(windows))]
    _reaper: Option<crate::home_reaper::HomeReaper>,
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
        // A killed test process runs neither guard below; the reaper stops the
        // detached host then. It outlives the startup cleanup on failure.
        #[cfg(not(windows))]
        let reaper = crate::home_reaper::HomeReaper::arm(
            command(image, home, true).arg("down"),
            home,
            false,
        )?;
        let mut cleanup = StartupCleanup {
            image,
            home,
            armed: true,
        };
        let result = Self::start_observed(image, home);
        cleanup.armed = result.is_err();
        // On failure the reaper must outlive `cleanup`, so it is only moved on success.
        #[cfg(not(windows))]
        let result = match result {
            Ok(mut host) => {
                host._reaper = Some(reaper);
                Ok(host)
            }
            Err(error) => Err(error),
        };
        result
    }
    fn start_observed(image: &Path, home: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(windows)]
        let child = foreground_host::ForegroundHost::start(command(image, home, true), home)?;
        #[cfg(not(windows))]
        checked(command(image, home, true).arg("up").output_executable()?)?;
        let endpoint = se_host::client::endpoint::decode_endpoint(&std::fs::read(
            home.join("endpoint.json"),
        )?)?;
        let expected = endpoint.epoch.owner.fields();
        #[cfg(windows)]
        assert_eq!(child.ready()["process"]["pid"], expected.pid.get());
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
            #[cfg(windows)]
            child,
            endpoint,
            key: Secret::new(std::fs::read(home.join("credential"))?)?,
            identity: observed.identity,
            #[cfg(not(windows))]
            _reaper: None,
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
            #[cfg(windows)]
            self.child.wait()?;
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
        #[cfg(windows)]
        self.child.wait()?;
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

#[cfg(windows)]
#[path = "foreground_host.rs"]
mod foreground_host;
