use crate::{Check, checked, command};
use se_types::Secret;
use std::{
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

/// Holds the exact observed native instance; PID reuse never proves its exit.
pub struct RunningHost {
    endpoint: se_host::EndpointRecord,
    key: Secret,
    identity: se_proc::ProcessIdentity,
}
impl RunningHost {
    pub fn start(image: &Path, home: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        checked(command(image, home, true).arg("up").output()?)?;
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
        if !self.live_until(Instant::now() + Duration::from_secs(10), "stop preflight")? {
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
