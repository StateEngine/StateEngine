//! Owned loopback forwarding through the user's SSH configuration.
//! Dropping a forward closes only SSH; it never stops a remote host or agent.
use super::RemoteReady;
use super::channel::unavailable;
mod authorization;
mod bootstrap;
mod staging;
pub use authorization::{Authorization, AuthorizationResult, Request as SshRequest, StartResult};
pub use bootstrap::connect;
use se_types::{Result, SeError};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::SocketAddr, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    process::{Child, Command},
    sync::Mutex,
    time::timeout,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    pub destination: String,
    pub local: SocketAddr,
    pub remote_port: u16,
    pub command: String,
    pub host: super::RemoteHostId,
}
impl ForwardConfig {
    pub fn validate(&self) -> Result<()> {
        validate_destination(&self.destination)?;
        if !self.local.ip().is_loopback() || self.local.port() == 0 || self.remote_port == 0 {
            return Err(SeError::invalid("SSH forward", "nonzero loopback ports"));
        }
        if self.command.is_empty()
            || self.command.len() > 4096
            || self.command.chars().any(char::is_control)
        {
            return Err(SeError::invalid(
                "SSH command",
                "the saved native connection command",
            ));
        }
        Ok(())
    }
}

/// SSH accepts options and a remote shell command, so a destination must never
/// become either. Configuration aliases, user@host and literal IPs remain valid.
pub fn validate_destination(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 255
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-@:[]".contains(&b))
    {
        return Err(SeError::invalid(
            "SSH destination",
            "an SSH configuration alias or user@host without shell syntax",
        ));
    }
    Ok(())
}

struct Forward {
    config: ForwardConfig,
    child: Option<Child>,
    enabled: bool,
}
impl Forward {
    async fn ensure(&mut self) -> Result<()> {
        if !self.enabled {
            return Err(unavailable(
                "machine is disconnected; explicitly add it again to reconnect",
            ));
        }
        if let Some(child) = &mut self.child {
            match child.try_wait() {
                Ok(None) => return Ok(()),
                Ok(Some(_)) => {
                    self.child = None;
                }
                Err(_) => return Err(unavailable("cannot inspect the owned SSH process")),
            }
        }
        self.config.validate()?;
        // An occupied port is never evidence that our earlier forward survived.
        // Do not connect application credentials to an unrelated local listener.
        let reservation = std::net::TcpListener::bind(self.config.local)
            .map_err(|_| unavailable("saved SSH forward port is occupied; close the conflicting application or explicitly reconnect this machine"))?;
        drop(reservation);
        let mapping = format!(
            "{}:127.0.0.1:{}",
            self.config.local, self.config.remote_port
        );
        let child = Command::new("ssh")
            .args(["-N", "-T", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
                "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2", "-L"])
            .arg(mapping).arg(&self.config.destination)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .kill_on_drop(true).spawn()
            .map_err(|_| unavailable("cannot start SSH; install the system SSH client and check the saved destination"))?;
        self.child = Some(child);
        // Readiness carries no application credential. The short-lived SSH
        // authorization below must still confirm the actual native channel;
        // a foreign listener cannot turn this TCP probe into authenticated data.
        let ready = timeout(Duration::from_secs(15), async {
            loop {
                let running = self.child.as_mut().ok_or_else(|| unavailable("owned SSH process is absent"))?
                    .try_wait().map_err(|_| unavailable("cannot inspect SSH readiness"))?.is_none();
                if !running {
                    return Err(unavailable("SSH forwarding failed; check authentication, host-key trust and forwarding permission"));
                }
                if let Ok(Ok(stream)) = timeout(Duration::from_millis(100), tokio::net::TcpStream::connect(self.config.local)).await {
                    drop(stream);
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await;
        match ready {
            Ok(Ok(())) => Ok(()),
            result => {
                self.close().await?;
                match result {
                    Ok(Err(error)) => Err(error),
                    _ => Err(unavailable(
                        "SSH forwarding readiness exceeded fifteen seconds",
                    )),
                }
            }
        }
    }
    async fn authorize(&mut self, authorization: Authorization) -> Result<RemoteReady> {
        let result = authorization::run(&self.config, authorization).await;
        if result
            .as_ref()
            .is_err_and(|error| error.code() == se_types::Code::ListenerUnavailable)
        {
            self.close().await?;
        }
        result
    }
    async fn close(&mut self) -> Result<()> {
        if let Some(child) = &mut self.child {
            if child
                .try_wait()
                .map_err(|_| unavailable("cannot inspect owned SSH shutdown"))?
                .is_none()
            {
                child
                    .start_kill()
                    .map_err(|_| unavailable("cannot close the owned SSH process"))?;
            }
            child
                .wait()
                .await
                .map_err(|_| unavailable("cannot join the owned SSH process"))?;
            self.child = None;
        }
        Ok(())
    }
}

/// Only active destinations retain process state. Callers on one source host
/// share this manager; agent enrollment allocates no SSH process or slot.
#[derive(Default)]
pub struct Forwards {
    entries: Mutex<BTreeMap<String, Arc<Mutex<Forward>>>>,
    closed: std::sync::atomic::AtomicBool,
}
impl Forwards {
    pub async fn ensure(
        &self,
        config: ForwardConfig,
        signer: Arc<dyn super::CredentialSource>,
        blocking: &crate::BlockingPool,
    ) -> Result<SocketAddr> {
        self.ensure_inner(config, Some((signer, blocking))).await
    }
    async fn ensure_inner(
        &self,
        config: ForwardConfig,
        admission: Option<(Arc<dyn super::CredentialSource>, &crate::BlockingPool)>,
    ) -> Result<SocketAddr> {
        config.validate()?;
        let alias = config.host.0.hex();
        let entry = {
            let mut entries = self.entries.lock().await;
            if self.closed.load(std::sync::atomic::Ordering::Acquire) {
                return Err(unavailable("owning source host is closing"));
            }
            entries
                .entry(alias)
                .or_insert_with(|| {
                    Arc::new(Mutex::new(Forward {
                        config: config.clone(),
                        child: None,
                        enabled: true,
                    }))
                })
                .clone()
        };
        let mut forward = entry.lock().await;
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(unavailable("owning source host is closing"));
        }
        if forward.config != config {
            return Err(unavailable(
                "saved SSH destination changed while its link is retained; explicitly disconnect before replacing it",
            ));
        }
        let result = async {
            if let Some((signer, blocking)) = admission {
                let deadline =
                    crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
                        expected_generation: None,
                        timeout: Duration::from_secs(10),
                        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    })?;
                // Recheck protected custody while holding this link's lock.
                // Disconnect either follows and joins this spawn, or precedes
                // this read and prevents a stale client from recreating it.
                blocking
                    .run_owned(&deadline, move || signer.credential())
                    .await?;
            }
            forward.ensure().await?;
            Ok(forward.config.local)
        }
        .await;
        if result.is_err() && forward.child.is_none() {
            forward.enabled = false;
            let mut entries = self.entries.lock().await;
            if entries
                .get(&config.host.0.hex())
                .is_some_and(|current| Arc::ptr_eq(current, &entry))
            {
                entries.remove(&config.host.0.hex());
            }
        }
        result
    }
    pub async fn authorize(
        &self,
        config: ForwardConfig,
        authorization: Authorization,
    ) -> Result<RemoteReady> {
        let entry = self
            .entries
            .lock()
            .await
            .get(&config.host.0.hex())
            .cloned()
            .ok_or_else(|| unavailable("owned SSH authorization link is absent"))?;
        let mut forward = entry.lock().await;
        if self.closed.load(std::sync::atomic::Ordering::Acquire) || !forward.enabled {
            return Err(unavailable("source connection is closing"));
        }
        forward.authorize(authorization).await
    }
    /// Reviving an idle far host stays inside this owned forward's disconnect
    /// lock and rechecks local credential custody before invoking saved SSH.
    pub async fn restart(
        &self,
        config: ForwardConfig,
        signer: Arc<dyn super::CredentialSource>,
        blocking: &crate::BlockingPool,
    ) -> Result<()> {
        let entry = self
            .entries
            .lock()
            .await
            .get(&config.host.0.hex())
            .cloned()
            .ok_or_else(|| unavailable("owned SSH restart link is absent"))?;
        let forward = entry.lock().await;
        if self.closed.load(std::sync::atomic::Ordering::Acquire)
            || !forward.enabled
            || forward.config != config
        {
            return Err(unavailable(
                "saved SSH connection changed or was disconnected",
            ));
        }
        let deadline =
            crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
                expected_generation: None,
                timeout: Duration::from_secs(25),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            })?;
        blocking
            .run_owned(&deadline, move || signer.credential())
            .await?;
        authorization::restart(&config).await
    }
    pub async fn activate(&self, config: ForwardConfig) -> Result<SocketAddr> {
        config.validate()?;
        let key = config.host.0.hex();
        let entry = self.entries.lock().await.get(&key).cloned();
        if let Some(entry) = entry {
            let mut forward = entry.lock().await;
            if !forward.enabled && forward.child.is_none() {
                forward.config = config.clone();
            }
            forward.enabled = true;
        }
        self.ensure_inner(config, None).await
    }
    pub async fn disconnect(&self, config: ForwardConfig) -> Result<()> {
        let key = config.host.0.hex();
        let entry = self.entries.lock().await.get(&key).cloned();
        if let Some(entry) = entry {
            let mut forward = entry.lock().await;
            forward.enabled = false;
            forward.close().await?;
            let mut entries = self.entries.lock().await;
            if entries
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &entry))
            {
                entries.remove(&key);
            }
        }
        Ok(())
    }
    pub async fn close(&self) -> Result<()> {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        let entries: Vec<_> = self.entries.lock().await.values().cloned().collect();
        let mut first = None;
        for entry in entries {
            if let Err(error) = entry.lock().await.close().await {
                first.get_or_insert(error);
            }
        }
        if first.is_none() {
            self.entries.lock().await.clear();
        }
        first.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn destination_cannot_inject_an_option_or_shell_command() {
        for bad in [
            "",
            "-oProxyCommand=anything",
            "host command",
            "host;echo",
            "$(echo)",
            "host\ncommand",
            "host'",
            "host/command",
        ] {
            assert!(validate_destination(bad).is_err(), "{bad:?}");
        }
        for good in ["build-box", "user@example.org", "127.0.0.1", "user@[::1]"] {
            assert!(validate_destination(good).is_ok(), "{good:?}");
        }
    }
}
