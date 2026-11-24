//! Owner setup verifies one reusable connection before publishing its name.
use super::*;
use se_types::Read;
use sha2::Digest;
impl Control {
    pub(super) async fn add(
        &self,
        router: &crate::HostedRouter,
        owner: auth::VerifiedLocalOwner,
        destination: String,
        alias: String,
        distribution: se_types::NativePath,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<serde_json::Value> {
        self.security.owner(&owner)?;
        let _configure = self.configure.lock().await;
        let prior = self
            .check_add(router, &destination, &alias, deadline)
            .await?;
        // Explicit setup may renew an expired session through authorized SSH.
        // Ordinary agent calls never create or restore machine authority.
        let (session, command) =
            ssh::connect(&destination, self.security.host(), distribution.to_local()?).await?;
        if let Some(prior) = &prior
            && prior.binding.paired.host != session.device.host
        {
            return Err(SeError::invalid(
                "saved machine",
                "the original destination identity; the incumbent binding was preserved",
            ));
        }
        let local = match &prior {
            Some(prior) => prior.binding.route,
            None => std::net::TcpListener::bind("127.0.0.1:0")
                .map_err(|_| SeError::invalid("SSH forward", "an available local loopback port"))?
                .local_addr()
                .map_err(|_| SeError::invalid("SSH forward", "its reserved local address"))?,
        };
        let host = session.device.host;
        let binding = bindings::SavedBinding {
            connected: true,
            alias: alias.clone(),
            route: local,
            paired: session.device,
            credential_sha256: CredentialDigest(
                sha2::Sha256::digest(session.secret.expose()).into(),
            ),
            forward: Some(ssh::ForwardConfig {
                destination,
                local,
                remote_port: session.port,
                command,
                host,
            }),
        };
        let records = self.records.clone();
        let save = binding.clone();
        let secret = session.secret;
        let key = router
            .execution
            .blocking
            .run_owned(deadline, move || records.keep_credential(&save, &secret))
            .await?;
        let unchanged = prior
            .as_ref()
            .is_some_and(|prior| prior.binding.same_authority(&binding));
        let expected = self
            .fence_prior(router, &owner, prior.as_ref(), unchanged, deadline)
            .await?;
        let forwards = router.execution.mail_waits.forwards();
        let config = binding
            .forward
            .clone()
            .ok_or_else(|| SeError::invalid("SSH forward", "verified configuration"))?;
        forwards.activate(config.clone()).await?;
        let result = self
            .verify_and_save(router, owner, &binding, key, expected, deadline)
            .await;
        if let Err(error) = result {
            if !unchanged && let Err(close) = forwards.disconnect(config).await {
                return Err(error.with_cause(close));
            }
            return Err(error);
        }
        Ok(
            serde_json::json!({"state":"connected","name":alias,"host":binding.paired.host,"reused":prior.is_some()}),
        )
    }
    /// Fence cached callers before replacing a changed source transport.
    /// Returns the saved record hash the new binding must replace.
    async fn fence_prior(
        &self,
        router: &crate::HostedRouter,
        owner: &auth::VerifiedLocalOwner,
        prior: Option<&bindings::BindingRecord>,
        unchanged: bool,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<Option<[u8; 32]>> {
        let Some(prior) = prior else {
            return Ok(None);
        };
        if unchanged {
            return Ok(Some(prior.sha256));
        }
        let mut disconnected = prior.binding.clone();
        disconnected.connected = false;
        let records = self.records.clone();
        let owner = owner.clone();
        let hash = prior.sha256;
        let fenced = router
            .execution
            .blocking
            .run_owned(deadline, move || {
                records.save(&owner, disconnected, Some(hash))
            })
            .await?
            .sha256;
        self.close_source(router, &prior.binding).await?;
        Ok(Some(fenced))
    }
    /// Prove one reusable connection through the forward before saving its name.
    async fn verify_and_save(
        &self,
        router: &crate::HostedRouter,
        owner: auth::VerifiedLocalOwner,
        binding: &bindings::SavedBinding,
        key: keys::ProtectedCredential,
        expected: Option<[u8; 32]>,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<()> {
        let connector = client::ClientConnector::with_forwards(
            router.execution.blocking.clone(),
            router.execution.mail_waits.forwards(),
        );
        let connected = connector
            .connect(
                RemoteRoute {
                    address: binding.route,
                    host: binding.paired.host,
                    forward: binding.forward.clone(),
                },
                binding.paired.clone(),
                Arc::new(key),
            )
            .await?;
        connected.close().await?;
        let records = self.records.clone();
        let save = binding.clone();
        router
            .execution
            .blocking
            .run_owned(deadline, move || records.save(&owner, save, expected))
            .await?;
        Ok(())
    }
    async fn close_source(
        &self,
        router: &crate::HostedRouter,
        binding: &bindings::SavedBinding,
    ) -> Result<()> {
        if let Some(broker) = router.execution.mail_waits.remote() {
            broker.disconnect(binding.paired.host).await?;
        }
        if let Some(config) = binding.forward.clone() {
            router
                .execution
                .mail_waits
                .forwards()
                .disconnect(config)
                .await?;
        }
        Ok(())
    }
}

impl Control {
    pub(super) async fn disconnect(
        &self,
        router: &crate::HostedRouter,
        owner: auth::VerifiedLocalOwner,
        alias: String,
        forget: bool,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<serde_json::Value> {
        self.security.owner(&owner)?;
        let _configure = self.configure.lock().await;
        let records = self.records.clone();
        let name = alias.clone();
        let (binding, hash) = router
            .execution
            .blocking
            .run_owned(deadline, move || {
                let record = se_core::scope::require_present(
                    records.read(&name)?,
                    "saved machine",
                    "Use an existing machine name.",
                )?;
                let mut binding = record.binding;
                binding.connected = false;
                let saved = records.save(&owner, binding, Some(record.sha256))?;
                Ok((saved.binding, saved.sha256))
            })
            .await?;
        self.close_source(router, &binding).await?;
        if forget {
            let records = self.records.clone();
            router
                .execution
                .blocking
                .run_owned(deadline, move || records.forget(&binding, hash))
                .await?;
        }
        Ok(
            serde_json::json!({"state":if forget {"forgotten"} else {"disconnected"},"name":alias,"remote_host_stopped":false}),
        )
    }
    pub(super) async fn check_add(
        &self,
        router: &crate::HostedRouter,
        destination: &str,
        alias: &str,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<Option<bindings::BindingRecord>> {
        let records = self.records.clone();
        let name = alias.to_owned();
        let prior = router
            .execution
            .blocking
            .run_owned(deadline, move || match records.read(&name)? {
                Read::Absent { .. } => Ok(None),
                read => se_core::scope::require_present(
                    read,
                    "saved machine",
                    "Restore readable protected custody; unreadable setup is never replaced.",
                )
                .map(Some),
            })
            .await?;
        if let Some(prior) = &prior
            && prior
                .binding
                .forward
                .as_ref()
                .is_none_or(|f| f.destination != destination)
        {
            return Err(SeError::invalid(
                "saved machine",
                "its original SSH destination; explicitly forget the old connection before choosing another",
            ));
        }
        Ok(prior)
    }
}
