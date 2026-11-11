//! Owner setup verifies one reusable connection before publishing its name.
use super::*;
use se_types::Read;
use sha2::Digest;
impl Control {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
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
        let records = self.records.clone();
        let name = alias.clone();
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
        let local = if let Some(prior) = &prior {
            prior.binding.route
        } else {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")
                .map_err(|_| SeError::invalid("SSH forward", "an available local loopback port"))?;
            listener
                .local_addr()
                .map_err(|_| SeError::invalid("SSH forward", "its reserved local address"))?
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
        let files = self.files.clone();
        let save = binding.clone();
        let key = router.execution.blocking.run_owned(deadline, move || {
            records.check_machine(&save)?;
            let path = records.key_path(&save.paired.grant);
            files.prepare_directory(path.parent().ok_or_else(||SeError::invalid("machine credential", "protected parent"))?).map_err(|e|store_error(&e))?;
            match files.readback(&path).map_err(|e|store_error(&e))? {
                Read::Absent {..} => files.replace_owned(&path,None,session.secret.expose()).map_err(|e|store_error(&e))?,
                read => {
                    use std::io::Read as _;
                    let file=se_core::scope::require_present(read,"machine credential","Restore the original protected credential; unreadable material is never replaced.")?;
                    let mut old=zeroize::Zeroizing::new(Vec::new());
                    file.take(33).read_to_end(&mut old).map_err(|_|SeError::invalid("machine credential","readable original credential"))?;
                    if old.as_slice()!=session.secret.expose() {return Err(SeError::invalid("machine credential","the original session; preserve conflicting credential material"));}
                }
            }
            keys::ProtectedCredential::open(files,path)
        }).await?;
        let unchanged = prior
            .as_ref()
            .is_some_and(|prior| prior.binding.same_authority(&binding));
        let mut expected = prior.as_ref().map(|record| record.sha256);
        if let Some(prior) = &prior
            && !unchanged
        {
            // Fence cached callers before replacing this source transport.
            let mut disconnected = prior.binding.clone();
            disconnected.connected = false;
            let records = self.records.clone();
            let owner = owner.clone();
            let hash = prior.sha256;
            expected = Some(
                router
                    .execution
                    .blocking
                    .run_owned(deadline, move || {
                        records.save(&owner, disconnected, Some(hash))
                    })
                    .await?
                    .sha256,
            );
            self.close_source(router, &prior.binding).await?;
        }
        let forwards = router.execution.mail_waits.forwards();
        let config = binding
            .forward
            .clone()
            .ok_or_else(|| SeError::invalid("SSH forward", "verified configuration"))?;
        forwards.activate(config.clone()).await?;
        let result = async {
            let connector = client::ClientConnector::with_forwards(
                router.execution.blocking.clone(),
                forwards.clone(),
            );
            let connected = connector
                .connect(
                    RemoteRoute {
                        address: local,
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
            Ok::<_, SeError>(())
        }
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
}
