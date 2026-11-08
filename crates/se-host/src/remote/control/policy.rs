//! Protected desired listener policy; public identity only, no grant or secret.
use super::*;
use se_types::Read;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read as _, net::SocketAddr, path::Path};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: u16,
    owner: se_types::HumanId,
    host: RemoteHostId,
    address: Option<SocketAddr>,
}
fn read(files: &dyn se_store::StateFiles, root: &Path) -> Result<Option<(Policy, [u8; 32])>> {
    let file = match files
        .readback(&root.join("remote-listener.json"))
        .map_err(|error| store_error(&error))?
    {
        Read::Absent { .. } => return Ok(None),
        other => se_core::scope::require_present(
            other,
            "remote listener policy",
            "Restore its protected native custody before starting this host.",
        )?,
    };
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| SeError::invalid("remote listener policy", "readable protected policy"))?;
    if bytes.len() > 4096 {
        return Err(SeError::invalid(
            "remote listener policy",
            "at most 4096 bytes",
        ));
    }
    let policy: Policy = serde_json::from_slice(&bytes).map_err(|_| {
        SeError::invalid(
            "remote listener policy",
            "the saved schema; preserve malformed policy for recovery",
        )
    })?;
    if policy.schema != 1
        || policy
            .address
            .is_some_and(|address| !address.ip().is_loopback() || address.port() == 0)
    {
        return Err(SeError::invalid(
            "remote listener policy",
            "schema1 and an explicit nonzero loopback address",
        ));
    }
    Ok(Some((policy, Sha256::digest(bytes).into())))
}
pub(super) fn enabled(files: &dyn se_store::StateFiles, root: &Path) -> Result<bool> {
    Ok(read(files, root)?.is_some_and(|(policy, _)| policy.address.is_some()))
}
impl Control {
    pub(super) async fn disabled_without_resources(
        router: &crate::HostedRouter,
        owner: &auth::VerifiedLocalOwner,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<bool> {
        if owner.generation != router.execution.generation.get()
            || owner.deadline <= std::time::Instant::now()
        {
            return Err(SeError::invalid(
                "remote disable",
                "current native human admission",
            ));
        }
        let root = router.execution.state_directory.clone();
        let owner = owner.owner.clone();
        router
            .execution
            .blocking
            .run_owned(deadline, move || {
                let files = crate::state_files::Files::open_with_policy(
                    &root,
                    crate::state_files::FilePolicy::Host,
                )
                .map_err(|error| store_error(&error))?;
                match read(&files, &root)? {
                    None => Ok(true),
                    Some((policy, _)) if policy.owner == owner => Ok(policy.address.is_none()),
                    _ => Err(SeError::invalid(
                        "remote disable",
                        "the policy's original registered native Owner",
                    )),
                }
            })
            .await
    }
    pub(super) async fn persist(
        &self,
        router: &crate::HostedRouter,
        owner: auth::VerifiedLocalOwner,
        address: Option<SocketAddr>,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<()> {
        self.security.owner(&owner)?;
        let files = self.files.clone();
        let root = router.execution.state_directory.clone();
        let host = self.security.host();
        router.execution.blocking.run_owned(deadline,move || {
            if owner.deadline<=std::time::Instant::now() {return Err(SeError::invalid("remote listener policy","current native human admission"));}
            let prior=read(&*files,&root)?;
            if prior.as_ref().is_some_and(|(policy,_)|policy.owner!=owner.owner || policy.host!=host) {return Err(SeError::invalid("remote listener policy","the original registered Owner and pinned host identity; restore them before changing exposure"));}
            let policy=Policy {schema:1,owner:owner.owner,host,address};
            let bytes=serde_json::to_vec(&policy).map_err(|_|SeError::invalid("remote listener policy","bounded public configuration"))?;
            files.replace_owned(&root.join("remote-listener.json"),prior.map(|(_,hash)|hash),&bytes).map_err(|error|store_error(&error))?;
            let actual=read(&*files,&root)?.ok_or_else(||SeError::invalid("remote listener policy","the published protected policy"))?.0;
            if actual.owner!=policy.owner || actual.host!=host || actual.address!=address {return Err(SeError::invalid("remote listener policy","the exact published listener state"));}
            Ok(())
        }).await
    }
}
impl crate::HostedRuntime {
    /// Finish protected invalidation before publishing local runtime readiness.
    /// A disabled/absent policy performs no key read, ring allocation or task start.
    pub async fn prepare_remote_listener(
        &self,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<Option<SocketAddr>> {
        let context = self.execution.clone();
        let owner = self.owner.clone();
        let prepared = self
            .execution
            .blocking
            .run_owned(deadline, move || {
                let root = &context.state_directory;
                let files = crate::state_files::Files::open_with_policy(
                    root,
                    crate::state_files::FilePolicy::Host,
                )
                .map_err(|error| store_error(&error))?;
                let Some((policy, _)) = read(&files, root)? else {
                    return Ok(None);
                };
                if policy.owner != owner {
                    return Err(SeError::invalid(
                        "remote listener policy",
                        "the actual registered native host Owner",
                    ));
                }
                let Some(address) = policy.address else {
                    return Ok(None);
                };
                if let Some(control) = context.mail_waits.remote_control() {
                    if control.security.host() != policy.host {
                        return Err(SeError::invalid(
                            "remote listener policy",
                            "the saved persistent host pin",
                        ));
                    }
                    return Ok(Some((None, address)));
                }
                let control = Control::load(&context, owner, None)?;
                if control.security.host() != policy.host {
                    return Err(SeError::invalid(
                        "remote listener policy",
                        "the saved persistent host pin; keys cannot be silently replaced",
                    ));
                }
                Ok(Some((Some(control), address)))
            })
            .await?;
        let Some((control, address)) = prepared else {
            return Ok(None);
        };
        if let Some(mut control) = control {
            control.finish_startup(&self.execution, deadline).await?;
            self.execution
                .mail_waits
                .install_remote_control(Arc::new(control))?;
        }
        Ok(Some(address))
    }
    /// Start only after local native custody activation and pre-listen protection.
    pub async fn restore_remote_listener(
        &self,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<()> {
        let Some(address) = self.prepare_remote_listener(deadline).await? else {
            return Ok(());
        };
        let router = self.router()?;
        let installed = self.execution.mail_waits.remote_control().ok_or_else(|| {
            SeError::invalid("remote listener policy", "the installed native control")
        })?;
        installed.start(&router, address, deadline).await?;
        Ok(())
    }
}
