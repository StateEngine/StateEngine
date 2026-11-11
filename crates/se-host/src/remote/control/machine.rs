//! SSH bootstrap reuses a durable machine session. Agents never receive it.
use super::*;
use se_store::{
    Actor, Revision,
    remote::{GRANT_INACTIVITY_US, GrantRecord, GrantState, SecurityTransition},
};
use se_types::{IdempotencyKey, Read};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read as _, num::NonZeroU64};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingSession {
    grant: GrantRecord,
    secret: LinkSecret,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapSession {
    pub device: MachineSession,
    pub secret: LinkSecret,
    pub port: u16,
}

impl Control {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) async fn bootstrap(
        &self,
        router: &crate::HostedRouter,
        owner: auth::VerifiedLocalOwner,
        source_host: RemoteHostId,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<serde_json::Value> {
        self.security.owner(&owner)?;
        if source_host == self.security.host() {
            return Err(SeError::invalid(
                "remote destination",
                "a different StateEngine host",
            ));
        }
        let _configure = self.configure.lock().await;
        let files = self.files.clone();
        let security = self.security.clone();
        let root = router.execution.state_directory.clone();
        let (mut pending,mut hash) = router.execution.blocking.run_owned(deadline, move || {
            let directory = root.join("remote-sessions");
            let path = directory.join(format!("{}.json", source_host.0.hex()));
            let pending = match files.readback(&path).map_err(|e| store_error(&e))? {
                Read::Absent { .. } => {
                    let pending = fresh(&security, source_host)?;
                    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&pending).map_err(|_| SeError::invalid("machine session", "serializable protected record"))?);
                    files.prepare_directory(&directory).map_err(|e| store_error(&e))?;
                    files.replace_owned(&path, None, &bytes).map_err(|e| store_error(&e))?;
                    let hash=Sha256::digest(&*bytes).into();
                    (pending,hash)
                }
                read => {
                    let file = se_core::scope::require_present(read, "machine session", "Restore readable protected session custody; an unreadable record is never replaced.")?;
                    let mut bytes = zeroize::Zeroizing::new(Vec::new());
                    file.take(65537).read_to_end(&mut bytes).map_err(|_| SeError::invalid("machine session", "readable protected record"))?;
                    if bytes.len() > 65536 {return Err(SeError::invalid("machine session", "at most 64 KiB"));}
                    let pending=serde_json::from_slice(&bytes).map_err(|_| SeError::invalid("machine session", "the original protected record; preserve malformed state"))?;
                    (pending,Sha256::digest(&*bytes).into())
                }
            };
            if pending.0.grant.host != security.host() || pending.0.grant.store != security.store.info.id
                || pending.0.grant.subject != (RemoteSubject::Machine {host: source_host})
            {return Err(SeError::invalid("machine session", "the original source, destination and store"));}
            Ok(pending)
        }).await?;
        let grant = loop {
            let key = IdempotencyKey::new(format!("ssh-session-{}", pending.grant.grant))?;
            let transition = SecurityTransition::Connect {
                grant: Box::new(pending.grant.clone()),
            };
            let intent = serde_json::json!({"grant":pending.grant});
            self.security
                .store
                .commit(Actor::Human(owner.owner.clone()), key, transition, intent)
                .await?;
            let security = self.security.clone();
            let id = pending.grant.grant;
            let grant = router
                .execution
                .blocking
                .run_owned(deadline, move || security.store.grant(&id))
                .await?;
            if grant.state == GrantState::Active
                && grant.expires_at_us > crate::remote::session::now()?
            {
                break grant;
            }
            // This is explicit, native-owner SSH setup, not agent discovery. New
            // session ids leave old grant tombstones and agent policy intact.
            let files = self.files.clone();
            let security = self.security.clone();
            let root = router.execution.state_directory.clone();
            (pending, hash) = router
                .execution
                .blocking
                .run_owned(deadline, move || {
                    let pending = fresh(&security, source_host)?;
                    let bytes =
                        zeroize::Zeroizing::new(serde_json::to_vec(&pending).map_err(|_| {
                            SeError::invalid("machine session", "serializable protected record")
                        })?);
                    files
                        .replace_owned(
                            &root
                                .join("remote-sessions")
                                .join(format!("{}.json", source_host.0.hex())),
                            Some(hash),
                            &bytes,
                        )
                        .map_err(|e| store_error(&e))?;
                    let hash = Sha256::digest(&*bytes).into();
                    Ok((pending, hash))
                })
                .await?;
        };
        let enabled = self
            .start(
                router,
                "127.0.0.1:0"
                    .parse()
                    .map_err(|_| SeError::invalid("listener", "loopback"))?,
                deadline,
            )
            .await?;
        let address: std::net::SocketAddr = serde_json::from_value(enabled["address"].clone())
            .map_err(|_| SeError::invalid("remote listener", "its actual bound address"))?;
        self.persist(router, owner, Some(address), deadline).await?;
        let session = BootstrapSession {
            device: MachineSession {
                host: grant.host,

                grant: grant.grant,
                device: grant.device,
                subject: grant.subject,
                scope: grant.scope,
                authority_revision: grant.authority_revision.value.get(),
                expires_at: se_types::UnixMicros::new(
                    u64::try_from(grant.expires_at_us)
                        .map_err(|_| SeError::invalid("session expiry", "nonnegative time"))?,
                )?,
            },
            secret: pending.secret,
            port: address.port(),
        };
        serde_json::to_value(session).map_err(|_| {
            SeError::invalid("machine session", "bounded protected bootstrap response")
        })
    }
}

fn fresh(security: &auth::Security, source_host: RemoteHostId) -> Result<PendingSession> {
    let at = crate::remote::session::now()?;
    let millis = u64::try_from(at / 1000)
        .map_err(|_| SeError::invalid("machine session clock", "nonnegative time"))?;
    let secret = LinkSecret::new(crate::remote::session::entropy()?);
    let revision = Revision {
        value: NonZeroU64::MIN,
    };
    let grant = GrantRecord {
        grant: RemoteGrantId::from_parts(millis, crate::remote::session::entropy()?)?,
        principal: RemotePrincipalId::from_parts(millis, crate::remote::session::entropy()?)?,
        device: RemoteDeviceId::from_parts(millis, crate::remote::session::entropy()?)?,
        credential_sha256: CredentialDigest(Sha256::digest(secret.expose()).into()),
        host: security.host(),
        store: security.store.info.id.clone(),
        subject: RemoteSubject::Machine { host: source_host },
        scope: RemoteScope {
            targets: vec![],
            verbs: vec![RemoteVerb::List, RemoteVerb::Watch, RemoteVerb::Send],
        },
        issued_at_us: at,
        authority_revision: revision,
        state: GrantState::Active,
        last_use_at_us: at,
        expires_at_us: at
            .checked_add(GRANT_INACTIVITY_US)
            .ok_or_else(|| SeError::invalid("session lease", "valid timestamp"))?,
        lease_revision: revision,
    };
    Ok(PendingSession { grant, secret })
}
