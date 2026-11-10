//! Protected pre-listen binding; a restored SQLite copy cannot revive devices.
use super::*;
use se_core::scope;
use se_types::{IdempotencyKey, Read, Secret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read as _, path::Path};

const FILE: &str = "remote-security.json";
const MAX_BYTES: usize = 4096;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    owner: se_types::HumanId,
    host: RemoteHostId,
    store: se_types::StoreId,
    incarnation: u64,
    credential_sha256: [u8; 32],
    database_identity: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    key: IdempotencyKey,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u16,
    binding: Binding,
    pending: Option<Pending>,
    notice: String,
}
pub(super) struct Fence {
    record: Record,
    hash: [u8; 32],
}
fn unreadable(reason: &str) -> SeError {
    scope::unreadable(
        "remote access startup protection",
        &format!(
            "{reason}. Remote access was not opened; preserve the protected state and restore readable custody before retrying. Unreadable state is not treated as a credential change or restore."
        ),
    )
}
fn binding(
    files: &dyn se_store::StateFiles,
    root: &Path,
    security: &auth::Security,
) -> Result<Binding> {
    let credential = scope::require_present(
        files
            .readback(&root.join("credential"))
            .map_err(|error| store_error(&error))?,
        "machine credential for remote access",
        "Restore the original protected credential; remote access cannot infer its absence or replace it.",
    )?;
    let mut bytes = Vec::new();
    let read = credential.take(33).read_to_end(&mut bytes);
    let secret = Secret::new(bytes);
    read.map_err(|_| unreadable("The machine credential could not be read"))?;
    let secret = secret.map_err(|_| unreadable("The machine credential is malformed"))?;
    if secret.expose().len() != 32 {
        return Err(unreadable(
            "The machine credential must contain exactly 32 bytes",
        ));
    }
    let path = root.join("state.db");
    scope::require_present(
        files.readback(&path).map_err(|error| store_error(&error))?,
        "remote access database",
        "Restore readable protected database custody before starting remote access.",
    )?;
    let pin = se_proc::NativeSourcePin::open(&path)
        .map_err(|error| {
            unreadable(&format!(
                "The database file identity could not be read: {error}"
            ))
        })?
        .ok_or_else(|| unreadable("The database file is absent"))?;
    pin.validate_path(&path).map_err(|error| {
        unreadable(&format!(
            "The database file identity changed during inspection: {error}"
        ))
    })?;
    Ok(Binding {
        owner: security.store.owner.clone(),
        host: security.host(),
        store: security.store.info.id.clone(),
        incarnation: security.store.info.incarnation,
        credential_sha256: Sha256::digest(secret.expose()).into(),
        database_identity: pin.identity(),
    })
}
fn read(files: &dyn se_store::StateFiles, root: &Path) -> Result<Option<(Record, [u8; 32])>> {
    let file = match files
        .readback(&root.join(FILE))
        .map_err(|error| store_error(&error))?
    {
        Read::Absent { .. } => return Ok(None),
        other => scope::require_present(
            other,
            "remote access startup protection",
            "Restore the original protected remote-security.json; do not discard an unresolved invalidation.",
        )?,
    };
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable("The startup binding could not be read"))?;
    if bytes.len() > MAX_BYTES {
        return Err(unreadable("The startup binding exceeds its size limit"));
    }
    let record: Record = serde_json::from_slice(&bytes)
        .map_err(|_| unreadable("The startup binding is malformed"))?;
    if record.schema != 1 || record.binding.incarnation == 0 || record.notice.len() > 512 {
        return Err(unreadable(
            "The startup binding has an unsupported schema or invalid fields",
        ));
    }
    Ok(Some((record, Sha256::digest(bytes).into())))
}
/// Public diagnostic bytes only; reading never initializes or resolves a fence.
pub fn startup_notice(files: &dyn se_store::StateFiles, root: &Path) -> Result<Option<String>> {
    if !policy::enabled(files, root)? {
        return Ok(None);
    }
    let Some((record, _)) = read(files, root)? else {
        return Ok(None);
    };
    if record.pending.is_some() {
        return Err(unreadable(
            "Remote device invalidation is still pending; no remote readiness is established",
        ));
    }
    Ok(Some(record.notice))
}
fn publish(
    files: &dyn se_store::StateFiles,
    root: &Path,
    record: &Record,
    expected: Option<[u8; 32]>,
) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(record)
        .map_err(|_| unreadable("The startup binding could not be encoded"))?;
    if bytes.len() > MAX_BYTES {
        return Err(unreadable("The startup binding exceeds its size limit"));
    }
    let hash = Sha256::digest(&bytes).into();
    files
        .replace_owned(&root.join(FILE), expected, &bytes)
        .map_err(|error| store_error(&error))?;
    if read(files, root)?.is_none_or(|(_, actual)| actual != hash) {
        return Err(unreadable(
            "The published startup binding differs on readback",
        ));
    }
    Ok(hash)
}
impl Fence {
    pub(super) fn load(
        files: &dyn se_store::StateFiles,
        root: &Path,
        security: &auth::Security,
    ) -> Result<Self> {
        let current = binding(files, root, security)?;
        let previous = read(files, root)?;
        if let Some((record, _)) = &previous {
            if record.binding.owner != current.owner || record.binding.host != current.host {
                return Err(unreadable(
                    "The registered Owner or pinned host identity differs from the protected binding; explicit identity recovery is required",
                ));
            }
            if record.binding == current {
                let (record, hash) =
                    previous.ok_or_else(|| unreadable("The startup binding disappeared"))?;
                return Ok(Self { record, hash });
            }
        }
        let reason = match &previous {
            None => "Remote access protection was initialized",
            Some((old, _)) if old.binding.credential_sha256 != current.credential_sha256 => {
                "The machine credential changed"
            }
            Some((old, _))
                if old.binding.store != current.store
                    || old.binding.incarnation != current.incarnation =>
            {
                "The state database incarnation changed"
            }
            Some(_) => "The state database file was replaced, including by a closed-copy restore",
        };
        let record = Record {
            schema: 1,
            binding: current,
            pending: Some(Pending {
                key: IdempotencyKey::new(format!(
                    "remote-startup-{}",
                    se_types::Sha256::from_bytes(super::super::session::entropy()?).hex()
                ))?,
            }),
            notice: format!(
                "Last remote access reset: {reason}. Machine sessions from before that reset were revoked. Reconnect affected machines through authorized SSH setup."
            ),
        };
        // Publish before FULL submission. Cancellation, unknown commit and lost
        // reply all leave a durable obligation that the next start must finish.
        let hash = publish(files, root, &record, previous.map(|(_, hash)| hash))?;
        Ok(Self { record, hash })
    }
    pub(super) fn require_ready(&self) -> Result<()> {
        if self.record.pending.is_some() {
            return Err(unreadable(
                "Remote device invalidation has not completed its FULL commit",
            ));
        }
        Ok(())
    }
    pub(super) fn notice(&self) -> &str {
        &self.record.notice
    }
}
impl Control {
    pub(super) async fn finish_startup(
        &mut self,
        context: &crate::ExecutionContext,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<()> {
        if let Some(pending) = &self.startup.record.pending {
            let result = self
                .security
                .revoke_all_before_listen(pending.key.clone())
                .await?;
            if result.sockets_pending {
                return Err(unreadable("Previous remote sockets have not closed"));
            }
            let files = self.files.clone();
            let root = context.state_directory.clone();
            let security = self.security.clone();
            let mut fence = Fence {
                record: Record {
                    schema: 1,
                    binding: self.startup.record.binding.clone(),
                    pending: None,
                    notice: self.startup.record.notice.clone(),
                },
                hash: self.startup.hash,
            };
            self.startup = context
                .blocking
                .run_owned(deadline, move || {
                    if binding(&*files, &root, &security)? != fence.record.binding {
                        return Err(unreadable(
                            "The credential or database changed again during invalidation",
                        ));
                    }
                    revocations::reset_after_revoke_all(&*files, &root, &security)?;
                    fence.hash = publish(&*files, &root, &fence.record, Some(fence.hash))?;
                    Ok(fence)
                })
                .await?;
            // No listener/control was installed yet. Discard the old instance's
            // all-fenced state; every previous durable grant is now revoked.
            self.security = Arc::new(auth::Security::new(
                self.security.store.clone(),
                &*self.key,
                context.generation,
                context.blocking.clone(),
            )?);
            eprintln!("{}", self.startup.notice());
        }
        let files = self.files.clone();
        let root = context.state_directory.clone();
        let security = self.security.clone();
        context
            .blocking
            .run_owned(deadline, move || {
                revocations::restore(&*files, &root, &security)
            })
            .await?;
        self.startup.require_ready()
    }
}
