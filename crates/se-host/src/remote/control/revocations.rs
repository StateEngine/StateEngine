//! Protected unresolved revoke intents survive cancellation and host restart.
use super::*;
// Bounded unresolved work, independent of enrolled machines or agents.
const MAX_PENDING_REVOKES: usize = 128;
use se_types::{IdempotencyKey, Read};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read as _, path::Path};

const MAX_BYTES: usize = 65536;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub grant: se_types::RemoteGrantId,
    pub authority_revision: u64,
    pub key: IdempotencyKey,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u16,
    host: RemoteHostId,
    owner: se_types::HumanId,
    store: se_types::StoreId,
    incarnation: u64,
    pending: Vec<Pending>,
}
fn invalid() -> SeError {
    SeError::invalid(
        "unresolved remote revocation",
        "the original protected revoke intents and host/store binding; retry the exact grant, revision and original key through native Owner control",
    )
}
fn read(
    files: &dyn se_store::StateFiles,
    root: &Path,
    security: &auth::Security,
) -> Result<Option<(Journal, [u8; 32])>> {
    let Some((journal, hash)) = read_journal(files, root)? else {
        return Ok(None);
    };
    if journal.host != security.host()
        || journal.owner != security.store.owner
        || journal.store != security.store.info.id
        || journal.incarnation != security.store.info.incarnation
    {
        return Err(invalid());
    }
    Ok(Some((journal, hash)))
}
fn read_journal(
    files: &dyn se_store::StateFiles,
    root: &Path,
) -> Result<Option<(Journal, [u8; 32])>> {
    let file = match files
        .readback(&root.join("remote-revocations.json"))
        .map_err(|error| store_error(&error))?
    {
        Read::Absent { .. } => return Ok(None),
        other => se_core::scope::require_present(
            other,
            "unresolved remote revocations",
            "Restore protected custody; do not discard an unresolved revoke intent.",
        )?,
    };
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    let journal: Journal = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if journal.schema != 1
        || journal.pending.len() > MAX_PENDING_REVOKES
        || journal.pending.iter().enumerate().any(|(i, entry)| {
            entry.authority_revision == 0
                || entry.authority_revision > i64::MAX as u64
                || journal.pending[..i]
                    .iter()
                    .any(|prior| prior.grant == entry.grant)
        })
    {
        return Err(invalid());
    }
    Ok(Some((journal, Sha256::digest(bytes).into())))
}
/// Only after the startup fence's FULL revoke-all resolved every old grant.
pub(super) fn reset_after_revoke_all(
    files: &dyn se_store::StateFiles,
    root: &Path,
    security: &auth::Security,
) -> Result<()> {
    let Some((mut journal, hash)) = read_journal(files, root)? else {
        return Ok(());
    };
    if journal.owner != security.store.owner || journal.host != security.host() {
        return Err(invalid());
    }
    journal.store = security.store.info.id.clone();
    journal.incarnation = security.store.info.incarnation;
    journal.pending.clear();
    let bytes = serde_json::to_vec(&journal).map_err(|_| invalid())?;
    files
        .replace_owned(&root.join("remote-revocations.json"), Some(hash), &bytes)
        .map_err(|error| store_error(&error))?;
    read(files, root, security)?.ok_or_else(invalid)?;
    Ok(())
}
pub(super) fn restore(
    files: &dyn se_store::StateFiles,
    root: &Path,
    security: &auth::Security,
) -> Result<()> {
    if let Some((journal, _)) = read(files, root, security)? {
        for entry in journal.pending {
            let grant = security.store.grant(&entry.grant)?;
            security.fence(&grant)?.revoke()?;
        }
    }
    Ok(())
}
impl Control {
    /// Caller holds configure through publication, FULL and confirmed retirement.
    pub(super) async fn pending_revoke(
        &self,
        router: &crate::HostedRouter,
        entry: Pending,
        resolved: bool,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<()> {
        let files = self.files.clone();
        let root = router.execution.state_directory.clone();
        let security = self.security.clone();
        router
            .execution
            .blocking
            .run_owned(deadline, move || {
                let grant = security.store.grant(&entry.grant)?;
                let resolved = resolved || grant.state == se_store::remote::GrantState::Revoked;
                let fence = if resolved {
                    None
                } else {
                    Some(security.fence(&grant)?)
                };
                let prior = read(&*files, &root, &security)?;
                let expected = prior.as_ref().map(|(_, hash)| *hash);
                let mut journal = prior
                    .map(|(journal, _)| journal)
                    .unwrap_or_else(|| Journal {
                        schema: 1,
                        host: security.host(),
                        owner: security.store.owner.clone(),
                        store: security.store.info.id.clone(),
                        incarnation: security.store.info.incarnation,
                        pending: Vec::new(),
                    });
                if let Some(index) = journal
                    .pending
                    .iter()
                    .position(|saved| saved.grant == entry.grant)
                {
                    // The record retains the first uncertain key as a recovery
                    // hint. A new explicit Owner revoke may resolve authority;
                    // only its actual FULL receipt retires this grant's fence.
                    if resolved {
                        journal.pending.remove(index);
                    } else {
                        if let Some(fence) = &fence {
                            fence.revoke()?;
                        }
                        return Ok(());
                    }
                } else if resolved {
                    return Ok(());
                } else {
                    if journal.pending.len() == MAX_PENDING_REVOKES {
                        return Err(invalid());
                    }
                    // Refuse nonexistent grants before publishing a recovery obligation.
                    let grant = security.store.grant(&entry.grant)?;
                    if grant.state == se_store::remote::GrantState::Active
                        && grant.authority_revision.value.get() != entry.authority_revision
                    {
                        return Err(invalid());
                    }
                    journal.pending.push(entry);
                }
                let bytes = serde_json::to_vec(&journal).map_err(|_| invalid())?;
                if bytes.len() > MAX_BYTES {
                    return Err(invalid());
                }
                files
                    .replace_owned(&root.join("remote-revocations.json"), expected, &bytes)
                    .map_err(|error| store_error(&error))?;
                // This worker retains the fence even if its async caller is
                // cancelled immediately after the durable intent publication.
                if let Some(fence) = fence {
                    fence.revoke()?;
                }
                let actual = read(&*files, &root, &security)?.ok_or_else(invalid)?.0;
                if actual.pending != journal.pending {
                    return Err(invalid());
                }
                Ok(())
            })
            .await
    }
}
