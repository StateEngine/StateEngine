//! The explicit host-custody branch: a process the host owns for itself.
//!
//! One login's shared daemon serves agents rather than belonging to one, so it
//! has no row in the principal registry, which stays limited to humans and
//! agents. Its immutable process fact instead carries a tagged host owner: the
//! exact project (the row's own), the exact scope it serves, and the host epoch
//! that originated it. The originating epoch never changes; a successor host
//! reconciles custody without rewriting the origin. A missing or inconsistent
//! binding refuses as unreadable custody, never as an unowned process.
use super::*;
use crate::process_custody::{decoded, origin, same_epoch, unreadable};

/// Bind a first host registration: the writer's own established epoch becomes
/// the record's fixed origin, and the fact names the exact scope it serves.
pub(super) fn bind(
    c: &Connection,
    h: &EventHeader,
    identity: &ProcessIdentityRecord,
    lease: &LeaseIdentity,
) -> StoreResult<(Vec<u8>, String)> {
    let Scope::Project(_) = &h.scope else {
        return Err(unreadable(
            "a host-owned process is recorded in the project whose scope it serves",
        ));
    };
    if identity.session.is_some() {
        return Err(unreadable("a host-owned process serves no single session"));
    }
    let checkpoint = decoded(&identity.custody, &identity.record)?;
    let (owner, generation) = origin(&checkpoint)?;
    let established: Option<(u64, String)> = c
        .query_row(
            "SELECT owner_generation,owner_epoch FROM runtime_owner WHERE singleton=1",
            [],
            |row| Ok((crate::sql_value::value(row, 0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    let Some((writer_generation, epoch)) = established else {
        return Err(unreadable("the current runtime owner is absent"));
    };
    if writer_generation != lease.generation {
        return Err(unreadable(
            "the current runtime owner differs from the writer lease",
        ));
    }
    let epoch: se_types::HostEpoch = serde_json::from_str(&epoch)
        .map_err(|e| unreadable(&format!("runtime owner epoch is not valid: {e}")))?;
    if !same_epoch(&owner, generation, &epoch) {
        return Err(unreadable(
            "checkpoint custody names a different host than the writer's epoch",
        ));
    }
    // The scope key is the scope row's own: this lifecycle, registry-wide.
    let scope = key(c, "lifecycle", identity.record.as_str(), &[0], false)?;
    Ok((scope, serde_json::to_string(&epoch).map_err(invalid)?))
}

/// A later event keeps the recorded binding: same scope, same originating
/// epoch, decoded again through the process codec from the new custody bytes.
/// The successor's own epoch appears only in those bytes' native observation,
/// never in the fixed origin.
pub(super) fn consistent(
    c: &Connection,
    old_seq: i64,
    identity: &ProcessIdentityRecord,
) -> StoreResult<String> {
    let (old_scope, old_epoch): (Option<Vec<u8>>, Option<String>) = c
        .query_row(
            "SELECT host_scope,host_epoch FROM process_data WHERE event_seq=?",
            [old_seq],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(sql)?;
    let (Some(old_scope), Some(old_epoch)) = (old_scope, old_epoch) else {
        return Err(unreadable(
            "the recorded process has no host binding to reconcile",
        ));
    };
    if identity.session.is_some() {
        return Err(unreadable("a host-owned process serves no single session"));
    }
    let recorded: se_types::HostEpoch = serde_json::from_str(&old_epoch)
        .map_err(|e| unreadable(&format!("recorded host epoch is not valid: {e}")))?;
    let checkpoint = decoded(&identity.custody, &identity.record)?;
    let (owner, generation) = origin(&checkpoint)?;
    if !same_epoch(&owner, generation, &recorded) {
        return Err(unreadable(
            "checkpoint custody names a different originating host epoch",
        ));
    }
    let scope = key(c, "lifecycle", identity.record.as_str(), &[0], false)?;
    if scope != old_scope {
        return Err(unreadable("the host binding names a different scope"));
    }
    Ok(old_epoch)
}
