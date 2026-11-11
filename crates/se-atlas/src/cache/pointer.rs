//! Atomic small-pointer discovery; open SQLite epochs are never replaced.
use super::{connection::*, *};
use crate::errors::cache_error;
use std::time::Instant;
pub const POINTER_MAX_BYTES: usize = 1024;
pub fn decode(bytes: &[u8], scope: &Scope) -> AtlasResult<CachePointer> {
    if bytes.len() > POINTER_MAX_BYTES {
        return Err(cache_error("current.json exceeds 1024 bytes"));
    }
    let pointer: CachePointer = serde_json::from_slice(bytes).map_err(cache_error)?;
    // A legacy pointer supplies only the CAS identity for an owned rebuild.
    // Opening its database still requires the current schema.
    if ![3, schema::SCHEMA_VERSION].contains(&pointer.schema)
        || pointer.project != scope.registration.project
        || pointer.root != scope.registration.root
    {
        return Err(cache_error(
            "current.json has a foreign schema/project/root",
        ));
    }
    Ok(pointer)
}
pub struct DiscoveredEpoch<'a> {
    pub connection: CacheConnection<'a>,
    pub epoch_retired: bool,
}
pub fn open_current<'a>(
    files: &'a dyn CacheFiles,
    scope: &Scope,
    role: ConnectionRole,
    profile: &SqlProfile,
    deadline: Instant,
) -> AtlasResult<Option<DiscoveredEpoch<'a>>> {
    open_epoch(files, scope, role, profile, None, deadline)
}
/// Reopen only the exact epoch whose integrity the native owner already checked.
/// A changed pointer requires fresh owner validation, never an unchecked write.
pub fn open_checked_writer<'a>(
    files: &'a dyn CacheFiles,
    scope: &Scope,
    profile: &SqlProfile,
    checked_epoch: &CacheEpoch,
    deadline: Instant,
) -> AtlasResult<Option<DiscoveredEpoch<'a>>> {
    open_epoch(
        files,
        scope,
        ConnectionRole::MaintenanceWriter,
        profile,
        Some(checked_epoch),
        deadline,
    )
}
fn open_epoch<'a>(
    files: &'a dyn CacheFiles,
    scope: &Scope,
    role: ConnectionRole,
    profile: &SqlProfile,
    checked_epoch: Option<&CacheEpoch>,
    deadline: Instant,
) -> AtlasResult<Option<DiscoveredEpoch<'a>>> {
    let Some(bytes) = files.read_pointer()? else {
        return Ok(None);
    };
    let pointer = decode(&bytes, scope)?;
    if checked_epoch.is_some_and(|epoch| epoch != &pointer.epoch) {
        return Err(cache_error(
            "cache epoch changed; owner must validate the new epoch before maintenance",
        ));
    }
    let identity = CacheIdentity {
        scope: scope.clone(),
        epoch: pointer.epoch,
    };
    let connection = CacheConnection::open(files, identity, role, profile, deadline)?
        .ok_or_else(|| cache_error("current.json names an absent epoch; preserve the pointer"))?;
    let after = files.read_pointer()?;
    if let Some(after) = &after {
        decode(after, scope)?;
    }
    let retired = after.as_deref() != Some(bytes.as_slice());
    // Old epoch handles remain valid for labelled RO results, but a retired
    // writer must never commit into the graph that new readers no longer see.
    if retired
        && matches!(
            role,
            ConnectionRole::HostWriter
                | ConnectionRole::MaintenanceWriter
                | ConnectionRole::ColdWriter
        )
    {
        return Err(cache_error(
            "epoch retired while opening writer; rediscover",
        ));
    }
    Ok(Some(DiscoveredEpoch {
        connection,
        epoch_retired: retired,
    }))
}
/// A09 owns writer lock, exact child reap, retirement capacity and old-writer
/// closure. This primitive requires its already validated candidate connection;
/// native compare/replace preserves a concurrent winner and witnesses readback.
pub fn publish(
    files: &dyn CacheFiles,
    candidate: &mut CacheConnection<'_>,
    expected: Option<&[u8]>,
    deadline: Instant,
) -> AtlasResult<CachePointer> {
    candidate.validate(deadline)?;
    let id = candidate.identity();
    if let Some(old) = expected {
        decode(old, &id.scope)?;
    }
    let pointer = CachePointer {
        schema: schema::SCHEMA_VERSION,
        project: id.scope.registration.project.clone(),
        root: id.scope.registration.root.clone(),
        epoch: id.epoch.clone(),
    };
    let bytes = serde_json::to_vec(&pointer).map_err(cache_error)?;
    if bytes.len() > POINTER_MAX_BYTES {
        return Err(cache_error("pointer exceeds its publication budget"));
    }
    files.replace_pointer(expected, &bytes)?;
    let actual = files
        .read_pointer()?
        .ok_or_else(|| cache_error("published pointer readback is absent"))?;
    if actual != bytes {
        return Err(cache_error(
            "published pointer readback differs; rediscover current epoch",
        ));
    }
    Ok(pointer)
}
