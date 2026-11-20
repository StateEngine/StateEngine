//! The foreground query reader, kept open between queries so each query skips the
//! pin, validations and connection setup. It is the one process-wide reader, so it
//! holds the reader slot; another reader role that needs the slot closes it if idle.
use crate::cache::connection::{CacheConnection, ConnectionRole, Detached, SqlProfile};
use crate::cache::{CacheFiles, pointer};
use crate::errors::{AtlasResult, cache_error};
use crate::scope::Scope;
use std::{sync::Mutex, time::Instant};

static RETAINED: Mutex<Option<(Scope, Detached)>> = Mutex::new(None);

/// Run `read` on the query reader for `scope`: the kept one while current.json still
/// names its epoch, otherwise one opened from `files`. `read` learns whether the epoch
/// was replaced while opening; only a successful read on a current epoch is kept.
pub fn with_retained<T>(
    scope: &Scope,
    profile: &SqlProfile,
    deadline: Instant,
    files: &dyn CacheFiles,
    read: impl FnOnce(&mut CacheConnection<'_>, bool) -> AtlasResult<T>,
) -> AtlasResult<Option<T>> {
    let mut held = RETAINED
        .lock()
        .map_err(|_| cache_error("Atlas retained reader lock poisoned"))?;
    let current = match files.read_pointer()? {
        Some(bytes) => Some(pointer::decode(&bytes, scope)?.epoch),
        None => None,
    };
    // A reader for another root or epoch closes here, before any replacement opens.
    let (mut connection, retired) = match held.take() {
        Some((kept, reader))
            if kept.registration == scope.registration
                && kept.physical_root == scope.physical_root
                && current.as_ref() == Some(&reader.identity().epoch) =>
        {
            (CacheConnection::attach(reader, files), false)
        }
        stale => {
            drop(stale); // It holds the one reader slot the replacement needs.
            let role = ConnectionRole::QueryReader;
            let Some(opened) = pointer::open_current(files, scope, role, profile, deadline)? else {
                return Ok(None);
            };
            (opened.connection, opened.epoch_retired)
        }
    };
    let value = read(&mut connection, retired)?;
    if !retired {
        *held = Some((scope.clone(), connection.detach()?));
    }
    Ok(Some(value))
}

/// Close the kept reader. The owner calls this before adopting a new epoch or closing
/// a root: Windows cannot delete or rename an open file.
pub fn release() {
    RETAINED
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take();
}

/// Another reader role needs the slot: close the kept reader unless a query holds it.
pub(crate) fn release_if_idle() {
    if let Ok(mut held) = RETAINED.try_lock() {
        held.take();
    }
}
