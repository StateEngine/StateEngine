//! The foreground query reader, kept open between queries. Opening it costs a
//! pin, two file validations and connection setup on every query otherwise.
//! It is the one process-wide reader connection, so it holds the reader slot;
//! another reader role that needs the slot closes it while it is idle.
use crate::cache::{
    CacheFiles,
    connection::{CacheConnection, ConnectionRole, Detached, SqlProfile},
    pointer,
};
use crate::errors::{AtlasResult, cache_error};
use crate::scope::Scope;
use std::{sync::Mutex, time::Instant};

struct Retained {
    scope: Scope,
    connection: Detached,
}

static RETAINED: Mutex<Option<Retained>> = Mutex::new(None);

impl Retained {
    /// Still the same registered root, and current.json still names its epoch.
    fn serves(&self, scope: &Scope, files: &dyn CacheFiles) -> AtlasResult<bool> {
        if self.scope.registration != scope.registration
            || self.scope.physical_root != scope.physical_root
        {
            return Ok(false);
        }
        let Some(bytes) = files.read_pointer()? else {
            return Ok(false);
        };
        Ok(pointer::decode(&bytes, scope)?.epoch == self.connection.identity().epoch)
    }
}

/// Run `read` on the query reader for `scope`, reusing the open one while it
/// serves this root's current epoch and otherwise opening it from `files`.
/// `read` also learns whether the epoch was replaced while it opened. The
/// reader is kept only after a successful read on a current epoch; an absent
/// pointer or epoch is `Ok(None)`.
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
    // A reader that no longer serves this root and epoch closes here, before
    // any replacement opens.
    let reused = match held.take() {
        Some(retained) if retained.serves(scope, files)? => Some(retained),
        _ => None,
    };
    let (mut connection, retired) = match reused {
        Some(retained) => (CacheConnection::attach(retained.connection, files), false),
        None => {
            let opened = pointer::open_current(
                files,
                scope,
                ConnectionRole::QueryReader,
                profile,
                deadline,
            )?;
            let Some(opened) = opened else {
                return Ok(None);
            };
            (opened.connection, opened.epoch_retired)
        }
    };
    let value = read(&mut connection, retired)?;
    if !retired {
        *held = Some(Retained {
            scope: scope.clone(),
            connection: connection.detach()?,
        });
    }
    Ok(Some(value))
}

/// Close the retained reader. The owner calls this before it adopts a new
/// epoch or closes a root, so no handle keeps an old epoch's files open:
/// Windows cannot delete or rename an open file.
pub fn release() {
    let mut held = RETAINED.lock().unwrap_or_else(|error| error.into_inner());
    held.take();
}

/// Another reader role needs the one reader slot: close the retained reader
/// unless a query is using it right now.
pub(crate) fn release_if_idle() {
    if let Ok(mut held) = RETAINED.try_lock() {
        held.take();
    }
}
