//! A connection handle's lifetime: closing inside the arena, and detaching a query
//! reader from its cache files to keep it open between queries.
use super::*;
/// The SQLite handle. A role that opened inside the arena closes inside it if it is
/// free within the latest caller budget (else one try): `closing` is taken in Drop and
/// released after `connection` closes. Missing it is safe: the host sets
/// NO_CKPT_ON_CLOSE on these roles (native_sql::retain_wal), so no close checkpoints.
pub(super) struct Db {
    pub(super) connection: Connection,
    arena_reader: Option<bool>,
    pub(super) until: Instant,
    closing: Option<Reservation>,
}
impl Db {
    pub(super) fn new(connection: Connection, role: ConnectionRole, until: Instant) -> Self {
        let arena_reader = role
            .opens_in_arena()
            .then_some(role == ConnectionRole::QueryReader);
        Self {
            connection,
            arena_reader,
            until,
            closing: None,
        }
    }
}
impl Drop for Db {
    fn drop(&mut self) {
        if let Some(reader) = self.arena_reader {
            let free = Reservation::acquire(reader, self.until).ok();
            self.closing = free.or_else(|| Reservation::try_now(reader));
        }
    }
}
impl Deref for Db {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.connection
    }
}
impl std::ops::DerefMut for Db {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }
}
/// A cold writer releases its native accounting guards before SQLite closes, so this
/// is the connection's first field.
pub(super) struct ColdRelease<'a>(pub(super) &'a dyn CacheFiles);
impl Drop for ColdRelease<'_> {
    fn drop(&mut self) {
        self.0.release_cold_observations();
    }
}
/// A query reader's open connection without its cache files, kept between queries.
pub struct Detached(Db, DatabasePin, CacheIdentity, slot::Slot);
impl Detached {
    pub fn identity(&self) -> &CacheIdentity {
        &self.2
    }
}
impl<'a> CacheConnection<'a> {
    /// Keep a query reader open without its cache files.
    pub fn detach(self) -> AtlasResult<Detached> {
        if self.role != ConnectionRole::QueryReader {
            return Err(cache_error(
                "only a query reader stays open between queries",
            ));
        }
        let CacheConnection {
            db,
            pin,
            identity,
            _slot,
            ..
        } = self;
        Ok(Detached(db, pin, identity, _slot))
    }
    /// Reattach a kept query reader whose epoch the caller has just confirmed is
    /// still current: its reads skip revalidating the pinned file until it changes.
    pub fn attach(Detached(db, pin, identity, _slot): Detached, files: &'a dyn CacheFiles) -> Self {
        let (role, current) = (ConnectionRole::QueryReader, true);
        Self {
            _cold: None,
            db,
            files,
            pin,
            identity,
            role,
            _slot,
            current,
        }
    }
}
