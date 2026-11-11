//! One owner-only cache per registered physical root; no authoritative floor reads.
pub mod connection;
pub(crate) mod path_scope;
pub mod pointer;
pub mod prune;
pub(crate) mod reference_counts;
pub mod schema;
pub mod write;
use crate::{errors::AtlasResult, model::*, scope::Scope};
use std::path::PathBuf;
/// The native adapter retains the directory/root and file pins while SQLite is
/// open. SQLite's own NOFOLLOW flag also rejects a linked final database name.
/// This trusted port is never constructed from CLI/MCP destination arguments.
pub trait CacheFiles {
    /// Fresh-connection allocator setup before any SQL prepares. Native Atlas
    /// disables lookaside here; other adapters must include their actual SQLite
    /// defaults in their independent profile measurement. This hook supplies no
    /// admission claim and cannot change another connection's allocation policy.
    fn configure_connection(&self, _connection: &mut rusqlite::Connection) -> AtlasResult<()> {
        Ok(())
    }
    /// Native adapters may give short-lived maintenance and read connections
    /// explicit checkpoint ownership without changing cold-writer behavior.
    fn configure_connection_role(
        &self,
        connection: &mut rusqlite::Connection,
        _role: connection::ConnectionRole,
    ) -> AtlasResult<()> {
        self.configure_connection(connection)
    }
    /// At most 1024 bytes; native bounded read refuses an oversized pointer.
    fn read_pointer(&self) -> AtlasResult<Option<Vec<u8>>>;
    /// Compare old bytes/absence, atomic protected replacement, sync and external
    /// readback. A conflicting pointer preserves the winner and refuses.
    fn replace_pointer(&self, expected: Option<&[u8]>, bytes: &[u8]) -> AtlasResult<()>;
    /// Derive epochs/<validated epoch>/atlas.db under retained owner-only custody.
    /// None is confirmed absence. Links, foreign owners and unreadability refuse.
    fn pin_database(&self, epoch: &CacheEpoch) -> AtlasResult<Option<DatabasePin>>;
    /// Exclusively reserve a protected empty regular database, never replace one.
    fn reserve_database(&self, epoch: &CacheEpoch) -> AtlasResult<DatabasePin>;
    /// After a failed create and after SQLite closes: remove only this reserved,
    /// unpublished epoch and its owned sidecars, by retained identity. Refuse a
    /// current/published epoch or replacement. Witness absence; preserve unknowns.
    fn discard_unpublished(&self, pin: &DatabasePin) -> AtlasResult<()>;
    fn validate_database(&self, pin: &DatabasePin) -> AtlasResult<()>;
    fn wal_bytes(&self, pin: &DatabasePin) -> AtlasResult<u64>;
    /// Global/project usage includes all DB/WAL/SHM/staging/retired files. This
    /// reservation includes other writers and is held until commit/rollback.
    fn reserve_growth(&self, bytes: u64) -> AtlasResult<Box<dyn GrowthReservation + '_>>;
}
pub trait GrowthReservation {}
pub type DatabaseFileIdentity = ([u8; 16], [u8; 16]);
/// Metadata custody may use a retained handle or a no-open native observation.
/// Its drop must preserve every SQLite connection's process-wide file locks.
pub trait DatabaseFile {
    fn metadata(&self) -> std::io::Result<std::fs::Metadata>;
    fn identity(&self) -> std::io::Result<DatabaseFileIdentity>;
}

pub struct DatabasePin {
    pub file: Box<dyn DatabaseFile>,
    pub path: PathBuf,
}
#[derive(Clone, Debug)]
pub struct CacheIdentity {
    pub scope: Scope,
    pub epoch: CacheEpoch,
}
#[derive(Clone, Debug)]
pub struct CacheSeed {
    pub identity: CacheIdentity,
    pub extractor_version: String,
    pub ignore_digest: ContentHash,
    pub coverage: Coverage,
    pub state: IndexState,
}
