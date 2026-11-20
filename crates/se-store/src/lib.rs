//! SQLite authority and bounded direct/host writer paths.
#[cfg(all(test, any(target_os = "linux", windows)))]
extern crate self as se_store;
mod api;
mod apply;
mod assignment_batch;
pub mod atlas_resume;
mod backup;
mod backup_context;
pub mod channel;
mod checkpoint_task;
mod codec;
mod completion;
mod connection;
mod creator;
mod credential;
mod error;
mod event;
mod identity;
pub mod import;
mod inventory;
pub mod mail;
mod migration;
mod migration_plan;
mod model;
mod open;
mod owner_guard;
mod read;
mod read_phase;
mod read_phase_pool;
mod read_slots;
pub mod remote;
mod return_mail;
mod security_receipt;
mod sql_value;
mod staging;
mod transaction;
mod transcript;
mod writer;
/// The channel delayed-phone-status threshold in microseconds after the
/// Saved commit at which the status becomes due. Production keeps this
/// constant; only the in-process test hook opens a writer on a shorter one.
pub const CHANNEL_DELAY_US: i64 = 60_000_000;
pub use api::*;
pub use event::*;
pub use model::*;
pub use open::{SqliteDirect, SqliteFactory, SqliteHost, SqliteReader};
pub use read::SqliteSnapshot;
pub use read_phase::ReadPhase;
pub use read_phase_pool::{ReadConnectionIdentity, ReadPhasePool};
pub use se_store_contract::assignment;
pub use se_store_contract::values::*;
pub use transcript::*;
pub use writer::{SqliteClient, SqliteWriter};
