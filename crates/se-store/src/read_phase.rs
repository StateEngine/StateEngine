//! One read pin owned by a finite synchronous host phase.
use crate::{connection, error::*, open::SqliteReader, *};
use rusqlite::{Connection, OptionalExtension};
use se_types::Read;
use std::{marker::PhantomData, path::PathBuf, rc::Rc};

/// A fresh SQLite read transaction and one shared reader-capacity reservation.
/// Query generation and authority again on every new phase. A finite auth
/// phase may include protected file reads and bounded native process-tree
/// observations on the same synchronous job; these reads retain the pin.
/// Close before a network wait, commit or externally mutating effect, or consume
/// this phase into its scoped snapshot and close that snapshot before leaving
/// the synchronous job. The pin covers these bounded native reads as well as SQL.
///
/// A phase cannot escape a blocking job through its `Send` result:
/// ```compile_fail
/// fn blocking_result<T: Send>() {}
/// blocking_result::<se_store::ReadPhase>();
/// ```
#[must_use = "close the read phase or consume it into a scoped snapshot"]
pub struct ReadPhase {
    pub(crate) db: Connection,
    pub(crate) info: StoreInfo,
    pub(crate) path: PathBuf,
    pub(crate) slot: crate::read_slots::ReadSlot,
    pub(crate) local: PhantomData<Rc<()>>,
}

impl SqliteReader {
    /// Begin one fresh read pin for a finite synchronous phase. Clones share
    /// the same capacity budget with ordinary snapshots and private lookups.
    pub fn read_phase(&self) -> StoreResult<ReadPhase> {
        let slot = self.slots.acquire()?;
        let db = self.connect()?;
        connection::begin_snapshot(&db, &self.path)?;
        let info = connection::info_at(&db, &self.path)?;
        Ok(ReadPhase {
            db,
            info,
            path: self.path.clone(),
            slot,
            local: PhantomData,
        })
    }
}

impl ReadPhase {
    /// Read the current phase's generation fact; no authority is cached for a
    /// later pin or request.
    pub fn runtime_owner(&self) -> StoreResult<Read<RuntimeOwnerHead>> {
        let row: Option<(String, u64, u64, i64)> = self.db.query_row(
            "SELECT owner_epoch,owner_generation,revision,last_seq FROM runtime_owner WHERE singleton=1",
            [], |r| Ok((crate::sql_value::value(r, 0)?, crate::sql_value::value(r, 1)?, crate::sql_value::value(r, 2)?, crate::sql_value::value(r, 3)?)),
        ).optional().map_err(sql)?;
        match row {
            None => Ok(Read::Absent {
                checked: "runtime_owner singleton absent".into(),
            }),
            Some((epoch, generation, revision, seq)) => Ok(Read::Present {
                value: RuntimeOwnerHead {
                    epoch: serde_json::from_str(&epoch).map_err(invalid)?,
                    generation: se_types::Generation::new(generation).map_err(invalid)?,
                    revision: crate::codec::revision(revision)?,
                    event: crate::read::load_event(&self.db, seq, &self.info)?
                        .header
                        .event,
                    handover: None,
                },
            }),
        }
    }

    /// Read a complete protected owner inventory on this same pin. Native
    /// file custody and the supplied finite inventory budget are still checked.
    pub fn owner_guard(
        &self,
        files: &dyn StateFiles,
        budget: ReadBudget,
    ) -> StoreResult<OwnerGuardInventory> {
        crate::owner_guard::read_at(&self.db, &self.path, files, budget)
    }

    /// Re-read the presented credential on this pin, retaining the ordinary
    /// active-session and expiry checks in the host admission layer.
    pub fn credential(&self, hash: [u8; 32]) -> StoreResult<Read<CredentialRecord>> {
        crate::credential::read_at(&self.db, &self.info, hash)
    }

    /// Transfer this exact pin and its reservation to the admitted snapshot.
    /// This consumes the pre-admission phase; it cannot be reused afterward.
    pub fn into_snapshot(self, scope: ReadScope) -> StoreResult<SqliteSnapshot> {
        SqliteSnapshot::from_phase(self, scope)
    }

    /// End the read pin and close its connection before returning its capacity.
    /// Early errors and unwinding also drop the connection and its transaction.
    pub fn close(self) -> StoreResult<()> {
        self.db
            .execute_batch("ROLLBACK")
            .map_err(|e| context(sql(e), &self.path, StoreIoStage::ReadSnapshot))?;
        self.db
            .close()
            .map_err(|(_, e)| context(sql(e), &self.path, StoreIoStage::ReadSnapshot))
    }

    pub(crate) fn finish<T>(self, result: StoreResult<T>) -> StoreResult<T> {
        match (result, self.close()) {
            (result, Ok(())) => result,
            (Ok(_), Err(error)) => Err(error),
            (Err(mut original), Err(error)) => {
                original.cause = format!("{}; closing read phase: {error}", original.cause);
                Err(original)
            }
        }
    }
}
