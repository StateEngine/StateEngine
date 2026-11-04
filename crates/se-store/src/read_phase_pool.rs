//! Bounded idle connections; transactions and authority never survive a phase.
use crate::{error::*, *};
use rusqlite::Connection;
use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

/// Native adapter custody of one database file, independent of its SQL header.
/// Validate both the retained file and its current name without following links.
/// Only the trusted host supplies this port; requests cannot supply a validator.
pub trait ReadConnectionIdentity: Send + Sync {
    fn validate(&self, path: &Path) -> StoreResult<()>;
}
type OpenIdentity = fn(&Path) -> StoreResult<Box<dyn ReadConnectionIdentity>>;

/// A host-owned cache of idle connections bounded by the reader's shared slots.
/// Each checkout starts a new transaction and validates its header. Callers must
/// reread generation and credentials on that transaction before admitting work.
/// Ordinary readers and CLI phases keep their physical-close behavior.
#[derive(Clone)]
pub struct ReadPhasePool(Arc<Pool>);
struct Pool {
    reader: SqliteReader,
    state: Mutex<State>,
}
struct State {
    closed: bool,
    // Close SQLite before releasing native file custody.
    idle: Vec<Connection>,
    identity: Option<Arc<dyn ReadConnectionIdentity>>,
}
pub(crate) struct Recycle {
    pool: ReadPhasePool,
    identity: Arc<dyn ReadConnectionIdentity>,
}
impl SqliteReader {
    /// Construct a host-owned idle cache sharing this reader's capacity budget.
    /// Bind native database identity once here and retain it until close, even
    /// when no idle connections remain after a refused checkout.
    pub fn phase_pool(&self, open_identity: OpenIdentity) -> StoreResult<ReadPhasePool> {
        let identity = Arc::from(open_identity(&self.path)?);
        Ok(ReadPhasePool(Arc::new(Pool {
            reader: self.clone(),
            state: Mutex::new(State {
                closed: false,
                idle: Vec::new(),
                identity: Some(identity),
            }),
        })))
    }
}
impl ReadPhasePool {
    fn state(&self) -> StoreResult<MutexGuard<'_, State>> {
        self.0.state.lock().map_err(|_| {
            fail(
                StoreErrorCode::Unreadable,
                "idle read connection custody lock is poisoned",
            )
        })
    }
    /// Native identity, fresh BEGIN and header validation occur on every checkout.
    /// The returned phase is synchronous and cannot cross an external await.
    pub fn read_phase(&self) -> StoreResult<ReadPhase> {
        let reader = &self.0.reader;
        let slot = reader.slots.acquire()?;
        let (idle, identity) = {
            let mut state = self.state()?;
            if state.closed {
                return Err(fail(
                    StoreErrorCode::NotReady,
                    "host read connection pool is closed",
                ));
            }
            let identity = state.identity.clone().ok_or_else(|| {
                fail(
                    StoreErrorCode::Unreadable,
                    "open read pool lost its database identity",
                )
            })?;
            (state.idle.pop(), identity)
        };
        identity.validate(&reader.path)?;
        let db = match idle {
            Some(db) => db,
            None => reader.connect()?,
        };
        identity.validate(&reader.path)?;
        let mut phase = reader.read_phase_on(slot, db)?;
        // Recheck after SQLite established its fresh snapshot as well.
        identity.validate(&reader.path)?;
        phase.recycle = Some(Recycle {
            pool: self.clone(),
            identity,
        });
        Ok(phase)
    }
    /// Seal checkout and close every idle handle before releasing host custody.
    /// Failed SQLite closes remain retained for a subsequent close attempt.
    /// The host first fences admission and joins all outstanding phase jobs.
    pub fn close(&self) -> StoreResult<()> {
        self.state()?.closed = true;
        loop {
            let db = {
                let mut state = self.state()?;
                match state.idle.pop() {
                    Some(db) => db,
                    None => {
                        state.identity = None;
                        return Ok(());
                    }
                }
            };
            self.close_connection(db)?;
        }
    }
    fn close_connection(&self, db: Connection) -> StoreResult<()> {
        match db.close() {
            Ok(()) => Ok(()),
            Err((db, error)) => {
                self.state()?.idle.push(db);
                Err(context(
                    sql(error),
                    &self.0.reader.path,
                    StoreIoStage::ReadSnapshot,
                ))
            }
        }
    }
}
impl Recycle {
    pub(crate) fn release(self, db: Connection) -> StoreResult<()> {
        self.identity.validate(&self.pool.0.reader.path)?;
        let mut state = self.pool.state()?;
        if !state.closed && state.idle.len() < self.pool.0.reader.slots.capacity() {
            state.idle.push(db);
            return Ok(());
        }
        drop(state);
        self.pool.close_connection(db)
    }
}
