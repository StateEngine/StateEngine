mod create;
mod existing;
use crate::{connection, error::*, read::SqliteSnapshot, transaction::Engine, *};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use se_types::{Page, Read};
use std::{num::NonZeroU32, path::PathBuf, sync::Arc, time::Duration};
pub struct SqliteFactory;
#[derive(Clone)]
pub struct SqliteReader {
    pub(crate) path: PathBuf,
    pub(crate) timeout: Duration,
    pub(crate) slots: crate::read_slots::ReadSlots,
}
pub struct SqliteDirect {
    pub(crate) reader: SqliteReader,
    pub(crate) engine: Engine,
}
pub struct SqliteHost {
    pub(crate) reader: SqliteReader,
    pub(crate) engine: Engine,
    pub(crate) context: BackupContext,
    // Declared after engine so SQLite closes before custody is released.
    pub(crate) lease: Option<Arc<dyn RuntimeLease>>,
}
impl SqliteHost {
    fn maintenance(reader: SqliteReader, mut engine: Engine) -> StoreResult<Self> {
        let context = BackupContext::bound(
            &connection::info(&engine.db)?,
            engine.identity.generation,
            reader.path.clone(),
            reader.slots.clone(),
        );
        engine.backup = Some(context.clone());
        Ok(Self {
            reader,
            engine,
            context,
            lease: None,
        })
    }
}
impl SqliteReader {
    fn for_options(o: &StoreOptions) -> StoreResult<Self> {
        Self::with_slots(o, crate::read_slots::ReadSlots::default())
    }
    fn with_slots(o: &StoreOptions, slots: crate::read_slots::ReadSlots) -> StoreResult<Self> {
        if !o.state_directory.is_absolute() {
            return Err(fail(
                StoreErrorCode::LocationUnsafe,
                "state directory must be resolved and absolute",
            ));
        }
        Ok(Self {
            path: o.state_directory.join("state.db"),
            timeout: o.busy_timeout,
            slots,
        })
    }
    pub(crate) fn connect(&self) -> StoreResult<Connection> {
        connection::connect(&self.path, false, self.timeout)
    }
}
impl SqliteFactory {
    /// Open an existing read-only store with an immutable capacity of 2–8.
    /// All clones share this budget, including snapshots and private lookups.
    /// Opening a separate reader creates a separate budget; the ordinary
    /// StoreFactory::open_reader constructor continues to use two slots.
    pub fn open_reader_with_capacity(
        options: &StoreOptions,
        capacity: NonZeroU32,
    ) -> StoreResult<Read<SqliteReader>> {
        Self::existing_with_slots(options, crate::read_slots::ReadSlots::new(capacity)?)
    }
}
impl StoreFactory for SqliteFactory {
    type Reader = SqliteReader;
    type Direct = SqliteDirect;
    type Host = SqliteHost;
    fn open_reader(o: &StoreOptions) -> StoreResult<Read<Self::Reader>> {
        Self::existing(o)
    }
    fn open_direct(o: &StoreOptions, lease: &dyn RuntimeLease) -> StoreResult<Read<Self::Direct>> {
        match Self::existing_protected(o, lease)? {
            Read::Present { value: reader } => {
                let db = connection::connect(&reader.path, true, o.busy_timeout)?;
                let info = connection::info_at(&db, &reader.path)?;
                let identity = connection::validate_lease(&info, lease, LeaseMode::DirectClient)?;
                let reader_path = reader.path.clone();
                Ok(Read::Present {
                    value: SqliteDirect {
                        reader,
                        engine: Engine {
                            db,
                            path: reader_path,
                            identity,
                            poisoned: false,
                            pending: Vec::new(),
                            maintenance: None,
                            backup: None,
                        },
                    },
                })
            }
            Read::Absent { checked } => Ok(Read::Absent { checked }),
            Read::Unreadable {
                source,
                reason,
                error,
            } => Ok(Read::Unreadable {
                source,
                reason,
                error,
            }),
            Read::Unknown { what } => Ok(Read::Unknown { what }),
        }
    }
    fn open_host(o: &StoreOptions, lease: &dyn RuntimeLease) -> StoreResult<Read<Self::Host>> {
        match Self::existing_protected(o, lease)? {
            Read::Present { value: reader } => {
                let db = connection::connect(&reader.path, true, o.busy_timeout)?;
                let info = connection::info_at(&db, &reader.path)?;
                let identity = connection::validate_lease(&info, lease, LeaseMode::Host)?;
                let context = BackupContext::bound(
                    &info,
                    identity.generation,
                    reader.path.clone(),
                    reader.slots.clone(),
                );
                crate::migration::upgrade(&db, o, lease, context)?;
                let reader_path = reader.path.clone();
                Ok(Read::Present {
                    value: SqliteHost::maintenance(
                        reader,
                        Engine {
                            db,
                            path: reader_path,
                            identity,
                            poisoned: false,
                            pending: Vec::new(),
                            maintenance: None,
                            backup: None,
                        },
                    )?,
                })
            }
            Read::Absent { checked } => Ok(Read::Absent { checked }),
            Read::Unreadable {
                source,
                reason,
                error,
            } => Ok(Read::Unreadable {
                source,
                reason,
                error,
            }),
            Read::Unknown { what } => Ok(Read::Unknown { what }),
        }
    }
    fn create_direct(
        o: &StoreOptions,
        lease: &dyn RuntimeLease,
        id: StoreId,
    ) -> StoreResult<Self::Direct> {
        let (reader, engine) = Self::create_engine(o, lease, id, LeaseMode::DirectClient)?;
        Ok(SqliteDirect { reader, engine })
    }
    fn create(o: &StoreOptions, lease: &dyn RuntimeLease, id: StoreId) -> StoreResult<Self::Host> {
        let (reader, engine) = Self::create_engine(o, lease, id, LeaseMode::Host)?;
        SqliteHost::maintenance(reader, engine)
    }
    fn backup(
        options: &StoreOptions,
        lease: Arc<dyn RuntimeLease>,
        context: BackupContext,
        deadline: Duration,
    ) -> StoreResult<BackupReport> {
        crate::backup::run(options, &*lease, context, deadline)
    }
    fn erasure_plan(
        _: &StoreOptions,
        _: Vec<EraseTarget>,
        _: &dyn RuntimeLease,
    ) -> StoreResult<ErasurePlan> {
        later("erasure planning")
    }
    fn inspect_backups(
        _: &StoreOptions,
        _: ReadBudget,
    ) -> StoreResult<Page<Read<BackupGeneration>>> {
        later("backup inventory")
    }
    fn recovery_receipt(
        _: &StoreOptions,
        _: &RequestIdentity,
        _: &Admission,
    ) -> StoreResult<Read<RestoreReceipt>> {
        later("restore receipt")
    }
    fn restore_backup(
        _: &StoreOptions,
        _: BackupGeneration,
        _: &RequestIdentity,
        _: StoreId,
        _: &Admission,
        _: &dyn RuntimeLease,
    ) -> StoreResult<RestoreOutcome<Self::Host>> {
        later("backup restore")
    }
}
impl ReadStore for SqliteReader {
    type Snapshot = SqliteSnapshot;
    fn info(&self) -> StoreResult<StoreInfo> {
        connection::info_at(&self.connect()?, &self.path)
    }
    fn snapshot(&self, scope: ReadScope) -> StoreResult<Self::Snapshot> {
        SqliteSnapshot::open(self, scope)
    }
    fn runtime_owner(&self) -> StoreResult<Read<RuntimeOwnerHead>> {
        let phase = self.read_phase()?;
        let result = phase.runtime_owner();
        phase.finish(result)
    }
    fn owner_guard(
        &self,
        files: &dyn StateFiles,
        budget: ReadBudget,
    ) -> StoreResult<OwnerGuardInventory> {
        crate::owner_guard::read(self, files, budget)
    }
    fn credential(&self, hash: [u8; 32]) -> StoreResult<Read<CredentialRecord>> {
        crate::credential::read(self, hash)
    }
    fn inspect_backups(&self, b: ReadBudget) -> StoreResult<Page<Read<BackupGeneration>>> {
        SqliteFactory::inspect_backups(
            &StoreOptions {
                state_directory: self
                    .path
                    .parent()
                    .ok_or_else(|| invalid("state path parent"))?
                    .to_path_buf(),
                busy_timeout: self.timeout,
            },
            b,
        )
    }
}
macro_rules! delegate_reads {
    ($t:ty) => {
        impl ReadStore for $t {
            type Snapshot = SqliteSnapshot;
            fn info(&self) -> StoreResult<StoreInfo> {
                self.reader.info()
            }
            fn snapshot(&self, s: ReadScope) -> StoreResult<Self::Snapshot> {
                self.reader.snapshot(s)
            }
            fn runtime_owner(&self) -> StoreResult<Read<RuntimeOwnerHead>> {
                self.reader.runtime_owner()
            }
            fn owner_guard(
                &self,
                files: &dyn StateFiles,
                budget: ReadBudget,
            ) -> StoreResult<OwnerGuardInventory> {
                self.reader.owner_guard(files, budget)
            }
            fn credential(&self, h: [u8; 32]) -> StoreResult<Read<CredentialRecord>> {
                self.reader.credential(h)
            }
            fn inspect_backups(&self, b: ReadBudget) -> StoreResult<Page<Read<BackupGeneration>>> {
                self.reader.inspect_backups(b)
            }
        }
    };
}
delegate_reads!(SqliteDirect);
delegate_reads!(SqliteHost);
macro_rules! staging {
    ($t:ty) => {
        impl TextStaging for $t {
            fn stage_text(
                &self,
                source: &mut dyn std::io::Read,
                maximum: u64,
                lease: &dyn RuntimeLease,
            ) -> StoreResult<StagedText> {
                crate::staging::stage(
                    &self.reader.path,
                    &connection::info(&self.engine.db)?,
                    &self.engine.identity,
                    source,
                    maximum,
                    lease,
                )
            }
        }
    };
}
staging!(SqliteDirect);
staging!(SqliteHost);
impl DirectStore for SqliteDirect {
    fn append(
        &mut self,
        batch: AtomicBatch,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<CommitReceipt> {
        self.engine
            .reopen(&self.reader.path, self.reader.timeout, lease)?;
        let identity = connection::validate_lease(
            &connection::info(&self.engine.db)?,
            lease,
            LeaseMode::DirectClient,
        )?;
        if identity.generation != self.engine.identity.generation {
            return Err(fail(
                StoreErrorCode::GenerationChanged,
                "direct generation changed",
            ));
        }
        let (mut results, _) = self.engine.group(vec![batch], false)?;
        results
            .pop()
            .ok_or_else(|| invalid("direct commit returned no operation"))?
    }
    fn close(self) -> StoreResult<()> {
        self.engine.require_resolved()?;
        self.engine.db.close().map_err(|(_, e)| sql(e))
    }
}
impl HostStore for SqliteHost {
    type Writer = crate::writer::SqliteWriter;
    fn runtime_ownership_fact(&self, id: se_types::EventId) -> StoreResult<Read<StoredEvent>> {
        let s = vec![0];
        let k = crate::identity::key(&self.engine.db, "event", id.as_str(), &s, false)?;
        let seq:Option<i64>=self.engine.db.query_row("SELECT seq FROM events WHERE event_id=? AND kind IN ('runtime.owner','runtime.handover') AND project_id IS NULL",[k],|r|crate::sql_value::value(r,0)).optional().map_err(sql)?;
        match seq {
            None => Ok(Read::Absent {
                checked: "private runtime event ID absent".into(),
            }),
            Some(s) => Ok(Read::Present {
                value: crate::read::load_event(
                    &self.engine.db,
                    s,
                    &connection::info(&self.engine.db)?,
                )?,
            }),
        }
    }
    fn backup_context(&self) -> BackupContext {
        self.context.clone()
    }
    fn start_writer(
        self,
        options: WriterOptions,
        lease: Arc<dyn RuntimeLease>,
    ) -> StoreResult<Self::Writer> {
        crate::writer::start(self, options, lease)
    }
    fn record_runtime_ownership(
        &mut self,
        b: AtomicBatch,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<CommitReceipt> {
        self.engine
            .reopen(&self.reader.path, self.reader.timeout, lease)?;
        connection::validate_lease(&connection::info(&self.engine.db)?, lease, LeaseMode::Host)?;
        if b.events.len() != 1
            || !matches!(b.events[0].body, EventBody::RuntimeOwnerEstablished { .. })
        {
            return Err(invalid(
                "exclusive ownership requires one runtime.owner fact",
            ));
        }
        let (mut r, _) = self.engine.group(vec![b], true)?;
        r.pop()
            .ok_or_else(|| invalid("ownership receipt missing"))?
    }
    fn record_first_binding(
        &mut self,
        binding: FirstBinding,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<FirstBindingReceipt> {
        self.engine
            .reopen(&self.reader.path, self.reader.timeout, lease)?;
        connection::validate_lease(&connection::info(&self.engine.db)?, lease, LeaseMode::Host)?;
        self.engine.first_binding(binding)
    }
    fn checkpoint(
        &mut self,
        mode: CheckpointMode,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<CheckpointReport> {
        connection::validate_lease(&connection::info(&self.engine.db)?, lease, LeaseMode::Host)?;
        let report = self
            .engine
            .db
            .query_row(
                match mode {
                    CheckpointMode::Passive => "PRAGMA wal_checkpoint(PASSIVE)",
                    CheckpointMode::Truncate => "PRAGMA wal_checkpoint(TRUNCATE)",
                },
                [],
                |r| {
                    Ok(CheckpointReport {
                        busy: crate::sql_value::value::<i64>(r, 0)? != 0,
                        wal_frames: crate::sql_value::value(r, 1)?,
                        checkpointed_frames: crate::sql_value::value(r, 2)?,
                    })
                },
            )
            .map_err(sql);
        self.engine.maintenance = match &report {
            Ok(value) if !value.busy && value.checkpointed_frames >= value.wal_frames => None,
            Ok(_) => Some(fail(StoreErrorCode::Busy, "checkpoint has pending frames")),
            Err(error) => Some(error.clone()),
        };
        report
    }
    fn erase(
        &mut self,
        _: ErasurePlan,
        _: ErasureApproval,
        _: &dyn RuntimeLease,
    ) -> StoreResult<ErasureReport> {
        later("body erasure")
    }
    fn close_clean(
        mut self,
        lease: &dyn RuntimeLease,
        deadline: Duration,
    ) -> StoreResult<BackupReport> {
        let start = std::time::Instant::now();
        self.engine.require_resolved()?;
        self.engine
            .reopen(&self.reader.path, self.reader.timeout, lease)?;
        connection::validate_lease(&connection::info(&self.engine.db)?, lease, LeaseMode::Host)?;
        if deadline.is_zero() {
            return Err(fail(
                StoreErrorCode::BackupFailed,
                "clean-close deadline is zero",
            ));
        }
        let report = crate::backup::run(
            &StoreOptions {
                state_directory: self
                    .reader
                    .path
                    .parent()
                    .ok_or_else(|| invalid("state path parent"))?
                    .to_path_buf(),
                busy_timeout: self.reader.timeout,
            },
            lease,
            self.context.clone(),
            deadline,
        )?;
        if start.elapsed() >= deadline {
            return Err(fail(
                StoreErrorCode::BackupFailed,
                "clean-close deadline expired after backup publication",
            ));
        }
        self.engine
            .db
            .busy_timeout(deadline.saturating_sub(start.elapsed()))
            .map_err(sql)?;
        let checkpoint = self.checkpoint(CheckpointMode::Truncate, lease)?;
        if checkpoint.busy {
            return Err(fail(
                StoreErrorCode::Busy,
                "clean-close checkpoint is pinned by another reader",
            ));
        }
        self.engine.db.close().map_err(|(_, error)| sql(error))?;
        if start.elapsed() >= deadline {
            return Err(fail(
                StoreErrorCode::BackupFailed,
                "clean-close deadline expired during checkpoint/connection close",
            ));
        }
        Ok(report)
    }
}
