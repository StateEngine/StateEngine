use crate::{connection, error::*, read::SqliteSnapshot, transaction::Engine, *};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use se_types::{Page, Read};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};
pub struct SqliteFactory;
#[derive(Clone)]
pub struct SqliteReader {
    pub(crate) path: PathBuf,
    pub(crate) timeout: Duration,
    pub(crate) slots: Arc<AtomicUsize>,
}
pub struct SqliteDirect {
    pub(crate) reader: SqliteReader,
    pub(crate) engine: Engine,
}
pub struct SqliteHost {
    pub(crate) reader: SqliteReader,
    pub(crate) engine: Engine,
    pub(crate) context: BackupContext,
}
impl SqliteReader {
    fn for_options(o: &StoreOptions) -> StoreResult<Self> {
        if !o.state_directory.is_absolute() {
            return Err(fail(
                StoreErrorCode::LocationUnsafe,
                "state directory must be resolved and absolute",
            ));
        }
        Ok(Self {
            path: o.state_directory.join("state.db"),
            timeout: o.busy_timeout,
            slots: Arc::new(AtomicUsize::new(0)),
        })
    }
    fn connect(&self) -> StoreResult<Connection> {
        connection::connect(&self.path, false, self.timeout)
    }
}
impl SqliteFactory {
    fn existing(o: &StoreOptions) -> StoreResult<Read<SqliteReader>> {
        let reader = SqliteReader::for_options(o)?;
        let metadata = match std::fs::symlink_metadata(&reader.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Read::Absent {
                    checked: format!("{} is absent", reader.path.display()),
                });
            }
            Err(e) => return Err(fail(StoreErrorCode::Unreadable, e.to_string())),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() < 100 {
            return Err(fail(
                StoreErrorCode::Unreadable,
                "state.db is not a complete regular SQLite file",
            ));
        }
        let c = reader.connect()?;
        connection::info(&c)?;
        Ok(Read::Present { value: reader })
    }
    fn create_engine(
        o: &StoreOptions,
        lease: &dyn RuntimeLease,
        id: StoreId,
        mode: LeaseMode,
    ) -> StoreResult<(SqliteReader, Engine)> {
        let identity = lease.identity()?;
        if identity.mode != mode || identity.store.is_some() || identity.generation == 0 {
            return Err(fail(
                StoreErrorCode::GenerationChanged,
                "bootstrap requires measured-absent store and held runtime lease",
            ));
        }
        let reader = SqliteReader::for_options(o)?;
        match lease.files().readback(&reader.path)? {
            Read::Absent { .. } => {}
            Read::Present { .. } => {
                return Err(fail(
                    StoreErrorCode::AlreadyExists,
                    "state.db already exists",
                ));
            }
            _ => {
                return Err(fail(
                    StoreErrorCode::Unreadable,
                    "destination absence is not proven",
                ));
            }
        }
        let stage = lease.files().create_staging(&o.state_directory)?;
        if stage.path.parent() != Some(o.state_directory.as_path())
            || !stage.file.metadata().map_err(invalid)?.is_file()
        {
            return Err(fail(
                StoreErrorCode::LocationUnsafe,
                "staging is not a reserved regular file in the state directory",
            ));
        }
        let staged = stage.path;
        drop(stage.file);
        let result = (|| {
            let c = Connection::open_with_flags(
                &staged,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(sql)?;
            c.execute_batch("PRAGMA page_size=16384").map_err(sql)?;
            connection::configure(&c, true, o.busy_timeout)?;
            c.execute_batch("PRAGMA synchronous=FULL; BEGIN EXCLUSIVE")
                .map_err(sql)?;
            c.execute_batch(include_str!("../migrations/001.sql"))
                .map_err(sql)?;
            c.execute("INSERT INTO store_info(singleton,store_id,incarnation,created_at_us,state) VALUES(1,?,1,?,'ready')",crate::sql_value::sql_params![crate::identity::canonical(id.as_str()).ok_or_else(||invalid("canonical store identity required"))?,connection::now()?]).map_err(sql)?;
            c.execute_batch("COMMIT; PRAGMA wal_checkpoint(TRUNCATE)")
                .map_err(sql)?;
            let info = connection::info(&c)?;
            if info.id != id {
                return Err(invalid("created StoreId readback differs"));
            }
            c.close().map_err(|(_, e)| sql(e))?;
            match lease.files().readback(&staged)? {
                Read::Present { value: file } => file.sync_all().map_err(invalid)?,
                _ => {
                    return Err(fail(
                        StoreErrorCode::Unreadable,
                        "protected staging readback failed",
                    ));
                }
            }
            lease.files().publish_no_replace(&staged, &reader.path)?;
            match lease.files().readback(&reader.path)? {
                Read::Present { .. } => {}
                _ => {
                    return Err(fail(
                        StoreErrorCode::CommitOutcomeUnknown,
                        "published store name not readable; preserve original init identity",
                    ));
                }
            }
            let db = connection::connect(&reader.path, true, o.busy_timeout)?;
            let identity = LeaseIdentity {
                store: Some(id),
                ..identity
            };
            Ok((
                reader,
                Engine {
                    db,
                    identity,
                    poisoned: false,
                },
            ))
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&staged);
        }
        result
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
        match Self::existing(o)? {
            Read::Present { value: reader } => {
                let db = connection::connect(&reader.path, true, o.busy_timeout)?;
                let info = connection::info(&db)?;
                let identity = connection::validate_lease(&info, lease, LeaseMode::DirectClient)?;
                Ok(Read::Present {
                    value: SqliteDirect {
                        reader,
                        engine: Engine {
                            db,
                            identity,
                            poisoned: false,
                        },
                    },
                })
            }
            other => Ok(other.map(|_| unreachable!())),
        }
    }
    fn open_host(o: &StoreOptions, lease: &dyn RuntimeLease) -> StoreResult<Read<Self::Host>> {
        match Self::existing(o)? {
            Read::Present { value: reader } => {
                let db = connection::connect(&reader.path, true, o.busy_timeout)?;
                let info = connection::info(&db)?;
                let identity = connection::validate_lease(&info, lease, LeaseMode::Host)?;
                Ok(Read::Present {
                    value: SqliteHost {
                        reader,
                        engine: Engine {
                            db,
                            identity,
                            poisoned: false,
                        },
                        context: BackupContext::new_internal(),
                    },
                })
            }
            other => Ok(other.map(|_| unreachable!())),
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
        Ok(SqliteHost {
            reader,
            engine,
            context: BackupContext::new_internal(),
        })
    }
    fn backup(
        _: &StoreOptions,
        _: Arc<dyn RuntimeLease>,
        _: BackupContext,
        _: Duration,
    ) -> StoreResult<BackupReport> {
        later("automatic backup")
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
        connection::info(&self.connect()?)
    }
    fn snapshot(&self, scope: ReadScope) -> StoreResult<Self::Snapshot> {
        SqliteSnapshot::open(self, scope)
    }
    fn runtime_owner(&self) -> StoreResult<Read<RuntimeOwnerHead>> {
        let c = self.connect()?;
        let info = connection::info(&c)?;
        let row:Option<(String,u64,u64,i64)>=c.query_row("SELECT owner_epoch,owner_generation,revision,last_seq FROM runtime_owner WHERE singleton=1",[],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?,crate::sql_value::value(r,3)?))).optional().map_err(sql)?;
        match row {
            None => Ok(Read::Absent {
                checked: "runtime_owner singleton absent".into(),
            }),
            Some((epoch, generation, revision, seq)) => Ok(Read::Present {
                value: RuntimeOwnerHead {
                    epoch: serde_json::from_str(&epoch).map_err(invalid)?,
                    generation: se_types::Generation::new(generation).map_err(invalid)?,
                    revision: crate::codec::revision(revision)?,
                    event: crate::read::load_event(&c, seq, &info)?.header.event,
                    handover: None,
                },
            }),
        }
    }
    fn credential(&self, _: [u8; 32]) -> StoreResult<Read<CredentialRecord>> {
        later("capability credential lookup")
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
                _: &mut dyn std::io::Read,
                _: u64,
                _: &dyn RuntimeLease,
            ) -> StoreResult<StagedText> {
                later("large capture staging")
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
        _: FirstBinding,
        _: &dyn RuntimeLease,
    ) -> StoreResult<FirstBindingReceipt> {
        later("embedded first binding")
    }
    fn checkpoint(
        &mut self,
        mode: CheckpointMode,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<CheckpointReport> {
        connection::validate_lease(&connection::info(&self.engine.db)?, lease, LeaseMode::Host)?;
        self.engine
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
            .map_err(sql)
    }
    fn erase(
        &mut self,
        _: ErasurePlan,
        _: ErasureApproval,
        _: &dyn RuntimeLease,
    ) -> StoreResult<ErasureReport> {
        later("body erasure")
    }
    fn close_clean(self, _: &dyn RuntimeLease, _: Duration) -> StoreResult<BackupReport> {
        later("shutdown backup")
    }
}
