//! Publish a fresh protected store through verified same-volume staging.
use super::*;
impl SqliteFactory {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) fn create_engine(
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
        match lease.files().inspect_metadata(&reader.path)? {
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
        let created_at = connection::now()?;
        let result = (|| {
            let c = connection::open(
                &staged,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            c.execute_batch("PRAGMA page_size=4096")
                .map_err(|error| sqlite_context(error, &staged, StoreIoStage::PragmaReadback))?;
            connection::configure(&c, &staged, true, o.busy_timeout)?;
            c.execute_batch("PRAGMA synchronous=FULL; BEGIN EXCLUSIVE")
                .map_err(sql)?;
            c.execute_batch(include_str!("../../migrations/001.sql"))
                .map_err(sql)?;
            for step in crate::migration::fresh() {
                c.execute_batch(step).map_err(sql)?;
            }
            c.execute("INSERT INTO store_info(singleton,store_id,incarnation,created_at_us,state) VALUES(1,?,1,?,'ready')",crate::sql_value::sql_params![crate::identity::canonical(id.as_str()).ok_or_else(||invalid("canonical store identity required"))?,created_at]).map_err(sql)?;
            c.execute_batch("COMMIT; PRAGMA wal_checkpoint(TRUNCATE)")
                .map_err(sql)?;
            let info = connection::info(&c)?;
            if info.id != id {
                return Err(invalid("created StoreId readback differs"));
            }
            c.close().map_err(|(_, e)| sql(e))?;
            match lease.files().readback(&staged)? {
                Read::Present { .. } => {}
                _ => {
                    return Err(fail(
                        StoreErrorCode::Unreadable,
                        "protected staging readback failed",
                    ));
                }
            }
            lease.files().publish_no_replace(&staged, &reader.path)?;
            match lease.files().inspect_metadata(&reader.path)? {
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
            let reader_path = reader.path.clone();
            Ok((
                reader,
                Engine {
                    db,
                    path: reader_path,
                    identity,
                    poisoned: false,
                    pending: Vec::new(),
                    maintenance: None,
                    backup: None,
                    checkpoints: Default::default(),
                },
            ))
        })();
        match result {
            Err(mut error) => {
                for suffix in ["-journal", "-wal", "-shm", ""] {
                    let name = staged
                        .file_name()
                        .and_then(|s| s.to_str())
                        .ok_or_else(|| invalid("native staging name"))?;
                    let path = staged.with_file_name(format!("{name}{suffix}"));
                    if let Err(cleanup) = crate::backup::remove_if_present(
                        lease.files(),
                        &path,
                        std::time::Instant::now() + Duration::from_secs(1),
                    ) {
                        error.cause.push_str(&format!(
                            "; retained staging {}: {}",
                            path.display(),
                            cleanup.cause
                        ));
                    }
                }
                Err(error)
            }
            success => success,
        }
    }
}
