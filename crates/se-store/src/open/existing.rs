//! Read existing stores without bootstrap or migration.
use super::*;
impl SqliteFactory {
    pub(super) fn existing(o: &StoreOptions) -> StoreResult<Read<SqliteReader>> {
        Self::existing_with_slots(o, crate::read_slots::ReadSlots::default())
    }
    pub(super) fn existing_with_slots(
        o: &StoreOptions,
        slots: crate::read_slots::ReadSlots,
    ) -> StoreResult<Read<SqliteReader>> {
        Self::existing_finish(o, slots, true, |reader, db| {
            connection::info_at(&db, &reader.path)?;
            Ok(reader)
        })
    }
    /// Open and validate one existing store on its first finite read pin.
    /// The returned reader shares its capacity with the phase; close or consume
    /// the phase before IPC, writer custody or any asynchronous wait.
    pub fn open_reader_with_phase(
        o: &StoreOptions,
    ) -> StoreResult<Read<(SqliteReader, ReadPhase)>> {
        Self::existing_finish(
            o,
            crate::read_slots::ReadSlots::default(),
            false,
            |r, db| {
                let slot = r.slots.acquire()?;
                let phase = r.read_phase_on(slot, db)?;
                Ok((r, phase))
            },
        )
    }
    /// Open and validate one existing store and seed its read-phase pool with
    /// the validated connection, avoiding a redundant second open during startup.
    pub fn open_reader_with_pool(
        o: &StoreOptions,
        capacity: std::num::NonZeroU32,
        open_identity: fn(&std::path::Path) -> StoreResult<Box<dyn crate::ReadConnectionIdentity>>,
    ) -> StoreResult<Read<(SqliteReader, ReadPhasePool)>> {
        Self::existing_finish(
            o,
            crate::read_slots::ReadSlots::new(capacity)?,
            true,
            |reader, db| {
                connection::info_at(&db, &reader.path)?;
                let pool = reader.phase_pool_seeded(open_identity, db)?;
                Ok((reader, pool))
            },
        )
    }
    fn existing_reader(
        o: &StoreOptions,
        slots: crate::read_slots::ReadSlots,
    ) -> StoreResult<Read<SqliteReader>> {
        let mut reader = SqliteReader::with_slots(o, slots)?;
        let metadata = match std::fs::symlink_metadata(&reader.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Windows also reports PATH_NOT_FOUND for a non-directory parent.
                // Establish absence without losing the original state.db error.
                for parent in reader.path.ancestors().skip(1) {
                    let obstruction = match std::fs::metadata(parent) {
                        Ok(m) if m.is_dir() => {
                            return Ok(Read::Absent {
                                checked: format!("{} is absent", reader.path.display()),
                            });
                        }
                        Ok(_) => format!("parent {} is not a directory", parent.display()),
                        Err(parent_error)
                            if parent_error.kind() == std::io::ErrorKind::NotFound =>
                        {
                            // A dangling link exists even when following it
                            // reports NotFound; only skip a proven absent entry.
                            match std::fs::symlink_metadata(parent) {
                                Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => {
                                    continue;
                                }
                                Ok(_) => format!(
                                    "parent {} exists but cannot be resolved: {parent_error}",
                                    parent.display()
                                ),
                                Err(check) => format!(
                                    "cannot verify parent {} without following links: {check}",
                                    parent.display()
                                ),
                            }
                        }
                        Err(parent_error) => {
                            format!("cannot verify parent {}: {parent_error}", parent.display())
                        }
                    };
                    let mut error = io(e, &reader.path, StoreIoStage::Open);
                    error.cause.push_str(&format!("; {obstruction}"));
                    return Err(error);
                }
                return Err(io(e, &reader.path, StoreIoStage::Open));
            }
            Err(e) => return Err(io(e, &reader.path, StoreIoStage::Open)),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(context(
                fail(
                    StoreErrorCode::Unreadable,
                    "state.db must be a regular file without symbolic links",
                ),
                &reader.path,
                StoreIoStage::Open,
            ));
        }
        if metadata.len() < 100 {
            return Err(context(
                fail(
                    StoreErrorCode::Corrupt,
                    "state.db is shorter than the SQLite header",
                ),
                &reader.path,
                StoreIoStage::Open,
            ));
        }
        reader.bind_identity()?;
        Ok(Read::Present { value: reader })
    }
    fn existing_finish<T>(
        o: &StoreOptions,
        slots: crate::read_slots::ReadSlots,
        check_path: bool,
        finish: impl FnOnce(SqliteReader, Connection) -> StoreResult<T>,
    ) -> StoreResult<Read<T>> {
        try_map_present(Self::existing_reader(o, slots)?, |r| {
            let db = r.connect_bound(check_path)?;
            finish(r, db).map(|value| Read::Present { value })
        })
    }
    pub(super) fn existing_protected(
        o: &StoreOptions,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<Read<SqliteReader>> {
        let path = o.state_directory.join("state.db");
        let meta = lease
            .files()
            .inspect_metadata(&path)
            .map_err(|e| context(e, &path, StoreIoStage::Open))?;
        try_map_present(meta, |_| Self::existing_reader(o, Default::default()))
    }
}
fn try_map_present<A, B>(
    read: Read<A>,
    f: impl FnOnce(A) -> StoreResult<Read<B>>,
) -> StoreResult<Read<B>> {
    match read {
        Read::Present { value } => f(value),
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
