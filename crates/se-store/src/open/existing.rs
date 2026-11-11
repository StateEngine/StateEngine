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
        Self::existing_finish(o, slots, |reader, db| {
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
        Self::existing_finish(o, crate::read_slots::ReadSlots::default(), |reader, db| {
            let slot = reader.slots.acquire()?;
            let phase = reader.read_phase_on(slot, db)?;
            Ok((reader, phase))
        })
    }
    fn existing_finish<T>(
        o: &StoreOptions,
        slots: crate::read_slots::ReadSlots,
        finish: impl FnOnce(SqliteReader, Connection) -> StoreResult<T>,
    ) -> StoreResult<Read<T>> {
        let reader = SqliteReader::with_slots(o, slots)?;
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
        let db = reader.connect()?;
        finish(reader, db).map(|value| Read::Present { value })
    }
    pub(super) fn existing_protected(
        o: &StoreOptions,
        lease: &dyn RuntimeLease,
    ) -> StoreResult<Read<SqliteReader>> {
        let path = o.state_directory.join("state.db");
        match lease
            .files()
            .inspect_metadata(&path)
            .map_err(|error| context(error, &path, StoreIoStage::Open))?
        {
            Read::Present { .. } => Self::existing(o),
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
}
