//! SQLite must keep refusing a final database link after resolving its ancestors.
use super::*;
use std::{cell::Cell, os::unix::fs::symlink, path::Path, process::Command};

fn linked() -> Result<(Native, CacheSeed, SqlProfile, PathBuf), Box<dyn Error>> {
    let (mut native, seed, profile) = setup()?;
    let physical = fs::canonicalize(&native.dir)?;
    let real = physical.join("real");
    fs::create_dir(&real)?;
    let alias = physical.join("alias");
    symlink(&real, &alias)?;
    native.dir = alias;
    Ok((native, seed, profile, physical))
}

#[test]
fn trusted_ancestor_open_keeps_real_database_write_and_readback() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (files, seed, profile, physical) = linked()?;
    let mut db = CacheConnection::create(
        &files,
        &seed,
        ConnectionRole::HostWriter,
        &profile,
        deadline(),
    )?;
    db.write(0, deadline(), |sql| {
        sql.prepare("INSERT INTO names(text) VALUES('boundary readback')")?
            .execute([])
            .map_err(cache_error)?;
        Ok(())
    })?;
    let n: i64 = db.read(deadline(), |sql| {
        sql.prepare("SELECT count(*) FROM names WHERE text='boundary readback'")?
            .query_row([], |r| r.get(0))
            .map_err(cache_error)
    })?;
    assert_eq!(n, 1);
    drop(db);
    assert!(
        physical
            .join("real")
            .join(seed.identity.epoch.as_str())
            .is_file()
    );
    drop(files);
    fs::remove_dir_all(physical)?;
    Ok(())
}

struct ReplaceAfterValidation<'a> {
    native: &'a Native,
    saved: PathBuf,
    replaced: Cell<bool>,
}
impl CacheFiles for ReplaceAfterValidation<'_> {
    fn read_pointer(&self) -> AtlasResult<Option<Vec<u8>>> {
        self.native.read_pointer()
    }
    fn replace_pointer(&self, expected: Option<&[u8]>, bytes: &[u8]) -> AtlasResult<()> {
        self.native.replace_pointer(expected, bytes)
    }
    fn pin_database(&self, epoch: &CacheEpoch) -> AtlasResult<Option<DatabasePin>> {
        self.native.pin_database(epoch)
    }
    fn reserve_database(&self, epoch: &CacheEpoch) -> AtlasResult<DatabasePin> {
        self.native.reserve_database(epoch)
    }
    fn discard_unpublished(&self, pin: &DatabasePin) -> AtlasResult<()> {
        self.native.discard_unpublished(pin)
    }
    fn wal_bytes(&self, pin: &DatabasePin) -> AtlasResult<u64> {
        self.native.wal_bytes(pin)
    }
    fn reserve_growth(&self, bytes: u64) -> AtlasResult<Box<dyn GrowthReservation + '_>> {
        self.native.reserve_growth(bytes)
    }
    fn validate_database(&self, pin: &DatabasePin) -> AtlasResult<()> {
        self.native.validate_database(pin)?;
        if !self.replaced.replace(true) {
            // A separate process replaces only this fixture's database name at
            // the handoff after native validation, before SQLite opens it.
            let status = Command::new("python3").arg("-c")
                .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2]); os.symlink(sys.argv[2],sys.argv[1])")
                .arg(&pin.path).arg(&self.saved).status().map_err(cache_error)?;
            if !status.success() {
                return Err(cache_error("replacement fixture process failed"));
            }
        }
        Ok(())
    }
}

fn unchanged_empty(path: &Path) -> Check {
    assert_eq!(
        fs::metadata(path)?.len(),
        0,
        "SQLite wrote through a final database symlink before reporting a pin refusal"
    );
    assert!(fs::read(path)?.is_empty());
    Ok(())
}

#[test]
fn final_link_after_pin_validation_refuses_before_writing_through_it() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (native, seed, profile, physical) = linked()?;
    let saved = physical.join("reserved-before-open");
    let files = ReplaceAfterValidation {
        native: &native,
        saved: saved.clone(),
        replaced: Cell::new(false),
    };
    let result = CacheConnection::create(
        &files,
        &seed,
        ConnectionRole::HostWriter,
        &profile,
        deadline(),
    );
    assert!(result.is_err(), "replaced database name was admitted");
    assert!(files.replaced.get(), "replacement was not exercised");
    assert!(
        fs::symlink_metadata(native.dir.join(seed.identity.epoch.as_str()))?
            .file_type()
            .is_symlink()
    );
    unchanged_empty(&saved)?;
    drop(result);
    drop(files);
    drop(native);
    fs::remove_dir_all(physical)?;
    Ok(())
}
