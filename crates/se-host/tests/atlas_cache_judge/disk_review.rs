//! Differential disk-admission checks through the production cache port.
use super::*;
use std::path::Path;

const CAP: u64 = 512_000_000;

fn allocated_bytes(path: &Path) -> std::io::Result<u64> {
    let mut bytes = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        bytes += if meta.is_dir() {
            allocated_bytes(&entry.path())?
        } else {
            meta.len()
        };
    }
    Ok(bytes)
}

fn resize(path: &Path, length: u64) -> std::io::Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .set_len(length)
}

fn refuse_disk(cache: &NativeAtlasCache, requested: u64, case: &str) -> Check {
    let error = match cache.reserve_growth(requested) {
        Ok(_) => return Err(format!("{case} admitted growth over the root limit").into()),
        Err(error) => error,
    };
    assert!(
        matches!(error.body.detail(), se_types::Detail::AtlasResourceBudget(detail)
            if detail.resource == "Atlas root disk" && detail.requested == requested && detail.available == 0),
        "{case} did not name the exhausted root budget: {error:?}",
    );
    Ok(())
}

#[test]
fn cached_inventory_refuses_one_more_byte_at_a_filled_root() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "fixture lock")?;
    let f = fixture()?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let pin = cache.reserve_database(&epoch(4)?)?;
    resize(&pin.path, 128 * 1024)?;
    drop(cache.reserve_growth(1)?); // Retain an inventory before the cap check.
    let used = allocated_bytes(&f.scope.registration.cache.directory)?;
    let fill = cache.reserve_growth(CAP - used)?;
    refuse_disk(&cache, 1, "filled root")?;
    drop(fill);
    drop(cache.reserve_growth(1)?);
    drop(pin);
    drop(cache);
    f._root_owner.finish(Ok(()))
}

#[test]
fn cached_inventory_counts_growth_during_an_existing_batch_reservation() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "fixture lock")?;
    let f = fixture()?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let pin = cache.reserve_database(&epoch(4)?)?;
    resize(&pin.path, 128 * 1024)?;
    drop(cache.reserve_growth(1)?);
    // Hold the actual reservation used by the transaction path while an
    // existing cache file grows in place. No half-gigabyte write is needed.
    let batch = cache.reserve_growth(500_000_000)?;
    resize(&pin.path, 13_000_000)?;
    refuse_disk(&cache, 1, "in-place growth during a batch")?;
    assert_eq!(fs::metadata(&pin.path)?.len(), 13_000_000);
    drop(batch);
    drop(cache.reserve_growth(1)?);
    drop(pin);
    drop(cache);
    f._root_owner.finish(Ok(()))
}

#[test]
fn cached_inventory_refuses_an_external_write_to_the_cache_folder() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "fixture lock")?;
    let f = fixture()?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let pin = cache.reserve_database(&epoch(4)?)?;
    drop(cache.reserve_growth(1)?);
    let outside = f.scope.registration.cache.directory.join("external.tmp");
    fs::write(&outside, b"independent writer evidence")?;
    let error = match cache.reserve_growth(1) {
        Ok(_) => {
            return Err("cached inventory admitted growth with an external cache entry".into());
        }
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("unknown or linked Atlas cache entry"),
        "{error:?}"
    );
    assert_eq!(fs::read(&outside)?, b"independent writer evidence");
    fs::remove_file(outside)?;
    drop(cache.reserve_growth(1)?);
    drop(pin);
    drop(cache);
    f._root_owner.finish(Ok(()))
}
