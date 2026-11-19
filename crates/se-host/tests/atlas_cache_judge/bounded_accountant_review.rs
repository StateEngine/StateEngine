//! Real Windows cold writer, disk admission and cleanup with an independent file.
use super::*;
use se_proc::{NativeStateFiles, ProtectedStateStaging};

const LIVE_RESERVATION: u64 = 500_000_000;
const EXTERNAL_GROWTH: u64 = 13_000_000;
const REFRESH: Duration = Duration::from_secs(1);
const ROW: &str = "bounded accountant fixture";

fn with_cold(run: impl FnOnce(&Fixture, &NativeAtlasCache, CacheConnection<'_>) -> Check) -> Check {
    let _serial = SERIAL.lock().map_err(|_| "fixture lock")?;
    let f = fixture()?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let db = CacheConnection::create(
        &cache,
        &seed(&f)?,
        ConnectionRole::ColdWriter,
        &SqlProfile::contained_cold(),
        setup_deadline(),
    )?;
    run(&f, &cache, db)?;
    drop(cache);
    f._root_owner.finish(Ok(()))
}

fn outside_file(f: &Fixture) -> Result<ProtectedStateStaging, Box<dyn Error>> {
    let root = &f.scope.registration.cache.directory;
    Ok(NativeStateFiles::open(root)?.create_staging(root)?)
}

fn refuses_disk(cache: &NativeAtlasCache) -> Result<bool, Box<dyn Error>> {
    match cache.reserve_growth(1) {
        Ok(_) => Ok(false),
        Err(error) => {
            assert!(
                matches!(error.body.detail(), se_types::Detail::AtlasResourceBudget(detail)
                    if detail.resource == "Atlas root disk" && detail.available == 0),
                "different refusal: {error}"
            );
            Ok(true)
        }
    }
}

fn witness(name: &str, body: serde_json::Value) -> Check {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/judge-diagnostics");
    fs::create_dir_all(&path)?;
    fs::write(
        path.join(format!("{name}.json")),
        serde_json::to_vec(&body)?,
    )?;
    Ok(())
}

#[test]
fn bounded_accountant_refuses_external_growth_at_the_next_interval() -> Check {
    with_cold(|f, cache, _db| {
        let external = outside_file(f)?;
        let batch = cache.reserve_growth(LIVE_RESERVATION)?;
        external.file.set_len(EXTERNAL_GROWTH)?;
        let grew = Instant::now();
        let mut successful_reservations = 0;
        let first_refusal = loop {
            let begin = Instant::now();
            if refuses_disk(cache)? {
                break begin;
            }
            assert!(
                begin.duration_since(grew) < REFRESH,
                "admission continued after the complete refresh interval"
            );
            successful_reservations += 1;
            std::thread::sleep(Duration::from_millis(20));
        };
        witness(
            "atlas-accountant-external-growth",
            serde_json::json!({
                "permitted_before_refusal": successful_reservations,
                "first_refusal_started_us": first_refusal.duration_since(grew).as_micros(),
                "refresh_interval_ms": REFRESH.as_millis()
            }),
        )?;
        drop(batch);
        Ok(())
    })
}

fn failed_transaction(duplicate: bool) -> Check {
    with_cold(|f, cache, mut db| {
        let external = outside_file(f)?;
        let warmed = Instant::now();
        let batch = cache.reserve_growth(LIVE_RESERVATION)?;
        let result: se_types::Result<()> = db.write(65_536, setup_deadline(), |sql| {
            let mut insert = sql.prepare("INSERT INTO names(text) VALUES(?1)")?;
            let refused_sql = |error: rusqlite::Error| {
                se_types::SeError::invalid("fixture SQL mutation", &error.to_string())
            };
            insert.execute([ROW]).map_err(refused_sql)?;
            external.file.set_len(EXTERNAL_GROWTH).map_err(|error| {
                se_types::SeError::invalid("independent staging growth", &error.to_string())
            })?;
            if duplicate {
                insert.execute([ROW]).map_err(refused_sql)?;
                Ok(())
            } else {
                Err(se_types::SeError::invalid(
                    "fixture decision",
                    "roll back inserted row",
                ))
            }
        });
        let error = result.err().ok_or("failed mutation was committed")?;
        if duplicate {
            assert!(error.to_string().contains("UNIQUE constraint"), "{error}");
        } else {
            assert!(
                error.to_string().contains("roll back inserted row"),
                "{error}"
            );
        }
        let began = warmed.elapsed();
        assert!(
            began < REFRESH,
            "fixture missed the unexpired estimate: {began:?}"
        );
        assert!(
            refuses_disk(cache)?,
            "failed transaction retained a stale estimate"
        );
        drop(batch);
        let rows: i64 = db.read(setup_deadline(), |sql| {
            sql.prepare("SELECT count(*) FROM names WHERE text=?1")?
                .query_row([ROW], |row| row.get(0))
                .map_err(|error| {
                    se_types::SeError::invalid("read failed mutation", &error.to_string())
                })
        })?;
        assert_eq!(rows, 0, "failed transaction retained its row");
        witness(
            if duplicate {
                "atlas-accountant-failed-sql"
            } else {
                "atlas-accountant-rollback"
            },
            serde_json::json!({
                "refusal_started_us_after_warming": began.as_micros(),
                "rolled_back_rows": rows,
                "refused_disk": true
            }),
        )
    })
}

#[test]
fn bounded_accountant_discards_the_estimate_after_sql_failure() -> Check {
    failed_transaction(true)
}

#[test]
fn bounded_accountant_discards_the_estimate_after_rollback() -> Check {
    failed_transaction(false)
}

#[test]
fn bounded_accountant_releases_the_native_observation_before_cleanup() -> Check {
    with_cold(|f, cache, db| {
        let stage = outside_file(f)?;
        let name = stage.path;
        drop(stage.file);
        drop(cache.reserve_growth(1)?);
        let moved = f.dir.join("recovery-proof");
        let held_before_close = match fs::rename(&name, &moved) {
            Ok(()) => {
                fs::rename(&moved, &name)?;
                false
            }
            Err(error) => {
                assert!(matches!(error.raw_os_error(), Some(5 | 32)), "{error}");
                true
            }
        };
        drop(db);
        fs::remove_file(&name)?;
        assert!(!name.exists());
        let key = epoch(4)?;
        let pin = cache
            .pin_database(&key)?
            .ok_or("unpublished database absent")?;
        let parent = pin.path.parent().ok_or("epoch parent absent")?;
        cache.discard_unpublished(&pin)?;
        assert!(!parent.exists());
        assert!(cache.read_pointer()?.is_none());
        drop(pin);
        witness(
            "atlas-accountant-cleanup",
            serde_json::json!({
                "held_before_close": held_before_close,
                "observation_released": true,
                "epoch_removed": true
            }),
        )
    })
}
