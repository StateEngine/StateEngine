//! Real SQLite graph deltas, independent readback, and cold WAL custody.
use super::*;
use se_atlas::cache::schema;

fn graph(db: &mut CacheConnection<'_>) -> Check {
    db.write(1_000_000, deadline(), |sql| {
        sql.prepare("INSERT INTO names(text) VALUES('first'),('second')")?
            .execute([])
            .map_err(cache_error)?;
        Ok(())
    })?;
    Ok(())
}
#[test]
fn cold_wal_has_no_shared_file_mapping_and_host_reopens_normally() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(
        &f,
        &s,
        ConnectionRole::ColdWriter,
        &SqlProfile::contained_cold(),
        deadline(),
    )?;
    graph(&mut db)?;
    let path = f.dir.join(s.identity.epoch.as_str());
    assert!(
        !PathBuf::from(format!("{}-shm", path.display())).try_exists()?,
        "exclusive cold WAL created shared mapping storage"
    );
    #[cfg(target_os = "linux")]
    assert!(
        !fs::read_to_string("/proc/self/maps")?
            .lines()
            .any(|line| line.contains(path.to_string_lossy().as_ref())),
        "cold cache data file is mapped"
    );
    drop(db);
    let mut writer = CacheConnection::open(
        &f,
        s.identity.clone(),
        ConnectionRole::HostWriter,
        &p,
        deadline(),
    )?
    .ok_or("writer absent")?;
    let mut reader = CacheConnection::open(
        &f,
        s.identity.clone(),
        ConnectionRole::HostReader,
        &p,
        deadline(),
    )?
    .ok_or("reader absent")?;
    writer.write(1_000_000, deadline(), |sql| {
        sql.prepare("DELETE FROM names WHERE text='first'")?
            .execute([])
            .map_err(cache_error)?;
        Ok(())
    })?;
    assert_eq!(
        reader.read(deadline(), |sql| sql
            .prepare("SELECT count(*) FROM names WHERE text='first'")?
            .query_row([], |r| r.get::<_, i64>(0))
            .map_err(cache_error))?,
        0
    );
    Ok(())
}
#[test]
fn legacy_pointer_is_only_a_rebuild_fence_and_never_a_zero_count_cache() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    drop(db);
    let legacy = rusqlite::Connection::open(f.dir.join(s.identity.epoch.as_str()))?;
    legacy.pragma_update(None, "user_version", 3)?;
    drop(legacy);
    let old = CachePointer {
        schema: 3,
        project: s.identity.scope.registration.project.clone(),
        root: s.identity.scope.registration.root.clone(),
        epoch: s.identity.epoch.clone(),
    };
    let bytes = serde_json::to_vec(&old)?;
    fs::write(f.dir.join("current.json"), &bytes)?;
    assert_eq!(
        pointer::decode(&bytes, &s.identity.scope)?.epoch,
        s.identity.epoch
    );
    assert!(
        pointer::open_current(
            &f,
            &s.identity.scope,
            ConnectionRole::ExternalReader,
            &p,
            deadline()
        )
        .is_err()
    );
    assert_eq!(f.read_pointer()?.as_deref(), Some(bytes.as_slice()));
    let mut next = s;
    next.identity.epoch = CacheEpoch::from_parts(2, [5; 10])?;
    let db = CacheConnection::create(
        &f,
        &next,
        ConnectionRole::ColdWriter,
        &SqlProfile::contained_cold(),
        deadline(),
    )?;
    drop(db);
    let mut candidate = CacheConnection::open(
        &f,
        next.identity.clone(),
        ConnectionRole::CandidateReader,
        &p,
        deadline(),
    )?
    .ok_or("candidate absent")?;
    let published = pointer::publish(&f, &mut candidate, Some(&bytes), deadline())?;
    assert_eq!(published.schema, schema::SCHEMA_VERSION);
    assert_eq!(published.epoch, next.identity.epoch);
    Ok(())
}
