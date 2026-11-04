//! Protects: fresh pooled read authority, native custody and bounded resource closure.
#![cfg(any(target_os = "linux", windows))]
use se_store::*;
use se_types::Read;
use std::{fs, num::NonZeroU32};
#[path = "support/capture_fixture.rs"]
#[allow(dead_code)]
mod capture_fixture;
#[path = "support/store_fixture.rs"]
mod fixture;
#[path = "support/host_fixture.rs"]
#[allow(dead_code)]
mod host_fixture;
#[path = "support/native_read_identity.rs"]
mod native;
use fixture::*;

fn initialized_fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let _owner = se_proc::initialize_file_creation_owner()
        .map_err(|e| format!("native file owner initialization: {e}"))?;
    Fixture::new()
}

/// Protects: G6 — an actual header refusal closes cached SQL but keeps its native
/// identity alive. The replacement has the same bytes and SQL store identity.
/// Protects: pooled reads preserve refused header empties idle sql without rebinding the native identity.
#[test]
fn refused_header_empties_idle_sql_without_rebinding_the_native_identity() -> Check {
    let f = initialized_fixture()?;
    let (writer, lease) = f.direct()?;
    writer.close()?;
    drop(lease);
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let pool = reader.phase_pool(native::open_identity)?;
    pool.read_phase()?.close()?;
    let path = f.options.state_directory.join("state.db");
    let db = rusqlite::Connection::open(&path)?;
    let version: u32 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    db.execute_batch("PRAGMA user_version=2147483647")?;
    assert_eq!(
        pool.read_phase()
            .err()
            .ok_or("pooled checkout ignored the fresh header")?
            .code,
        StoreErrorCode::TooNew
    );
    db.execute_batch(&format!("PRAGMA user_version={version}"))?;
    db.close().map_err(|(_, e)| e)?;
    let original = f.options.state_directory.join("original.db");
    let copy = f.options.state_directory.join("replacement.db");
    fs::copy(&path, &copy)?;
    fs::rename(&path, &original)?;
    fs::rename(&copy, &path)?;
    let replacement = se_proc::NativeSourcePin::open(&path)?.ok_or("replacement absent")?;
    let old = se_proc::NativeSourcePin::open(&original)?.ok_or("original absent")?;
    assert_ne!(
        replacement.identity(),
        old.identity(),
        "the replacement did not change native file identity"
    );
    drop((replacement, old));
    for _ in 0..3 {
        assert_eq!(
            pool.read_phase()
                .err()
                .ok_or("an emptied pool silently rebound to a replacement database")?
                .code,
            StoreErrorCode::SourceChanged
        );
    }
    fs::rename(&path, &copy)?;
    fs::rename(&original, &path)?;
    pool.read_phase()?.close()?;
    pool.close()?;
    Ok(())
}

/// Protects: G1 — cached connections observe committed credential activation and revocation.
#[test]
fn cached_connection_observes_newly_committed_activation_and_revocation() -> Check {
    use capture_fixture::*;
    let f = initialized_fixture()?;
    let (mut writer, lease) = f.direct()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let pool = reader.phase_pool(native::open_identity)?;
    let session = session()?;
    let credential = record()?;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    writer.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                prepared(&f, &session, &f.a),
                EventBody::CredentialIssued {
                    credential,
                    session: session.clone(),
                    purpose: "http".into(),
                    secret_sha256: [17; 32],
                    expires_at_us: now + 300_000_000,
                    activation_deadline_us: now + 60_000_000,
                    expected: Expected::Absent,
                },
            ],
        )?,
        &*lease,
    )?;
    let phase = pool.read_phase()?;
    assert_eq!(
        present(phase.credential([17; 32])?)?.state,
        CredentialState::Prepared
    );
    phase.close()?;
    writer.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                activated(&session)?,
                EventBody::CredentialActivated {
                    credential,
                    session: session.clone(),
                    expected: revision(1)?,
                    first_request: record()?,
                },
            ],
        )?,
        &*lease,
    )?;
    let phase = pool.read_phase()?;
    assert_eq!(
        present(phase.credential([17; 32])?)?.state,
        CredentialState::Active
    );
    phase.close()?;
    writer.append(
        f.batch(
            f.owner_project(),
            None,
            vec![EventBody::CredentialRevoked {
                credential,
                expected: revision(2)?,
                reason: InputText::Inline("independently committed revocation".into()),
            }],
        )?,
        &*lease,
    )?;
    let phase = pool.clone().read_phase()?;
    assert_eq!(
        present(phase.credential([17; 32])?)?.state,
        CredentialState::Revoked
    );
    phase.close()?;
    pool.close()?;
    writer.close()?;
    Ok(())
}

/// Protects: G6 — cached connections observe the next committed owner generation.
#[test]
fn cached_connection_observes_a_new_committed_owner_generation() -> Check {
    let f = initialized_fixture()?;
    let (host, lease) = host_fixture::host(&f)?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let pool = reader.phase_pool(native::open_identity)?;
    let phase = pool.read_phase()?;
    assert_eq!(present(phase.runtime_owner()?)?.generation.get(), 1);
    phase.close()?;
    drop(host);
    lease.identity.lock().map_err(|_| "lease mutex")?.generation = 2;
    let mut host = present(SqliteFactory::open_host(&f.options, &*lease)?)?;
    let mut epoch = host_fixture::epoch()?;
    epoch.generation = se_types::HostGeneration::new(2)?;
    let mut admission = f.admission(Scope::Registry, Actor::Human(f.owner.clone()));
    admission.generation = 2;
    host.record_runtime_ownership(
        f.batch(
            admission,
            Some(request("pool-next-owner")?),
            vec![EventBody::RuntimeOwnerEstablished {
                epoch,
                generation: se_types::Generation::new(2)?,
                expected_owner_generation: Some(se_types::Generation::new(1)?),
                expected: revision(1)?,
                witnesses: vec![],
                recovered: None,
            }],
        )?,
        &*lease,
    )?;
    let phase = pool.clone().read_phase()?;
    let current = present(phase.runtime_owner()?)?;
    assert_eq!(current.generation.get(), 2);
    assert_eq!(current.revision.value.get(), 2);
    phase.close()?;
    pool.close()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn native_database_handles(path: &std::path::Path) -> Result<usize, Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt;
    let wanted = fs::metadata(path)?;
    let mut count = 0;
    for entry in fs::read_dir("/proc/self/fd")? {
        match fs::metadata(entry?.path()) {
            Ok(found) if found.dev() == wanted.dev() && found.ino() == wanted.ino() => count += 1,
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(count)
}

/// Protects: G6 — ordinary and cached phases share capacity and retain only bounded idle handles.
#[test]
fn ordinary_and_cached_phases_share_capacity_and_idle_handles_stay_bounded() -> Check {
    let f = initialized_fixture()?;
    let (writer, lease) = f.direct()?;
    writer.close()?;
    drop(lease);
    for capacity in [2, 8] {
        let reader = present(SqliteFactory::open_reader_with_capacity(
            &f.options,
            NonZeroU32::new(capacity).ok_or("capacity")?,
        )?)?;
        let pool = reader.phase_pool(native::open_identity)?;
        let mut active = Vec::new();
        for i in 0..capacity {
            active.push(if i % 2 == 0 {
                pool.clone().read_phase()?
            } else {
                reader.clone().read_phase()?
            });
        }
        assert_eq!(
            pool.read_phase()
                .err()
                .ok_or("cached phase bypassed shared capacity")?
                .code,
            StoreErrorCode::Backpressure
        );
        assert_eq!(
            reader
                .snapshot(f.scoped(Visibility::Owner))
                .err()
                .ok_or("snapshot bypassed cached reservations")?
                .code,
            StoreErrorCode::Backpressure
        );
        assert_eq!(
            reader
                .credential([7; 32])
                .err()
                .ok_or("credential bypassed cached reservations")?
                .code,
            StoreErrorCode::Backpressure
        );
        for phase in active {
            phase.close()?;
        }
        for _ in 0..3 {
            let phases = (0..capacity)
                .map(|_| pool.read_phase())
                .collect::<StoreResult<Vec<_>>>()?;
            assert_eq!(
                pool.read_phase()
                    .err()
                    .ok_or("too many cached phases admitted")?
                    .code,
                StoreErrorCode::Backpressure
            );
            for phase in phases {
                phase.close()?;
            }
            #[cfg(target_os = "linux")]
            assert_eq!(
                native_database_handles(&f.options.state_directory.join("state.db"))?,
                capacity as usize + 1,
                "the cache must reuse its bounded idle SQL handles plus one native pin"
            );
        }
        pool.close()?;
        #[cfg(target_os = "linux")]
        assert_eq!(
            native_database_handles(&f.options.state_directory.join("state.db"))?,
            0,
            "close left native database handles"
        );
    }
    Ok(())
}

/// Protects: G6 — closing the pool seals admission and closes handles returned afterwards.
#[test]
fn close_seals_checkout_and_physically_closes_a_phase_returned_after_close() -> Check {
    let f = initialized_fixture()?;
    let (writer, lease) = f.direct()?;
    writer.close()?;
    drop(lease);
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let pool = reader.phase_pool(native::open_identity)?;
    pool.read_phase()?.close()?;
    let active = pool.read_phase()?;
    pool.close()?;
    assert_eq!(
        pool.read_phase()
            .err()
            .ok_or("closed pool allowed a checkout")?
            .code,
        StoreErrorCode::NotReady
    );
    assert!(
        matches!(active.credential([9; 32])?, Read::Absent { .. }),
        "accepted phase was invalidated rather than joined"
    );
    active.close()?;
    #[cfg(target_os = "linux")]
    assert_eq!(
        native_database_handles(&f.options.state_directory.join("state.db"))?,
        0,
        "returned-after-close phase kept its SQLite or identity handle"
    );
    let path = f.options.state_directory.join("state.db");
    let moved = f.options.state_directory.join("closed.db");
    fs::rename(&path, &moved)?;
    fs::rename(&moved, &path)?;
    pool.close()?;
    Ok(())
}

/// Protects: G4 — an explicit close after a real query refusal clears the old read and reuses a fresh committed snapshot.
#[test]
fn query_refusal_then_explicit_close_observes_the_next_committed_head() -> Check {
    let f = initialized_fixture()?;
    let (mut writer, lease) = f.direct()?;
    writer.append(
        f.working("before", Expected::Absent, "pool-before")?,
        &*lease,
    )?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let pool = reader.phase_pool(native::open_identity)?;
    let mut read = pool
        .read_phase()?
        .into_snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(
        present(read.working_state(f.a.clone())?)?
            .revision
            .value
            .get(),
        1
    );
    let error = read
        .history(
            HistoryQuery {
                agent: None,
                session: None,
                kinds: Vec::new(),
                families: Vec::new(),
                transcript: se_store::TranscriptFilter::All,
                since: None,
            },
            budget(1, 1, None)?,
        )
        .err()
        .ok_or("one-byte history did not reach its real query refusal")?;
    assert_eq!(error.code, StoreErrorCode::ReadBudgetTooSmall);
    read.close()?;
    writer.append(f.working("after", revision(1)?, "pool-after")?, &*lease)?;
    writer.close()?;
    drop(lease);
    let mut next = pool
        .read_phase()?
        .into_snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(
        present(next.working_state(f.a.clone())?)?
            .revision
            .value
            .get(),
        2
    );
    next.close()?;
    pool.close()?;
    Ok(())
}

/// Protects: G6 — abandoning a cached snapshot physically closes SQL before returning its reader capacity.
#[test]
fn implicit_snapshot_drop_closes_sql_and_returns_shared_capacity() -> Check {
    let f = initialized_fixture()?;
    let (writer, lease) = f.direct()?;
    writer.close()?;
    drop(lease);
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let pool = reader.phase_pool(native::open_identity)?;
    pool.read_phase()?.close()?;
    let read = pool
        .read_phase()?
        .into_snapshot(f.scoped(Visibility::Owner))?;
    drop(read);
    #[cfg(target_os = "linux")]
    assert_eq!(
        native_database_handles(&f.options.state_directory.join("state.db"))?,
        1,
        "implicit drop recycled SQL instead of keeping only native identity custody"
    );
    let a = pool.read_phase()?;
    let b = reader.read_phase()?;
    assert_eq!(
        pool.read_phase()
            .err()
            .ok_or("reader capacity lost after drop")?
            .code,
        StoreErrorCode::Backpressure
    );
    a.close()?;
    b.close()?;
    pool.close()?;
    Ok(())
}
