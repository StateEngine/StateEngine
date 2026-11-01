use se_store::*;
use se_types::Read;
use std::{num::NonZeroU32, sync::mpsc, time::Duration};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn capacity(value: u32) -> Result<NonZeroU32, Box<dyn std::error::Error>> {
    NonZeroU32::new(value).ok_or_else(|| "zero capacity".into())
}

/// Protects: the bounded constructor refuses invalid capacities before I/O,
/// while ordinary readers retain their original two-slot clone-shared limit.
#[test]
fn default_two_and_constructor_bounds() -> Check {
    let f = Fixture::new()?;
    let (direct, _lease) = f.direct()?;
    direct.close()?;
    let absent = StoreOptions {
        state_directory: f.home.join("never-created"),
        busy_timeout: Duration::from_secs(1),
    };
    for value in [1, 9, u32::MAX] {
        let error = SqliteFactory::open_reader_with_capacity(&absent, capacity(value)?)
            .err()
            .ok_or("out-of-range reader admitted")?;
        assert_eq!(error.code, StoreErrorCode::EventInvalid);
        assert!(error.cause.contains("2 and 8"));
    }
    assert!(matches!(
        SqliteFactory::open_reader_with_capacity(&absent, capacity(8)?)?,
        Read::Absent { .. }
    ));
    assert!(!absent.state_directory.try_exists()?);
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let clone = reader.clone();
    let first = reader.snapshot(f.scoped(Visibility::Owner))?;
    let second = clone.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(
        reader
            .snapshot(f.scoped(Visibility::Owner))
            .err()
            .ok_or("third default snapshot admitted")?
            .code,
        StoreErrorCode::Backpressure
    );
    first.close()?;
    let replacement = clone.snapshot(f.scoped(Visibility::Owner))?;
    second.close()?;
    replacement.close()?;
    for limit in 2..=8 {
        let bounded = present(SqliteFactory::open_reader_with_capacity(
            &f.options,
            capacity(limit)?,
        )?)?;
        let snapshots = (0..limit)
            .map(|_| bounded.clone().snapshot(f.scoped(Visibility::Owner)))
            .collect::<StoreResult<Vec<_>>>()?;
        assert_eq!(
            bounded
                .snapshot(f.scoped(Visibility::Owner))
                .err()
                .ok_or("configured reader capacity ignored")?
                .code,
            StoreErrorCode::Backpressure
        );
        for snapshot in snapshots {
            snapshot.close()?;
        }
    }
    Ok(())
}

/// Protects: eight actual SQLite snapshots on separate threads share one cloned
/// budget with credential and owner-guard reads; each observes the real project.
#[test]
fn eight_clones_share_capacity_with_private_reads() -> Check {
    let f = Fixture::new()?;
    let (direct, lease) = f.direct()?;
    direct.close()?;
    let reader = present(SqliteFactory::open_reader_with_capacity(
        &f.options,
        capacity(8)?,
    )?)?;
    std::thread::scope(|threads| -> Check {
        let (ready, received) = mpsc::channel();
        let mut releases = Vec::new();
        let mut clients = Vec::new();
        for _ in 0..8 {
            let reader = reader.clone();
            let scope = f.scoped(Visibility::Owner);
            let project = f.project.clone();
            let ready = ready.clone();
            let (release, released) = mpsc::sync_channel(1);
            releases.push(release);
            clients.push(threads.spawn(move || -> Result<(), String> {
                let mut snapshot = reader.snapshot(scope).map_err(|e| e.to_string());
                let observed = match snapshot.as_mut() {
                    Ok(snapshot) => match snapshot.project(project.clone()) {
                        Ok(Read::Present { value }) if matches!(value.current.body, EventBody::ProjectRegistered { project: ref stored, .. } if stored == &project) => Ok(()),
                        _ => Err("concurrent client did not observe the seeded project".to_string()),
                    },
                    Err(error) => Err(error.clone()),
                };
                ready.send(observed).map_err(|e| e.to_string())?;
                released.recv_timeout(Duration::from_secs(10)).map_err(|e| e.to_string())?;
                snapshot?.close().map_err(|e| e.to_string())
            }));
        }
        drop(ready);
        let observations = (0..8)
            .map(|_| received.recv_timeout(Duration::from_secs(10)))
            .collect::<Result<Vec<_>, _>>()?;
        let checks = (|| -> Check {
            for observed in observations {
                observed.map_err(|e| format!("eight-client read: {e}"))?;
            }
            assert_eq!(
                reader
                    .snapshot(f.scoped(Visibility::Owner))
                    .err()
                    .ok_or("ninth snapshot admitted")?
                    .code,
                StoreErrorCode::Backpressure
            );
            assert_eq!(
                reader
                    .credential([91; 32])
                    .err()
                    .ok_or("credential bypassed shared capacity")?
                    .code,
                StoreErrorCode::Backpressure
            );
            assert_eq!(
                reader
                    .owner_guard(&lease.files, budget(20, 32768, None)?)
                    .err()
                    .ok_or("owner guard bypassed shared capacity")?
                    .code,
                StoreErrorCode::Backpressure
            );
            Ok(())
        })();
        for release in releases {
            release.send(())?;
        }
        for client in clients {
            client.join().map_err(|_| "reader client panicked")??;
        }
        checks
    })?;
    let snapshots = (0..7)
        .map(|_| reader.clone().snapshot(f.scoped(Visibility::Owner)))
        .collect::<StoreResult<Vec<_>>>()?;
    assert!(matches!(reader.credential([91; 32])?, Read::Absent { .. }));
    assert_eq!(
        reader
            .owner_guard(&lease.files, budget(20, 32768, None)?)?
            .owners,
        vec![f.owner.clone()]
    );
    for snapshot in snapshots {
        snapshot.close()?;
    }
    Ok(())
}

/// Protects: failed snapshot/credential connections return their reservations,
/// so repeated real I/O failures cannot silently shrink the configured budget.
#[test]
fn failed_reads_release_all_eight_slots() -> Check {
    let f = Fixture::new()?;
    let (direct, lease) = f.direct()?;
    direct.close()?;
    let reader = present(SqliteFactory::open_reader_with_capacity(
        &f.options,
        capacity(8)?,
    )?)?;
    let path = f.options.state_directory.join("state.db");
    let retained = f.options.state_directory.join("state.retained");
    std::fs::rename(&path, &retained)?;
    for _ in 0..16 {
        assert_ne!(
            reader
                .snapshot(f.scoped(Visibility::Owner))
                .err()
                .ok_or("missing snapshot source accepted")?
                .code,
            StoreErrorCode::Backpressure
        );
        assert_ne!(
            reader
                .credential([92; 32])
                .err()
                .ok_or("missing credential source accepted")?
                .code,
            StoreErrorCode::Backpressure
        );
    }
    std::fs::rename(&retained, &path)?;
    let mut snapshots = Vec::new();
    for _ in 0..8 {
        snapshots.push(reader.clone().snapshot(f.scoped(Visibility::Owner))?);
    }
    assert_eq!(
        reader
            .snapshot(f.scoped(Visibility::Owner))
            .err()
            .ok_or("ninth snapshot admitted after failures")?
            .code,
        StoreErrorCode::Backpressure
    );
    for snapshot in snapshots {
        snapshot.close()?;
    }
    reader.owner_guard(&lease.files, budget(20, 32768, None)?)?;
    Ok(())
}
