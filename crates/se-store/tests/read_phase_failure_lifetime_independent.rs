//! Independent public-surface judge for the failed read-phase lifetime.
//! The `read_phase` failure contract (slot returned, connection closed)
//! landed with 5b's single-open e60e45191b3034ea1d0676ee2ac19b37fbebf35d;
//! this judge is built at 8ddbe0dd0c018e661e8d0b006c3f33f9b0679cf7, landed
//! rust-se main, rebased from eef5a356 where the contract is unchanged.
//!
//! Prime 2026-11-03: "add a small judge that fails BEGIN and then checks
//! reader capacity, to pin the slot-before-connection order."
//!
//! A failed phase open must (1) return its shared slot — repeated attempts
//! see the real failure, never Backpressure — and (2) close the failed
//! SQLite connection, observed from outside through the kernel
//! file-descriptor table on Linux. A replaced file fails at the pragma
//! readback, before BEGIN, and the stage is asserted so the judge cannot
//! drift to a different refusal. Exhausted capacity must refuse with
//! Backpressure before any connection attempt, pinning the
//! slot-before-connection order Prime requested.

use se_store::*;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::{fs, num::NonZeroU32};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn capacity(value: u32) -> Result<NonZeroU32, Box<dyn std::error::Error>> {
    NonZeroU32::new(value).ok_or_else(|| "zero capacity".into())
}

fn db_path(f: &Fixture) -> std::path::PathBuf {
    f.options.state_directory.join("state.db")
}

#[cfg(target_os = "linux")]
fn open_db_handles(path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    let canonical = fs::canonicalize(path)?;
    let mut handles = 0;
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        if target == canonical {
            handles += 1;
        }
    }
    Ok(handles)
}

/// Protects: a failed phase open (a replaced database file refuses its
/// pragma readback before BEGIN) returns the shared slot and closes its
/// connection, so the full configured capacity is available again after
/// restore. The failed stage is asserted, not assumed.
#[test]
fn failed_phase_open_returns_slot_and_closes_connection() -> Check {
    let f = Fixture::new()?;
    let (writer, _lease) = f.direct()?;
    let db = db_path(&f);
    let original = fs::read(&db)?;
    writer.close()?;
    let reader = present(SqliteFactory::open_reader_with_capacity(
        &f.options,
        capacity(8)?,
    )?)?;
    fs::write(&db, b"judge-replaced-database-not-sqlite")?;
    for attempt in 1..=16 {
        let error = reader
            .read_phase()
            .err()
            .ok_or("failed phase open admitted a phase")?;
        assert_eq!(
            error.code,
            StoreErrorCode::Corrupt,
            "attempt {attempt}: {error}"
        );
        match &error.detail {
            StoreDetail::Io { stage, .. } => assert_eq!(
                *stage,
                StoreIoStage::PragmaReadback,
                "attempt {attempt}: the replaced file fails at the pragma readback: {error}"
            ),
            other => panic!(
                "attempt {attempt}: expected the pragma-readback IO failure, got {other:?}: {error}"
            ),
        }
        #[cfg(target_os = "linux")]
        assert_eq!(
            open_db_handles(&db)?,
            0,
            "attempt {attempt}: failed phase open retained a connection"
        );
    }
    fs::write(&db, &original)?;
    let mut phases = Vec::new();
    for _ in 0..8 {
        phases.push(reader.read_phase()?);
    }
    assert_eq!(
        reader
            .read_phase()
            .err()
            .ok_or("ninth phase admitted after failures")?
            .code,
        StoreErrorCode::Backpressure
    );
    for phase in phases {
        phase.close()?;
    }
    Ok(())
}

/// Protects: once every shared slot is held, the next read_phase must
/// refuse with Backpressure before opening a connection, even when the
/// database file would fail any connection attempt. A connect-before-slot
/// order would return the file's Corrupt instead, or leak a connection.
#[test]
fn exhausted_capacity_backpressures_before_any_connection() -> Check {
    let f = Fixture::new()?;
    let (writer, _lease) = f.direct()?;
    let db = db_path(&f);
    let original = fs::read(&db)?;
    writer.close()?;
    let reader = present(SqliteFactory::open_reader_with_capacity(
        &f.options,
        capacity(8)?,
    )?)?;
    let mut phases = Vec::new();
    for _ in 0..8 {
        phases.push(reader.read_phase()?);
    }
    #[cfg(target_os = "linux")]
    let before = open_db_handles(&db)?;
    #[cfg(target_os = "linux")]
    assert_eq!(
        before, 8,
        "each live phase holds one connection to the database"
    );
    // Replace the database in place: any new connection now fails at the
    // pragma readback before BEGIN, so a Backpressure answer proves no
    // connection was attempted.
    fs::write(&db, b"judge-replaced-database-not-sqlite")?;
    let error = reader
        .read_phase()
        .err()
        .ok_or("ninth phase admitted after the slots were exhausted")?;
    assert_eq!(
        error.code,
        StoreErrorCode::Backpressure,
        "exhausted capacity must refuse before any connection attempt: {error}"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        open_db_handles(&db)?,
        before,
        "the exhausted refusal opened a connection to the replaced database"
    );
    fs::write(&db, &original)?;
    for phase in phases {
        phase.close()?;
    }
    Ok(())
}
