use se_store::*;
use se_types::Read;
use std::path::Path;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn context(error: &StoreError, path: &Path, stage: StoreIoStage) -> (Option<i32>, Option<i32>) {
    match &error.detail {
        StoreDetail::Io {
            path: relative,
            opened_path,
            stage: actual,
            sqlite_extended_code,
            native_os_code,
        } => {
            assert_eq!(relative, "state.db");
            assert_eq!(opened_path, &path.to_string_lossy());
            assert_eq!(*actual, stage);
            for text in [&error.cause, &error.remedy.text] {
                assert!(text.contains("state.db"), "missing path: {text}");
                assert!(
                    text.contains(&format!("stage={stage:?}")),
                    "missing stage: {text}"
                );
                if let Some(code) = sqlite_extended_code {
                    assert!(
                        text.contains(&format!("sqlite_extended_code={code}")),
                        "missing SQLite result: {text}"
                    );
                }
                if let Some(code) = native_os_code {
                    assert!(
                        text.contains(&format!("native_os_code={code}")),
                        "missing native result: {text}"
                    );
                }
            }
            (*sqlite_extended_code, *native_os_code)
        }
        detail => panic!("missing actual store I/O context: {detail:?}; error={error}"),
    }
}

/// Protects: measured absence never becomes an error or creates a database; a real inaccessible path keeps its native failure and open stage.
#[test]
fn absence_and_native_path_failure_are_distinct() -> Check {
    let f = Fixture::new()?;
    assert!(matches!(
        SqliteFactory::open_reader(&f.options)?,
        Read::Absent { .. }
    ));
    assert!(!f.options.state_directory.join("state.db").try_exists()?);
    let not_directory = f.home.join("regular-file");
    std::fs::write(&not_directory, b"retained path obstruction")?;
    let options = StoreOptions {
        state_directory: not_directory,
        ..f.options.clone()
    };
    let path = options.state_directory.join("state.db");
    let native = std::fs::symlink_metadata(&path)
        .err()
        .ok_or("fixture path was traversable")?
        .raw_os_error();
    let error = SqliteFactory::open_reader(&options)
        .err()
        .ok_or("native path failure became absence")?;
    assert_eq!(error.code, StoreErrorCode::Unreadable);
    assert_eq!(context(&error, &path, StoreIoStage::Open), (None, native));
    assert!(
        native.is_some(),
        "native filesystem refusal lost its own error code"
    );
    Ok(())
}

#[cfg(any(unix, windows))]
fn directory_link(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(target, link)
    }
}

#[cfg(any(unix, windows))]
fn dangling_parent(descendants: &Path) -> Check {
    let f = Fixture::new()?;
    let capacity = std::num::NonZeroU32::new(8).ok_or("zero reader capacity")?;
    let target = f.home.join("missing-link-target");
    let link = f.home.join("dangling-directory");
    directory_link(&target, &link)?;
    assert!(std::fs::symlink_metadata(&link)?.file_type().is_symlink());
    let options = StoreOptions {
        state_directory: link.join(descendants),
        ..f.options.clone()
    };
    let path = options.state_directory.join("state.db");
    let native = std::fs::symlink_metadata(&path)
        .err()
        .ok_or("dangling parent unexpectedly resolved")?
        .raw_os_error();
    assert!(native.is_some(), "fixture did not observe a native error");
    for result in [
        SqliteFactory::open_reader(&options),
        SqliteFactory::open_reader_with_capacity(&options, capacity),
    ] {
        let error = result
            .err()
            .ok_or("dangling directory parent became a measured-absent store")?;
        assert_eq!(error.code, StoreErrorCode::Unreadable);
        assert_eq!(context(&error, &path, StoreIoStage::Open), (None, native));
    }
    assert_eq!(std::fs::read_link(&link)?, target);
    assert_eq!(
        std::fs::symlink_metadata(&target)
            .err()
            .ok_or("read-only open created the dangling target")?
            .kind(),
        std::io::ErrorKind::NotFound,
        "read-only open created or replaced the dangling target"
    );
    Ok(())
}

/// Protects: a dangling immediate directory parent is an unreadable path, retaining the original state.db native error for both reader constructors.
#[cfg(any(unix, windows))]
#[test]
fn dangling_immediate_parent_retains_native_open_failure() -> Check {
    dangling_parent(Path::new(""))
}

/// Protects: missing descendants cannot hide a dangling directory ancestor as measured database absence.
#[cfg(any(unix, windows))]
#[test]
fn dangling_ancestor_above_missing_descendants_retains_native_open_failure() -> Check {
    dangling_parent(Path::new("missing/descendant"))
}

/// Protects: real missing directories and missing databases under valid directory links stay Absent without creating a store.
#[cfg(any(unix, windows))]
#[test]
fn absent_directories_and_valid_directory_links_keep_their_meaning() -> Check {
    let f = Fixture::new()?;
    let capacity = std::num::NonZeroU32::new(8).ok_or("zero reader capacity")?;
    let alias = f.home.join("valid-directory");
    directory_link(&f.options.state_directory, &alias)?;
    for directory in [
        f.home.join("missing"),
        f.home.join("missing/descendant"),
        alias.clone(),
        alias.join("missing/descendant"),
    ] {
        let options = StoreOptions {
            state_directory: directory.clone(),
            ..f.options.clone()
        };
        for result in [
            SqliteFactory::open_reader(&options),
            SqliteFactory::open_reader_with_capacity(&options, capacity),
        ] {
            assert!(matches!(result?, Read::Absent { .. }));
        }
        assert!(!directory.join("state.db").try_exists()?);
    }
    Ok(())
}

/// Protects: short damaged files and SQLite-detected non-databases report Corrupt, keep original bytes, and identify the stage that discovered corruption.
#[test]
fn corruption_preserves_early_and_sqlite_diagnostics() -> Check {
    for bytes in [b"broken database".to_vec(), vec![b'x'; 4096]] {
        let f = Fixture::new()?;
        let path = f.options.state_directory.join("state.db");
        std::fs::write(&path, &bytes)?;
        let error = SqliteFactory::open_reader(&f.options)
            .err()
            .ok_or("corruption became absence")?;
        assert_eq!(error.code, StoreErrorCode::Corrupt);
        let (sqlite, native) = context(
            &error,
            &path,
            if bytes.len() < 100 {
                StoreIoStage::Open
            } else {
                StoreIoStage::PragmaReadback
            },
        );
        if bytes.len() < 100 {
            assert_eq!(sqlite, None);
        } else {
            assert_eq!(
                sqlite.map(|code| code & 255),
                Some(rusqlite::ffi::SQLITE_NOTADB)
            );
        }
        assert_eq!(native, None);
        assert_eq!(std::fs::read(path)?, bytes);
    }
    Ok(())
}

/// Protects: failed reopening through an existing reader names SQLite CANTOPEN and does not leak finite snapshot slots or initialize a replacement database.
#[test]
fn snapshot_open_failure_retains_path_code_and_releases_slots() -> Check {
    let f = Fixture::new()?;
    let (direct, lease) = f.direct()?;
    drop(direct);
    drop(lease);
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let path = f.options.state_directory.join("state.db");
    let held = f.options.state_directory.join("retained.db");
    std::fs::rename(&path, &held)?;
    for _ in 0..3 {
        let error = reader
            .snapshot(f.scoped(Visibility::Owner))
            .err()
            .ok_or("missing database reopened")?;
        assert_eq!(error.code, StoreErrorCode::Unreadable);
        assert_eq!(
            context(&error, &path, StoreIoStage::Open)
                .0
                .map(|code| code & 255),
            Some(rusqlite::ffi::SQLITE_CANTOPEN)
        );
        assert!(!path.try_exists()?);
    }
    std::fs::rename(held, path)?;
    reader.snapshot(f.scoped(Visibility::Owner))?.close()?;
    Ok(())
}

/// Protects: a late header failure through a previously opened reader retains its exact header-readback stage and SQLite result.
#[test]
fn reader_header_failure_is_not_an_open_failure() -> Check {
    let f = Fixture::new()?;
    let (direct, lease) = f.direct()?;
    drop(direct);
    drop(lease);
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let path = f.options.state_directory.join("state.db");
    let db = rusqlite::Connection::open(&path)?;
    db.execute_batch("DROP TABLE store_info")?;
    drop(db);
    let error = reader
        .snapshot(f.scoped(Visibility::Owner))
        .err()
        .ok_or("missing header accepted")?;
    assert_eq!(
        context(&error, &path, StoreIoStage::HeaderReadback).0,
        Some(rusqlite::ffi::SQLITE_ERROR)
    );
    Ok(())
}

fn missing_messages() -> Result<Fixture, Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let (direct, lease) = f.direct()?;
    drop(direct);
    drop(lease);
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    db.execute_batch("DROP TABLE messages")?;
    drop(db);
    Ok(f)
}

/// Protects: a real page SQL failure retains read-snapshot context instead of becoming empty mail or an unlocated SQLite error.
#[test]
fn message_page_failure_retains_read_context() -> Check {
    let f = missing_messages()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
    let error = snapshot
        .messages(query(None, false), budget(10, 65536, None)?)
        .err()
        .ok_or("missing messages became empty page")?;
    assert_eq!(
        context(
            &error,
            &f.options.state_directory.join("state.db"),
            StoreIoStage::ReadSnapshot
        )
        .0,
        Some(rusqlite::ffi::SQLITE_ERROR)
    );
    snapshot.close()?;
    Ok(())
}

/// Protects: the count reader carries the same path/stage/SQLite facts as the page reader for the same real failed SQL source.
#[test]
fn message_count_failure_retains_read_context() -> Check {
    let f = missing_messages()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
    let error = snapshot
        .message_count(query(None, false))
        .err()
        .ok_or("missing messages became zero count")?;
    assert_eq!(
        context(
            &error,
            &f.options.state_directory.join("state.db"),
            StoreIoStage::ReadSnapshot
        )
        .0,
        Some(rusqlite::ffi::SQLITE_ERROR)
    );
    snapshot.close()?;
    Ok(())
}
