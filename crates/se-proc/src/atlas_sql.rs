//! Per-connection native SQLite allocation setup, confined to Atlas adapters.
//! This changes no global SQLite settings or authoritative-store connection.
pub fn configure(connection: &rusqlite::Connection) -> rusqlite::Result<()> {
    // SAFETY: the borrowed Connection owns a live handle, is not shared across
    // threads, and SQLite itself returns BUSY if lookaside is currently in use.
    // A null buffer with zero size/count frees its internal lookaside allocation;
    // no caller-owned storage or pointer outlives this synchronous call.
    let result = unsafe {
        rusqlite::ffi::sqlite3_db_config(
            connection.handle(),
            rusqlite::ffi::SQLITE_DBCONFIG_LOOKASIDE,
            std::ptr::null_mut::<std::ffi::c_void>(),
            0 as std::ffi::c_int,
            0 as std::ffi::c_int,
        )
    };
    if result != rusqlite::ffi::SQLITE_OK {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(result),
            Some("Atlas connection lookaside could not be disabled".into()),
        ));
    }
    Ok(())
}

/// Keep a short-lived Atlas connection's close from checkpointing the entire
/// WAL. The maintenance owner checkpoints inside its bounded work instead.
pub fn retain_wal(connection: &rusqlite::Connection) -> rusqlite::Result<()> {
    // SAFETY: this connection owns its live SQLite handle and is not shared
    // across threads. The option changes only this handle, and a null output
    // pointer requests no caller-owned result storage.
    let result = unsafe {
        rusqlite::ffi::sqlite3_db_config(
            connection.handle(),
            rusqlite::ffi::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            1 as std::ffi::c_int,
            std::ptr::null_mut::<std::ffi::c_int>(),
        )
    };
    if result != rusqlite::ffi::SQLITE_OK {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(result),
            Some("Atlas maintenance could not retain its WAL between work slices".into()),
        ));
    }
    Ok(())
}
