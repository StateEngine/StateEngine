//! Process-wide SQLite heap observation for the isolated native probe.

pub fn sqlite_heap(reset_high_water: bool) -> Result<(i64, i64), i32> {
    let mut current = 0;
    let mut high_water = 0;
    // SAFETY: Both output pointers are valid and SQLite serializes this API.
    let status = unsafe {
        rusqlite::ffi::sqlite3_status64(
            rusqlite::ffi::SQLITE_STATUS_MEMORY_USED,
            &mut current,
            &mut high_water,
            i32::from(reset_high_water),
        )
    };
    if status != rusqlite::ffi::SQLITE_OK {
        return Err(status);
    }
    Ok((current, high_water))
}
