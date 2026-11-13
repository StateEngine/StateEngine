//! Build fixed historical boundaries independently of the current schema.
use rusqlite::Connection;

pub fn through(version: u32) -> rusqlite::Result<Connection> {
    let migrations = [
        include_str!("../../migrations/001.sql"),
        include_str!("../../migrations/002.sql"),
        include_str!("../../migrations/003.sql"),
        include_str!("../../migrations/004.sql"),
        include_str!("../../migrations/005.sql"),
        include_str!("../../migrations/006.sql"),
    ];
    assert!((1..=6).contains(&version));
    let db = Connection::open_in_memory()?;
    for sql in migrations.iter().take(version as usize) {
        db.execute_batch(sql)?;
    }
    Ok(db)
}

/// Remove later objects without maintaining a list of future migrations.
/// A retained object can deliberately obstruct a migration under test.
pub fn remove_later_objects(
    db: &Connection,
    historical: &Connection,
    retained: &[&str],
) -> rusqlite::Result<()> {
    let foreign_keys: bool = db.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    db.execute_batch("PRAGMA foreign_keys=OFF")?;
    let result = (|| {
        // Drop indices/triggers before their tables implicitly remove them.
        let objects = db
            .prepare(
                "SELECT type,name FROM sqlite_schema
                 WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL
                 ORDER BY type='table',type,name",
            )?
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (kind, name) in objects {
            let existed: bool = historical.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type=?1 AND name=?2)",
                [&kind, &name],
                |row| row.get(0),
            )?;
            if !existed && !retained.contains(&name.as_str()) {
                assert!(matches!(
                    kind.as_str(),
                    "table" | "index" | "trigger" | "view"
                ));
                db.execute_batch(&format!("DROP {kind} \"{}\"", name.replace('"', "\"\"")))?;
            }
        }
        Ok(())
    })();
    if foreign_keys {
        db.execute_batch("PRAGMA foreign_keys=ON")?;
    }
    result
}
