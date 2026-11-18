//! Derive the latest empty schema from the same SQL that upgrades saved stores.
use rusqlite::Connection;
use std::{env, error::Error, fmt::Write, fs, path::PathBuf};

#[path = "src/migration_plan.rs"]
mod migration_plan;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=migrations");
    println!("cargo:rerun-if-changed=src/migration_plan.rs");
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing Cargo OUT_DIR")?);
    let db = Connection::open_in_memory()?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; BEGIN EXCLUSIVE;")?;
    db.execute_batch(include_str!("migrations/001.sql"))?;
    for step in &migration_plan::STEPS {
        db.execute_batch(step.sql).map_err(|error| {
            format!(
                "schema migration {} (table rebuild: {}) failed: {error}",
                step.version, step.table_rebuild
            )
        })?;
    }
    db.execute_batch("COMMIT")?;
    fs::write(output.join("fresh-schema.sql"), schema(&db)?)?;
    Ok(())
}

fn schema(db: &Connection) -> Result<String, Box<dyn Error>> {
    let app: u32 = db.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: u32 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let mut output = format!("PRAGMA application_id={app};\nPRAGMA user_version={version};\n");
    let mut statement = db.prepare(
        "SELECT type, name, sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY rowid",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let kind: String = row.get(0)?;
        let name: String = row.get(1)?;
        if kind == "table" {
            let quoted = name.replace('"', "\"\"");
            let populated: bool = db.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM \"{quoted}\")"),
                [],
                |value| value.get(0),
            )?;
            if populated {
                return Err(format!(
                    "fresh migration populated {name}; schema alone would lose data"
                )
                .into());
            }
        }
        // SQLite creates its own internal objects when their owning DDL runs.
        if !name.starts_with("sqlite_") {
            let sql: String = row.get(2)?;
            writeln!(output, "{sql};")?;
        }
    }
    Ok(output)
}
