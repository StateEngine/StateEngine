//! Schema 12 migration: row preservation, source-contact backfill, atomicity.
use super::*;
use se_types::remote::RemoteAgentAddress;

type Check = Result<(), Box<dyn std::error::Error>>;
const HOST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PROJECT: &str = "prj_01a1d329-59c2-7a14-a9fa-1910352a3eaa";
const AGENT_A: &str = "ag_01a1d329-59c2-7a14-a9fa-1910352a3eab";
const AGENT_B: &str = "ag_01a1d329-59c2-7a14-a9fa-1910352a3eac";

fn step(version: u32) -> Result<&'static Step, &'static str> {
    STEPS
        .iter()
        .find(|step| step.version == version)
        .ok_or("migration step is not registered")
}

fn version(db: &Connection) -> Result<i64, rusqlite::Error> {
    db.query_row("PRAGMA user_version", [], |r| r.get(0))
}

fn schema_eleven(db: &Connection) -> Check {
    db.execute_batch(include_str!("../../migrations/001.sql"))?;
    for step in STEPS.iter().filter(|step| step.version <= 11) {
        apply_step(db, step)?;
    }
    assert_eq!(version(db)?, 11);
    // Rows below stand in for events this fixture does not build.
    db.execute_batch("PRAGMA foreign_keys=OFF")?;
    Ok(())
}

fn attribution(
    db: &Connection,
    seq: i64,
    message: u8,
    source: Option<(&str, &str)>,
) -> Result<(), rusqlite::Error> {
    let source = source.map_or(String::new(), |(host, agent)| {
        format!(
            r#","source":{{"host":"{host}","project":"{PROJECT}","agent":"{agent}","session":"ses_x","generation":1}}"#
        )
    });
    let facts = format!(r#"{{"attribution":{{"host":"{HOST}"{source}}}}}"#);
    db.execute(
        "INSERT INTO remote_message_attribution(event_seq,project_id,message_id,grant_id,facts) VALUES(?,?,?,?,?)",
        rusqlite::params![seq, vec![9u8; 16], vec![message; 16], vec![7u8; 16], facts],
    )?;
    Ok(())
}

fn column(db: &Connection, sql: &str) -> Result<Vec<String>, rusqlite::Error> {
    db.prepare(sql)?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect()
}

fn every_row(db: &Connection, table: &str) -> Result<Vec<String>, rusqlite::Error> {
    let columns = column(
        db,
        &format!("SELECT name FROM pragma_table_info('{table}') ORDER BY cid"),
    )?;
    let expression = columns
        .iter()
        .map(|c| format!("quote({c})"))
        .collect::<Vec<_>>()
        .join("||'|'||");
    column(db, &format!("SELECT {expression} FROM {table} ORDER BY 1"))
}

fn objects(db: &Connection) -> Result<Vec<String>, rusqlite::Error> {
    column(db, "SELECT type||' '||name FROM sqlite_master ORDER BY 1")
}

/// Protects: schema 12 keeps every earlier row and backfills one contact per source address.
#[test]
fn schema_twelve_preserves_rows_and_backfills_contacts_in_the_stored_address_form() -> Check {
    let db = Connection::open_in_memory()?;
    schema_eleven(&db)?;
    attribution(&db, 5, 1, Some((HOST, AGENT_A)))?;
    attribution(&db, 3, 2, Some((HOST, AGENT_A)))?;
    attribution(&db, 8, 3, Some((HOST, AGENT_B)))?;
    attribution(&db, 9, 4, None)?;
    let mut before = Vec::new();
    for table in column(
        &db,
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
    )? {
        before.push((every_row(&db, &table)?, table));
    }
    apply_step(&db, step(12)?)?;
    assert_eq!(version(&db)?, 12);
    for (rows, table) in &before {
        assert_eq!(&every_row(&db, table)?, rows, "{table} changed");
    }
    let contacts = db
        .prepare("SELECT address,first_seq FROM remote_source_contacts ORDER BY first_seq")?
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(contacts.len(), 2, "sourceless mail makes no contact");
    assert_eq!(contacts[0].1, 3, "earliest event per address");
    assert_eq!(contacts[1].1, 8);
    for (address, _) in &contacts {
        let typed: RemoteAgentAddress = serde_json::from_str(address)?;
        assert_eq!(&serde_json::to_string(&typed)?, address);
    }
    Ok(())
}

/// Protects: a failing schema step leaves the store entirely at the old schema.
#[test]
fn failed_schema_twelve_leaves_the_old_store_untouched() -> Check {
    let db = Connection::open_in_memory()?;
    schema_eleven(&db)?;
    attribution(&db, 5, 1, Some((HOST, AGENT_A)))?;
    let before_objects = objects(&db)?;
    let before_rows = every_row(&db, "remote_message_attribution")?;
    let planted: &'static str = Box::leak(
        format!(
            "{}\nINSERT INTO table_that_is_absent VALUES(1);",
            step(12)?.sql
        )
        .into_boxed_str(),
    );
    let failing = Step {
        version: 12,
        sql: planted,
        table_rebuild: false,
    };
    let Err(error) = apply_step(&db, &failing) else {
        return Err("a failing schema step reported success".into());
    };
    assert!(error.cause.contains("rolled back"), "{}", error.cause);
    assert!(db.is_autocommit());
    assert_eq!(version(&db)?, 11);
    assert_eq!(objects(&db)?, before_objects);
    assert_eq!(every_row(&db, "remote_message_attribution")?, before_rows);
    Ok(())
}
