use super::*;

fn schema_objects(
    db: &rusqlite::Connection,
) -> Result<Vec<(String, String, String)>, rusqlite::Error> {
    db.prepare(
        "SELECT type,name,sql FROM sqlite_master
         WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY type,name",
    )?
    .query_map([], |row| {
        let sql: String = row.get(2)?;
        Ok((
            row.get(0)?,
            row.get(1)?,
            sql.replace("\"session_data\"", "session_data")
                .replace("\"turn_data\"", "turn_data"),
        ))
    })?
    .collect()
}

fn restore_schema_six(db: &rusqlite::Connection) -> Check {
    let historical = rusqlite::Connection::open_in_memory()?;
    for sql in [
        include_str!("../../migrations/001.sql"),
        include_str!("../../migrations/002.sql"),
        include_str!("../../migrations/003.sql"),
        include_str!("../../migrations/004.sql"),
        include_str!("../../migrations/005.sql"),
        include_str!("../../migrations/006.sql"),
    ] {
        historical.execute_batch(sql)?;
    }
    db.execute_batch(
        "DROP TABLE remote_message_attribution;
         DROP TABLE remote_grants; DROP INDEX session_data_agent_seq;
         DROP INDEX mark_data_message_seq; DROP INDEX work_mark_recipient_seq",
    )?;
    // Schema eight widened these constraints. Preserve the rows while restoring
    // the actual pre-upgrade tables, indices and immutable-history triggers.
    for table in ["session_data", "turn_data"] {
        let sql: String = historical.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )?;
        let prefix = format!("CREATE TABLE {table}(");
        assert!(sql.starts_with(&prefix));
        db.execute_batch(&sql.replacen(&prefix, &format!("CREATE TABLE {table}_old("), 1))?;
        db.execute_batch(&format!(
            "INSERT INTO {table}_old SELECT * FROM {table};
             DROP TABLE {table}; ALTER TABLE {table}_old RENAME TO {table}"
        ))?;
        let mut objects = historical.prepare(
            "SELECT sql FROM sqlite_master WHERE tbl_name=?1
             AND type IN ('index','trigger') AND sql IS NOT NULL ORDER BY type,name",
        )?;
        for sql in objects.query_map([table], |row| row.get::<_, String>(0))? {
            db.execute_batch(&sql?)?;
        }
    }
    assert_eq!(schema_objects(db)?, schema_objects(&historical)?);
    db.execute_batch("PRAGMA user_version=6")?;
    Ok(())
}

/// Protects: 49 — schema-five Atlas homes keep ordinary mail usable before channel migration.
#[test]
fn schema_five_mail_read_and_reply_do_not_query_absent_channel_tables() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let original = message()?;
    writer.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.b.clone()),
            original.clone(),
            "ordinary mail before channels",
            "old-schema-original",
        )?,
        &*lease,
    )?;
    writer.close()?;
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    restore_schema_six(&db)?;
    db.execute_batch("DROP TABLE channel_actions; DROP TABLE channel_outbox; DROP TABLE channel_updates; DROP TABLE channel_connections; PRAGMA user_version=5")?;
    drop(db);
    let mut writer = present(SqliteFactory::open_direct(&f.options, &*lease)?)?;
    assert_eq!(writer.info()?.schema_version, 5);
    writer.append(
        f.batch(
            f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.b.clone())),
            None,
            vec![EventBody::MessageRead {
                message: original.clone(),
                recipient: Actor::Agent(f.b.clone()),
            }],
        )?,
        &*lease,
    )?;
    let reply = message()?;
    let mut batch = f.send(
        Actor::Agent(f.b.clone()),
        Actor::Agent(f.a.clone()),
        reply.clone(),
        "ordinary linked reply",
        "old-schema-reply",
    )?;
    let EventBody::MessageSent { reply_to, .. } = &mut batch.events[0].body else {
        return Err("ordinary message fixture expected".into());
    };
    *reply_to = Some(original.clone());
    writer.append(batch, &*lease)?;
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    assert!(view.channel_reply_route(&original)?.is_none());
    assert!(view.channel_active()?.is_empty());
    assert!(view.channel_connections(0)?.items.is_empty());
    assert!(present(view.message(original)?)?.read.is_some());
    assert!(present(view.message(reply)?)?.read.is_none());
    view.close()?;
    writer.close()?;
    Ok(())
}

/// Protects: R0 appends its migration after Atlas/channels without replacing their state.
#[test]
fn schema_six_remote_upgrade_preserves_paired_channels_and_mail() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let current_schema = writer.info()?.schema_version;
    let channel = paired(&f, &mut writer, &lease)?;
    let original = message()?;
    writer.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.b.clone()),
            original.clone(),
            "ordinary mail across remote migration",
            "before-remote-migration",
        )?,
        &*lease,
    )?;
    let mut before = writer.snapshot(f.scoped(Visibility::Owner))?;
    let prior_channels = before.channel_active()?;
    assert_eq!(prior_channels.len(), 1);
    assert_eq!(prior_channels[0].id, channel.id);
    assert!(matches!(prior_channels[0].pairing, Pairing::Paired { .. }));
    before.close()?;
    writer.close()?;
    drop(lease);
    // Recreate the landed schema-six boundary, with its real data retained.
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    restore_schema_six(&db)?;
    drop(db);
    let lease = Lease::acquire_with_backup_ports(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(f.store.clone()),
        true,
    )?;
    let host = present(SqliteFactory::open_host(&f.options, &*lease)?)?;
    assert_eq!(host.info()?.schema_version, current_schema);
    let mut view = host.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(view.channel_active()?, prior_channels);
    assert_eq!(
        present(view.message(original)?)?.sender,
        Actor::Agent(f.a.clone())
    );
    view.close()?;
    drop(host);
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    let count: i64 = db.query_row("SELECT count(*) FROM remote_grants", [], |row| row.get(0))?;
    assert_eq!(count, 0);
    assert!(
        db.query_row("SELECT count(*) FROM atlas_resume_roots", [], |row| row
            .get::<_, i64>(0))
            .is_ok()
    );
    Ok(())
}
