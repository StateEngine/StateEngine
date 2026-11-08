use super::*;

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
    db.execute_batch("DROP TABLE remote_message_attribution; DROP TABLE remote_grant_targets; DROP TABLE remote_grants; DROP TABLE remote_invitations; DROP INDEX session_data_agent_seq; DROP INDEX mark_data_message_seq; DROP INDEX work_mark_recipient_seq; PRAGMA user_version=6")?;
    drop(db);
    let lease = Lease::acquire(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(f.store.clone()),
    )?;
    let host = present(SqliteFactory::open_host(&f.options, &*lease)?)?;
    assert_eq!(host.info()?.schema_version, 7);
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
