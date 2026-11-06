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
