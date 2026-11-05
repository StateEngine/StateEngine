use super::*;
use se_atlas::{query::RecordReader, rank};
use se_types::{Read, code::*};
fn outside(db: &CacheConnection<'_>) -> Result<rusqlite::Connection, Box<dyn Error>> {
    let id = db.identity();
    Ok(rusqlite::Connection::open_with_flags(
        id.scope
            .registration
            .cache
            .directory
            .join("epochs")
            .join(id.epoch.as_str())
            .join("atlas.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?)
}
pub(super) fn check(db: &CacheConnection<'_>) -> Check {
    let out = outside(db)?;
    for query in [
        "SELECT count(*) FROM symbols s WHERE coalesce((SELECT inbound_resolved FROM activity WHERE target_kind='symbol' AND target_key=s.key),0)!=(SELECT count(*) FROM refs r WHERE r.target=s.id AND r.accuracy!='NameOnly')",
        "SELECT count(*) FROM files f WHERE coalesce((SELECT inbound_resolved FROM activity WHERE target_kind='file' AND target_key=f.key),0)!=(SELECT count(*) FROM refs r JOIN symbols s ON s.id=r.target WHERE s.file=f.id AND r.accuracy!='NameOnly')",
    ] {
        assert_eq!(
            out.query_row(query, [], |r| r.get::<_, i64>(0))?,
            0,
            "derived counts disagree with actual graph: {query}"
        );
    }
    Ok(())
}
struct NoRecords;
impl RecordReader for NoRecords {
    fn read(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: Option<&QueryText>,
    ) -> se_atlas::errors::AtlasResult<Read<RecordHit>> {
        panic!("unexpected record read")
    }
    fn literal_read(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: &QueryText,
    ) -> se_atlas::errors::AtlasResult<Read<RecordHit>> {
        panic!("unexpected record literal read")
    }
    fn body(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: Option<&QueryText>,
    ) -> se_atlas::errors::AtlasResult<Read<HitBody>> {
        panic!("unexpected record body read")
    }
}
pub(super) fn rank_and_touch_absence(db: &CacheConnection<'_>) -> Check {
    let out = outside(db)?;
    assert_eq!(
        out.query_row(
            "SELECT count(*) FROM activity WHERE last_touch_unix_ms IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    let viewer = AtlasPrincipal::Human(se_types::HumanId::from_parts(1, [22; 10])?);
    let (key, count): (Vec<u8>, i64) = out.query_row(
        "SELECT s.key,a.inbound_resolved FROM symbols s JOIN activity a ON a.target_kind='symbol' AND a.target_key=s.key WHERE a.inbound_resolved>0 LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let read = || {
        db.read(deadline(), |sql| {
            rank::activity(
                sql,
                "symbol",
                &key,
                rank::ActivityQuery {
                    project: &db.identity().scope.registration.project,
                    viewer: &viewer,
                    records: &NoRecords,
                    now: Some(1000),
                },
            )
        })
    };
    let result = read()?;
    assert_eq!(
        result.last, None,
        "reference popularity fabricated a touch time"
    );
    assert!((result.score - 0.3 * (1.0 + count as f64).log2()).abs() < 1e-9);
    let (file_key, file_count): (Vec<u8>, i64) = out.query_row(
        "SELECT f.key,a.inbound_resolved FROM files f JOIN activity a ON a.target_kind='file' AND a.target_key=f.key WHERE a.inbound_resolved>0 LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let file_activity = db.read(deadline(), |sql| {
        rank::activity(
            sql,
            "file",
            &file_key,
            rank::ActivityQuery {
                project: &db.identity().scope.registration.project,
                viewer: &viewer,
                records: &NoRecords,
                now: Some(1000),
            },
        )
    })?;
    assert_eq!(file_activity.last, None);
    assert!((file_activity.score - 0.3 * (1.0 + file_count as f64).log2()).abs() < 1e-9);
    // The public record feed, including removal and restricted replacement,
    // must leave popularity intact and an absent last touch absent.
    let project = db.identity().scope.registration.project.clone();
    let record = RecordKey::new("record-count-test")?;
    let event = se_types::EventId::from_parts(1, [23; 10])?;
    let restricted_event = se_types::EventId::from_parts(2, [24; 10])?;
    let through = se_types::EventId::from_parts(3, [25; 10])?;
    let feed = RecordFeed {
        project: project.clone(),
        after: None,
        through: event.clone(),
        complete: true,
        changes: vec![RecordFeedChange::Upsert(FeedRecord {
            pointer: RecordPointer {
                key: record.clone(),
                kind: RecordKind::Message,
                source_event: event.clone(),
            },
            project: project.clone(),
            actor: None,
            occurred_unix_ms: 777,
            title: "reference".into(),
            visibility: RecordVisibility::Project,
            body: String::new(),
            body_truncated: false,
            mentions: vec![MentionTarget::Symbol(SymbolId(key.as_slice().try_into()?))],
        })],
    };
    se_atlas::records::apply(db, &feed, deadline())?;
    assert_eq!(
        out.query_row(
            "SELECT last_touch_unix_ms FROM activity WHERE target_kind='symbol' AND target_key=?1 AND last_touch_unix_ms IS NOT NULL",
            [&key],
            |r| r.get::<_, i64>(0)
        )?,
        777
    );
    let mut restricted = feed;
    restricted.after = Some(event);
    restricted.through = restricted_event.clone();
    let RecordFeedChange::Upsert(changed_record) = &mut restricted.changes[0] else {
        unreachable!()
    };
    changed_record.visibility = RecordVisibility::Restricted { audience: None };
    changed_record.pointer.source_event = restricted_event.clone();
    se_atlas::records::apply(db, &restricted, deadline())?;
    assert_eq!(
        out.query_row(
            "SELECT count(*) FROM activity WHERE target_kind='symbol' AND target_key=?1 AND last_touch_unix_ms IS NOT NULL",
            [&key],
            |r| r.get::<_, i64>(0)
        )?,
        0,
        "restricted-only touch manufactured a public timestamp"
    );
    se_atlas::records::apply(
        db,
        &RecordFeed {
            project: project.clone(),
            after: Some(restricted_event),
            through: through.clone(),
            complete: true,
            changes: vec![RecordFeedChange::Remove {
                project: project.clone(),
                key: record,
            }],
        },
        deadline(),
    )?;
    assert_eq!(
        out.query_row(
            "SELECT count(*) FROM activity WHERE target_kind='symbol' AND target_key=?1 AND last_touch_unix_ms IS NOT NULL",
            [&key],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    let result = read()?;
    assert_eq!(result.last, None);
    assert!((result.score - 0.3 * (1.0 + count as f64).log2()).abs() < 1e-9);
    let before:(i64,i64,i64)=out.query_row("SELECT (SELECT sum(inbound_resolved) FROM activity WHERE target_kind='file'),(SELECT sum(inbound_resolved) FROM activity WHERE target_kind='symbol'),(SELECT count(*) FROM refs)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    let target_file: i64 = out.query_row("SELECT file FROM symbols WHERE key=?1", [&key], |r| {
        r.get(0)
    })?;
    let failure: se_atlas::errors::AtlasResult<()> = db.write(
        2_000_000,
        Instant::now() + Duration::from_millis(100),
        |sql| {
            se_atlas::cache::write::clear_semantics(sql, target_file)?;
            std::thread::sleep(Duration::from_millis(110));
            Ok(())
        },
    );
    assert!(matches!(
        failure
            .err()
            .ok_or("expired graph update committed")?
            .body
            .detail(),
        se_types::Detail::DeadlineExceeded(_)
    ));
    let after:(i64,i64,i64)=out.query_row("SELECT (SELECT sum(inbound_resolved) FROM activity WHERE target_kind='file'),(SELECT sum(inbound_resolved) FROM activity WHERE target_kind='symbol'),(SELECT count(*) FROM refs)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    assert_eq!(
        before, after,
        "deadline rollback separated counts from graph authority"
    );
    check(db)
}
