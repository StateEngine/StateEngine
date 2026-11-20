//! Git ingestion and immutable retry consumers.
use super::*;
struct NoRecords;
impl se_atlas::query::RecordReader for NoRecords {
    fn read(
        &self,
        _: &se_types::ProjectId,
        _: &se_types::code::AtlasPrincipal,
        _: &se_types::code::RecordPointer,
        _: Option<&se_types::code::QueryText>,
    ) -> AtlasResult<se_types::Read<se_types::code::RecordHit>> {
        Err(cache_error("unexpected record read"))
    }
    fn literal_read(
        &self,
        _: &se_types::ProjectId,
        _: &se_types::code::AtlasPrincipal,
        _: &se_types::code::RecordPointer,
        _: &se_types::code::QueryText,
    ) -> AtlasResult<se_types::Read<se_types::code::RecordHit>> {
        Err(cache_error("unexpected literal read"))
    }
    fn body(
        &self,
        _: &se_types::ProjectId,
        _: &se_types::code::AtlasPrincipal,
        _: &se_types::code::RecordPointer,
        _: Option<&se_types::code::QueryText>,
    ) -> AtlasResult<se_types::Read<se_types::code::HitBody>> {
        Err(cache_error("unexpected body read"))
    }
}
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn history_feed_filters_secrets_before_all_derivations_and_retries_immutably() -> Check {
    use se_atlas::history::*;
    use se_atlas_cold::apply::ingest;
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    db.write(131072, deadline(), |sql| {
        sql.prepare("INSERT INTO files(key,path,path_key,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,?2,?2,'{}',0,0,0)")?
            .execute(rusqlite::params![[0u8;16].as_slice(),"src/ok.rs"]).map_err(cache_error)?;
        sql.prepare("UPDATE files SET coverage_json='\"Indexed\"' WHERE path='src/ok.rs'")?.execute([]).map_err(cache_error)?;
        sql.prepare("INSERT INTO files(key,path,path_key,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,'src/aa.rs','src/aa.rs','\"Indexed\"',0,0,0)")?
            .execute([[2u8;16].as_slice()]).map_err(cache_error)?;
        // A stale cache row must not let denied paths bypass producer policy.
        sql.prepare("INSERT INTO files(key,path,path_key,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,?2,?2,'{}',0,0,0)")?
            .execute(rusqlite::params![[1u8;16].as_slice(),".env"]).map_err(cache_error)?;
        Ok(())
    })?;
    let a = "a".repeat(40);
    let b = "b".repeat(40);
    let feed = HistoryFeed {
        project: s.identity.scope.registration.project.clone(),
        root: s.identity.scope.registration.root.clone(),
        expected: None,
        bound: HistoryBound {
            head: a.clone(),
            oldest: Some(b.clone()),
            next: None,
            limit: HistoryLimit::Complete,
        },
        observed_unix_ms: 10,
        commits: vec![
            Commit {
                oid: a.clone(),
                parent: Some(b.clone()),
                author_unix_ms: 1,
                author: "Public author".into(),
                subject: "Public commit".into(),
                paths: vec![RelativePath::new("src/ok.rs")?, RelativePath::new(".env")?],
                paths_note: None,
                allowed_paths: None,
            },
            Commit {
                oid: b,
                parent: None,
                author_unix_ms: 2,
                author: "secret-only-author-DO-NOT-STORE".into(),
                subject: "secret-only-subject-DO-NOT-STORE".into(),
                paths: vec![RelativePath::new(".env")?],
                paths_note: None,
                allowed_paths: None,
            },
        ],
    };
    let receipt = ingest(&mut db, &feed, deadline())?;
    assert_eq!(
        (receipt.changed, receipt.denied_paths, receipt.generation.0),
        (1, 2, 1)
    );
    let outside = rusqlite::Connection::open(f.dir.join(s.identity.epoch.as_str()))?;
    for (sql, want) in [
        ("SELECT count(*) FROM commits", 1),
        (
            "SELECT count(*) FROM mentions WHERE source_kind='commit' AND target_key=zeroblob(16)",
            1,
        ),
        (
            "SELECT count(*) FROM mentions WHERE target_key!=zeroblob(16)",
            0,
        ),
        ("SELECT count(*) FROM touches WHERE target_kind='commit'", 1),
        (
            "SELECT count(*) FROM activity WHERE target_kind='commit'",
            1,
        ),
        ("SELECT count(*) FROM authors", 0),
        ("SELECT sum(last_author_generation) FROM files", 0),
        (
            "SELECT count(*) FROM commits WHERE author LIKE '%DO-NOT-STORE%' OR subject LIKE '%DO-NOT-STORE%'",
            0,
        ),
    ] {
        assert_eq!(
            outside.query_row(sql, [], |r| r.get::<_, i64>(0))?,
            want,
            "{sql}"
        );
    }
    use se_types::code::*;
    let _clock = super::test_clock::control();
    let mut reader = se_atlas::query::QueryReader::new(
        &mut db,
        se_atlas::query::ReaderContext {
            memory: None,
            viewer: AtlasPrincipal::Human(se_types::HumanId::from_parts(1, [8; 10])?),
            records: &NoRecords,
            source: None,
            hostless: false,
            epoch_retired: false,
            now_unix_ms: Some(10),
            record_feed_current: true,
        },
    );
    let mut query = FindQuery {
        query: QueryText::new(&a)?,
        kind: SearchKind::Commit,
        scope: SearchScope {
            paths: vec![],
            languages: vec![],
        },
        next: None,
        budget: Validate.query_budget(10, 16384)?,
        mode: Some(SearchMode::Exact),
        order: SearchOrder::Relevance,
        full: false,
        regex: false,
    };
    let found = reader.find(&query)?;
    assert!(matches!(found.data,se_types::Read::Present{value} if value.page.items().len()==1));
    query.query = QueryText::new("src/")?;
    query.kind = SearchKind::Path;
    query.mode = Some(SearchMode::Literal);
    let se_types::Read::Present { value } = reader.find(&query)?.data else {
        return Err("file search unavailable".into());
    };
    assert_eq!(value.page.items().len(), 2);
    let HitTarget::Code(first) = &value.page.items()[0].target else {
        return Err("file search returned another kind".into());
    };
    assert_eq!(
        first.pointer.path.as_str(),
        "src/ok.rs",
        "Git activity must outrank the lexically earlier untouched file"
    );
    assert_eq!(value.page.items()[0].reason.last_touch_unix_ms, Some(1));
    assert_eq!(
        value.page.items()[0].reason.edited_by,
        None,
        "Git names are not Atlas identities"
    );
    assert!(ingest(&mut db, &feed, deadline())?.replay);
    let mut conflicting = feed.clone();
    conflicting.commits[0].subject = "changed immutable commit".into();
    assert!(ingest(&mut db, &conflicting, deadline()).is_err());
    assert_eq!(
        outside.query_row("SELECT index_generation FROM meta", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    assert_eq!(
        outside.query_row("SELECT subject FROM commits", [], |r| r.get::<_, String>(0))?,
        "Public commit"
    );
    assert_eq!(
        outside.query_row(
            "SELECT count(*) FROM touches WHERE target_kind='file' AND source_commit IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        1
    );
    assert_eq!(
        outside.query_row(
            "SELECT count(*) FROM touches WHERE actor IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    db.write(4_000_000, deadline(), |sql| {
        sql.prepare("WITH RECURSIVE n(x) AS (VALUES(2) UNION ALL SELECT x+1 FROM n WHERE x<20001) INSERT INTO commits(id,oid,author_unix_ms,author,subject) SELECT x,CAST(printf('%040d',x) AS BLOB),x,'author','subject' FROM n")?.execute([]).map_err(cache_error)?;
        Ok(())
    })?;
    assert!(!prune::commits(&mut db, 1, deadline())?);
    assert_eq!(
        outside.query_row(
            "SELECT count(*) FROM touches WHERE target_kind='file'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(
        outside.query_row(
            "SELECT count(*) FROM activity WHERE target_kind='file'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}
#[test]
fn history_cursor_scope_and_quantum_refusals_preserve_the_previous_generation() -> Check {
    use se_atlas::history::*;
    use se_atlas_cold::apply::ingest;
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    let a = "a".repeat(40);
    let feed = HistoryFeed {
        project: s.identity.scope.registration.project.clone(),
        root: s.identity.scope.registration.root.clone(),
        expected: None,
        bound: HistoryBound {
            head: a.clone(),
            oldest: Some(a.clone()),
            next: None,
            limit: HistoryLimit::Complete,
        },
        observed_unix_ms: 1,
        commits: vec![Commit {
            oid: a,
            parent: None,
            author_unix_ms: 1,
            author: "author".into(),
            subject: "root".into(),
            paths: vec![RelativePath::new("src/ok.rs")?],
            paths_note: None,
            allowed_paths: None,
        }],
    };
    ingest(&mut db, &feed, deadline())?;
    let mut stale = feed.clone();
    let next = "c".repeat(40);
    stale.bound.head = next.clone();
    stale.bound.oldest = Some(next.clone());
    stale.commits[0].oid = next;
    assert!(ingest(&mut db, &stale, deadline()).is_err());
    let mut wrong_root = feed.clone();
    wrong_root.root = RootId::from_parts(1, [9; 10])?;
    assert!(ingest(&mut db, &wrong_root, deadline()).is_err());
    let mut oversized = feed.clone();
    oversized.commits[0].paths = (0..33)
        .map(|n| RelativePath::new(format!("src/file-{n}.rs")))
        .collect::<Result<_, _>>()?;
    assert!(ingest(&mut db, &oversized, deadline()).is_err());
    db.read(deadline(), |sql| {
        let generation: i64 = sql
            .prepare("SELECT index_generation FROM meta")?
            .query_row([], |r| r.get(0))
            .map_err(cache_error)?;
        assert_eq!(generation, 1);
        let count: i64 = sql
            .prepare("SELECT count(*) FROM commits")?
            .query_row([], |r| r.get(0))
            .map_err(cache_error)?;
        assert_eq!(count, 1);
        Ok(())
    })?;
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one judge covers feed, replay, validation and serde round-trip"
)]
fn history_window_degrades_one_commit_and_keeps_the_rest() -> Check {
    use se_atlas::history::*;
    use se_atlas_cold::apply::ingest;
    use se_types::code::*;
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    db.write(131072, deadline(), |sql| {
        sql.prepare("INSERT INTO files(key,path,path_key,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,?2,?2,'\"Indexed\"',0,0,0)")?
            .execute(rusqlite::params![[0u8;16].as_slice(),"src/ok.rs"]).map_err(cache_error)?;
        Ok(())
    })?;
    let a = "a".repeat(40);
    let b = "b".repeat(40);
    let note =
        "changed paths could not be read within the bounded Git read; paths omitted".to_owned();
    let feed = HistoryFeed {
        project: s.identity.scope.registration.project.clone(),
        root: s.identity.scope.registration.root.clone(),
        expected: None,
        bound: HistoryBound {
            head: a.clone(),
            oldest: Some(b.clone()),
            next: None,
            limit: HistoryLimit::Complete,
        },
        observed_unix_ms: 10,
        commits: vec![
            Commit {
                oid: a.clone(),
                parent: Some(b.clone()),
                author_unix_ms: 1,
                author: "Public author".into(),
                subject: "Public commit".into(),
                paths: vec![RelativePath::new("src/ok.rs")?],
                paths_note: None,
                allowed_paths: None,
            },
            Commit {
                oid: b.clone(),
                parent: None,
                author_unix_ms: 2,
                author: "Oversized author".into(),
                subject: "Oversized commit".into(),
                paths: Vec::new(),
                paths_note: Some(note.clone()),
                allowed_paths: Some(1),
            },
        ],
    };
    feed.validate()?;
    let receipt = ingest(&mut db, &feed, deadline())?;
    assert_eq!(
        (receipt.changed, receipt.denied_paths, receipt.generation.0),
        (2, 0, 1)
    );
    let outside = rusqlite::Connection::open(f.dir.join(s.identity.epoch.as_str()))?;
    for (sql, want) in [
        ("SELECT count(*) FROM commits", 2),
        (
            "SELECT count(*) FROM commits WHERE subject='Oversized commit'",
            1,
        ),
        ("SELECT count(*) FROM touches WHERE target_kind='commit'", 2),
        (
            "SELECT count(*) FROM activity WHERE target_kind='commit'",
            2,
        ),
        (
            "SELECT count(*) FROM mentions WHERE source_kind='commit'",
            1,
        ),
        (
            "SELECT count(*) FROM touches WHERE target_kind='file' AND source_commit IS NOT NULL",
            1,
        ),
    ] {
        assert_eq!(
            outside.query_row(sql, [], |r| r.get::<_, i64>(0))?,
            want,
            "{sql}"
        );
    }
    // A same-bound retry re-verifies the retained rows and replays cleanly.
    assert!(ingest(&mut db, &feed, deadline())?.replay);
    // The degradation note survives the coverage round trip and does not flag
    // the history unavailable.
    db.write(131072, deadline(), |sql| {
        let saved: String = sql
            .prepare("SELECT coverage_json FROM meta WHERE singleton=1")?
            .query_row([], |r| r.get(0))
            .map_err(cache_error)?;
        let mut coverage: Coverage = serde_json::from_str(&saved).map_err(cache_error)?;
        coverage.history_commit_notes = vec![HistoryCommitNote {
            oid: b.clone(),
            note: note.clone(),
        }];
        sql.prepare("UPDATE meta SET coverage_json=?1 WHERE singleton=1")?
            .execute([serde_json::to_string(&coverage).map_err(cache_error)?])
            .map_err(cache_error)?;
        Ok(())
    })?;
    let limit = db.read(deadline(), |sql| {
        let saved: String = sql
            .prepare("SELECT coverage_json FROM meta WHERE singleton=1")?
            .query_row([], |r| r.get(0))
            .map_err(cache_error)?;
        let coverage: Coverage = serde_json::from_str(&saved).map_err(cache_error)?;
        assert_eq!(
            coverage.history_commit_notes,
            vec![HistoryCommitNote {
                oid: b.clone(),
                note: note.clone()
            }]
        );
        limitation(sql)
    })?;
    assert_eq!(limit, None);
    // Validation rejects contradictory or oversized notes.
    let mut contradictory = feed.clone();
    contradictory.commits[1].paths = vec![RelativePath::new("src/ok.rs")?];
    assert!(contradictory.validate().is_err());
    let mut verbose = feed.clone();
    verbose.commits[1].paths_note = Some("x".repeat(513));
    assert!(verbose.validate().is_err());
    let mut no_evidence = feed.clone();
    no_evidence.commits[1].allowed_paths = None;
    assert!(no_evidence.validate().is_err());
    let mut stray_evidence = feed.clone();
    stray_evidence.commits[0].allowed_paths = Some(1);
    assert!(stray_evidence.validate().is_err());
    // Older coverage records without the field still deserialize.
    let old: Coverage = serde_json::from_value(
        serde_json::json!({"discovered_files":0,"indexed_files":0,"partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":true,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":true,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[],"history_unavailable":null}),
    )?;
    assert!(old.history_commit_notes.is_empty());
    Ok(())
}

#[test]
fn degraded_commit_without_allowed_evidence_keeps_the_note_but_not_the_metadata() -> Check {
    use se_atlas::history::*;
    use se_atlas_cold::apply::ingest;
    use se_types::code::*;
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    let a = "a".repeat(40);
    let b = "b".repeat(40);
    let note =
        "changed paths could not be read within the bounded Git read; paths omitted".to_owned();
    let feed = HistoryFeed {
        project: s.identity.scope.registration.project.clone(),
        root: s.identity.scope.registration.root.clone(),
        expected: None,
        bound: HistoryBound {
            head: a.clone(),
            oldest: Some(b.clone()),
            next: None,
            limit: HistoryLimit::Complete,
        },
        observed_unix_ms: 10,
        commits: vec![
            Commit {
                oid: a.clone(),
                parent: Some(b.clone()),
                author_unix_ms: 1,
                author: "Public author".into(),
                subject: "Public commit".into(),
                paths: vec![RelativePath::new("src/ok.rs")?],
                paths_note: None,
                allowed_paths: None,
            },
            Commit {
                oid: b,
                parent: None,
                author_unix_ms: 2,
                author: "Denied-only author".into(),
                subject: "Denied-only commit".into(),
                paths: Vec::new(),
                paths_note: Some(note),
                allowed_paths: Some(0),
            },
        ],
    };
    feed.validate()?;
    let receipt = ingest(&mut db, &feed, deadline())?;
    assert_eq!(
        (receipt.changed, receipt.denied_paths, receipt.generation.0),
        (1, 0, 1)
    );
    let outside = rusqlite::Connection::open(f.dir.join(s.identity.epoch.as_str()))?;
    for (sql, want) in [
        ("SELECT count(*) FROM commits", 1),
        (
            "SELECT count(*) FROM commits WHERE subject='Denied-only commit'",
            0,
        ),
        (
            "SELECT count(*) FROM commits WHERE subject='Public commit'",
            1,
        ),
        ("SELECT count(*) FROM touches WHERE target_kind='commit'", 1),
    ] {
        assert_eq!(
            outside.query_row(sql, [], |r| r.get::<_, i64>(0))?,
            want,
            "{sql}"
        );
    }
    Ok(())
}
