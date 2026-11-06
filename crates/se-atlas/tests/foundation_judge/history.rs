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
fn history_feed_filters_secrets_before_all_derivations_and_retries_immutably() -> Check {
    use se_atlas::history::*;
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
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
            },
            Commit {
                oid: b,
                parent: None,
                author_unix_ms: 2,
                author: "secret-only-author-DO-NOT-STORE".into(),
                subject: "secret-only-subject-DO-NOT-STORE".into(),
                paths: vec![RelativePath::new(".env")?],
            },
        ],
    };
    let receipt = ingest(&db, &feed, deadline())?;
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
    let reader = se_atlas::query::QueryReader::new(
        &db,
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
    assert!(ingest(&db, &feed, deadline())?.replay);
    let mut conflicting = feed.clone();
    conflicting.commits[0].subject = "changed immutable commit".into();
    assert!(ingest(&db, &conflicting, deadline()).is_err());
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
    assert!(!prune::commits(&db, 1, deadline())?);
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
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
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
        }],
    };
    ingest(&db, &feed, deadline())?;
    let mut stale = feed.clone();
    let next = "c".repeat(40);
    stale.bound.head = next.clone();
    stale.bound.oldest = Some(next.clone());
    stale.commits[0].oid = next;
    assert!(ingest(&db, &stale, deadline()).is_err());
    let mut wrong_root = feed.clone();
    wrong_root.root = RootId::from_parts(1, [9; 10])?;
    assert!(ingest(&db, &wrong_root, deadline()).is_err());
    let mut oversized = feed.clone();
    oversized.commits[0].paths = (0..33)
        .map(|n| RelativePath::new(format!("src/file-{n}.rs")))
        .collect::<Result<_, _>>()?;
    assert!(ingest(&db, &oversized, deadline()).is_err());
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
