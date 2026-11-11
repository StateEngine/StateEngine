use super::*;
#[test]
fn file_retirement_uses_bounded_key_lookups() -> Result<(), Box<dyn std::error::Error>> {
    let db = Connection::open_in_memory()?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")?;
    db.execute_batch(schema::SQL)?;
    for sql in [
        "DELETE FROM refs WHERE file=?1",
        "UPDATE refs SET accuracy='NameOnly',target=NULL WHERE file=?1",
        "DELETE FROM symbols WHERE file=?1",
    ] {
        let mut statement = db.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
        let plan = statement
            .query_map([1], |row| row.get::<_, String>(3))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert!(
            !plan.iter().any(|step| step.starts_with("SCAN ")),
            "file retirement scans unrelated graph rows: {sql}: {plan:?}"
        );
    }
    Ok(())
}
#[test]
fn coverage_windows_use_the_preexisting_covering_index() -> Result<(), Box<dyn std::error::Error>> {
    let db = Connection::open_in_memory()?;
    db.execute_batch(schema::SQL)?;
    let mut statement = db.prepare("EXPLAIN QUERY PLAN SELECT id,target IS NOT NULL,accuracy='NameOnly' FROM refs WHERE id>?1 ORDER BY id LIMIT 1024")?;
    let plan = statement
        .query_map([0], |row| row.get::<_, String>(3))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    assert!(
        plan.iter()
            .any(|step| step.contains("COVERING INDEX refs_coverage (id>?)")),
        "{plan:?}"
    );
    assert!(
        !plan
            .iter()
            .any(|step| step.contains("TEMP B-TREE") || step.starts_with("SCAN ")),
        "{plan:?}"
    );
    Ok(())
}
#[test]
fn fixed_cache_statements_fit_budget() -> Result<(), Box<dyn std::error::Error>> {
    let db = Connection::open_in_memory()?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=FILE;")?;
    db.execute_batch(schema::SQL)?;
    let mut count = 0;
    for source in [
        include_str!("connection.rs"),
        include_str!("schema.rs"),
        include_str!("prune.rs"),
        include_str!("write.rs"),
        include_str!("reference_counts.rs"),
        include_str!("pointer.rs"),
        include_str!("../coverage.rs"),
    ] {
        for sql in literals(source)? {
            let first = sql.split_whitespace().next().unwrap_or("");
            if !matches!(first, "SELECT" | "INSERT" | "UPDATE" | "DELETE") {
                continue;
            }
            let statement = db.prepare(&sql)?;
            let bytes = statement.get_status(StatementStatus::MemUsed) as usize;
            assert!(
                bytes <= STATEMENT_BYTES,
                "{bytes} exceeds {STATEMENT_BYTES}: {sql}"
            );
            count += 1;
        }
    }
    assert!(
        count >= 20,
        "source scanner must find the production cache statements"
    );
    println!("{count} fixed cache statements fit {STATEMENT_BYTES} bytes");
    Ok(())
}
// Recognize ordinary Rust literals while ignoring comments; fail on an unknown
// escape instead of quietly dropping a query. Production SQL is static text.
fn literals(source: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut chars = source.chars().peekable();
    let mut strings = Vec::new();
    while let Some(ch) = chars.next() {
        if ch == '/' && chars.peek() == Some(&'/') {
            for ch in chars.by_ref() {
                if ch == '\n' {
                    break;
                }
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut depth = 1;
            while let Some(ch) = chars.next() {
                if ch == '/' && chars.peek() == Some(&'*') {
                    chars.next();
                    depth += 1;
                } else if ch == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
            assert_eq!(depth, 0, "unterminated source comment");
            continue;
        }
        if ch != '"' {
            continue;
        }
        let mut value = String::new();
        let mut closed = false;
        while let Some(ch) = chars.next() {
            if ch == '"' {
                closed = true;
                break;
            }
            if ch == '\\' {
                value.push(match chars.next().ok_or("incomplete source escape")? {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '\\' => '\\',
                    '"' => '"',
                    other => return Err(format!("unsupported source escape {other}").into()),
                });
            } else {
                value.push(ch);
            }
        }
        assert!(closed, "unterminated source literal");
        strings.push(value);
    }
    Ok(strings)
}

#[test]
fn expired_sql_is_not_started_and_live_submillisecond_budget_is_positive()
-> Result<(), Box<dyn std::error::Error>> {
    let mut db = Connection::open_in_memory()?;
    let entered = Cell::new(false);
    assert!(
        finite(&mut db, Instant::now(), |_, _| {
            entered.set(true);
            Ok(())
        })
        .is_err()
    );
    assert!(!entered.get(), "expired SQL work must not start");
    let view = SqlView {
        db: &db,
        count: Cell::new(0),
        bytes: Cell::new(0),
        readonly: true,
        deadline: Instant::now(),
    };
    let error = view
        .prepare("THIS IS INVALID SQL")
        .err()
        .ok_or("expired statement admitted")?;
    assert!(
        matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_)),
        "SQL was prepared after the snapshot expired: {error}"
    );
    for _ in 0..20 {
        let _ = finite(
            &mut db,
            Instant::now() + Duration::from_micros(500),
            |_, budget| {
                assert!(
                    budget > 0,
                    "live SQL work was admitted with zero milliseconds"
                );
                entered.set(true);
                Ok(())
            },
        );
        if entered.get() {
            break;
        }
    }
    assert!(
        entered.get(),
        "no live submillisecond SQL callback was observed"
    );
    Ok(())
}

#[test]
fn prepared_queries_and_writes_recheck_the_snapshot_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let db = Connection::open_in_memory()?;
    db.execute_batch("CREATE TABLE retained(value INTEGER)")?;
    let view = SqlView {
        db: &db,
        count: Cell::new(0),
        bytes: Cell::new(0),
        readonly: false,
        deadline: Instant::now() + Duration::from_millis(100),
    };
    let mut write = view.prepare("INSERT INTO retained VALUES(1)")?;
    let mut one = view.prepare("SELECT 1")?;
    let mut lazy_statement = view.prepare("SELECT 1")?;
    let mut lazy = lazy_statement.query([])?;
    let mut mapped_statement = view.prepare("SELECT 1")?;
    let mut mapped = mapped_statement.query_map([], |row| row.get::<_, i64>(0))?;
    std::thread::sleep(Duration::from_millis(110));
    assert!(
        lazy.next().is_err(),
        "lazy query executed its first step after expiry"
    );
    assert!(
        mapped
            .next()
            .ok_or("expired mapped query returned no row/error")?
            .is_err(),
        "expired mapped query executed"
    );
    assert!(
        mapped.next().is_none(),
        "expired mapped query repeats its error forever"
    );
    assert!(write.execute([]).is_err(), "expired write executed");
    assert!(
        one.query_row([], |row| row.get::<_, i64>(0)).is_err(),
        "expired single-row query started"
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM retained", [], |row| row
            .get::<_, i64>(0))?,
        0
    );
    Ok(())
}
