use super::*;
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
        include_str!("pointer.rs"),
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
