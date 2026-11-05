//! Separate bounded plans admit IDs and recency before loading display metadata.
use super::{candidates::Kind, *};
use rusqlite::types::Value;
pub(super) struct Plan {
    pub kind: Kind,
    pub tier: u8,
    pub sql: String,
    pub values: Vec<Value>,
    pub lexical: bool,
}
pub(super) fn plans(query: &FindQuery, mode: SearchMode) -> AtlasResult<Vec<Plan>> {
    let mut output = Vec::new();
    if matches!(mode, SearchMode::Broad | SearchMode::Related)
        && super::modes::words(query.query.as_str()).is_empty()
    {
        return Ok(output);
    }
    let text = query.query.as_str();
    let exact = mode == SearchMode::Exact;
    let smart = text.chars().any(char::is_uppercase);
    let literal = |field: &str| {
        if smart {
            format!("instr({field},?1)>0")
        } else {
            format!("instr(lower({field}),lower(?1))>0")
        }
    };
    let mut add = |kind, tier, condition: &str, text: &str| -> AtlasResult<()> {
        output.push(plan(kind, tier, condition, text, query)?);
        Ok(())
    };
    if matches!(
        query.kind,
        SearchKind::All | SearchKind::Code | SearchKind::Symbol
    ) {
        let equality = if smart {
            "n.text=?1"
        } else {
            "s.name IN (SELECT id FROM names WHERE lower(text)=?1)"
        };
        add(Kind::Symbol, 1, equality, text)?;
        if !exact {
            if mode != SearchMode::Phrase {
                let prefix = if smart {
                    "s.name IN (SELECT id FROM names WHERE instr(text,?1)=1)"
                } else {
                    "s.name IN (SELECT id FROM names WHERE instr(lower(text),lower(?1))=1)"
                };
                add(Kind::Symbol, 2, prefix, text)?;
            }
            let tokens = crate::rank::identifier_tokens(text);
            if !tokens.is_empty() && matches!(mode, SearchMode::Broad | SearchMode::Related) {
                let split = tokens
                    .iter()
                    .map(|t| format!("\"{}\"*", t.replace('"', "\"\"")))
                    .collect::<Vec<_>>()
                    .join(" AND ");
                add(
                    Kind::Symbol,
                    2,
                    "s.id IN (SELECT rowid FROM symbol_fts WHERE split_name MATCH ?1)",
                    &format!("(\"{}\"* OR ({split}))", text.replace('"', "\"\"")),
                )?;
            }
            if mode == SearchMode::Literal {
                add(
                    Kind::Symbol,
                    4,
                    &format!("s.name IN (SELECT id FROM names WHERE {})", literal("text")),
                    text,
                )?;
            }
            if mode != SearchMode::Literal {
                add(
                    Kind::Symbol,
                    4,
                    "s.id IN (SELECT rowid FROM symbol_fts WHERE symbol_fts MATCH ?1)",
                    &super::modes::fts(text, mode),
                )?;
            }
        }
    }

    if matches!(
        query.kind,
        SearchKind::All | SearchKind::Code | SearchKind::Path
    ) {
        add(
            Kind::File,
            3,
            &if exact {
                "f.path=?1".into()
            } else {
                literal("f.path")
            },
            text,
        )?;
    }
    if matches!(
        query.kind,
        SearchKind::All
            | SearchKind::Decision
            | SearchKind::Message
            | SearchKind::Working
            | SearchKind::Edit
    ) {
        if exact {
            add(Kind::Record, 1, "r.record_id=?1", text)?;
        } else if mode == SearchMode::Literal {
            add(Kind::Record, 4, &literal("r.title"), text)?;
            // Word tokens cannot answer an arbitrary interior substring. Read a
            // bounded, recency-ordered candidate range through core instead.
            add(Kind::Record, 5, "?1 IS NOT NULL", text)?;
        } else {
            let expression = super::modes::fts(text, mode);
            add(
                Kind::Record,
                4,
                "r.id IN (SELECT rowid FROM record_fts WHERE record_fts MATCH ?1)",
                &expression,
            )?;
            add(
                Kind::Record,
                5,
                "r.id IN (SELECT rowid FROM record_text_fts WHERE record_text_fts MATCH ?1)",
                &expression,
            )?;
        }
    }
    if matches!(query.kind, SearchKind::All | SearchKind::Commit) {
        if !exact {
            add(Kind::Commit, 4, &literal("c.subject"), text)?;
        }
        if let Some((low, high)) = oid_prefix(text, exact) {
            let mut p = plan(
                Kind::Commit,
                if exact { 1 } else { 4 },
                if exact {
                    "c.oid=?1"
                } else {
                    "c.oid>=?1 AND c.oid<?2"
                },
                "",
                query,
            )?;
            p.values[0] = Value::Blob(low);
            if !exact {
                p.values[1] = Value::Blob(high);
            }
            output.push(p);
        }
    }
    Ok(output)
}
fn plan(kind: Kind, tier: u8, condition: &str, text: &str, query: &FindQuery) -> AtlasResult<Plan> {
    let (tag, table, alias, key) = match kind {
        Kind::Symbol => ("symbol", "symbols", "s", "s.key"),
        Kind::File => ("file", "files", "f", "f.key"),
        Kind::Record => ("record", "records", "r", "CAST(r.record_id AS BLOB)"),
        Kind::Commit => ("commit", "commits", "c", "c.oid"),
    };
    let mut values = vec![Value::Text(text.into())];
    if condition.contains("?2") {
        values.push(Value::Null);
    }
    let mut from = if kind == Kind::Symbol {
        "symbols s JOIN names n ON n.id=s.name".to_owned()
    } else {
        format!("{table} {alias}")
    };
    let fts = ["symbol_fts", "record_fts", "record_text_fts"]
        .into_iter()
        .find(|table| condition.contains(&format!("FROM {table} WHERE")));
    let (condition, lexical) = if let Some(table) = fts {
        from.push_str(&format!(" JOIN {table} ON {table}.rowid={alias}.id"));
        let prefix = format!("{alias}.id IN (SELECT rowid FROM {table} WHERE ");
        let condition = condition
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix(')'))
            .ok_or_else(|| cache_error("invalid bounded FTS plan"))?;
        (condition, format!(",bm25({table})"))
    } else {
        (condition, String::new())
    };
    let mut sql = format!(
        "SELECT {alias}.id,a.last_touch_unix_ms{lexical} FROM {from} LEFT JOIN activity a ON a.target_kind='{tag}' AND a.target_key={key} WHERE ({condition})"
    );
    if kind == Kind::Record {
        let k = match query.kind {
            SearchKind::Decision => Some("decision"),
            SearchKind::Message => Some("message"),
            SearchKind::Working => Some("working"),
            SearchKind::Edit => Some("edit"),
            _ => None,
        };
        if let Some(k) = k {
            values.push(Value::Text(k.into()));
            sql.push_str(&format!(" AND r.kind=?{}", values.len()));
        }
    }
    if !query.scope.paths.is_empty() || !query.scope.languages.is_empty() {
        let column = if kind == Kind::File { "f" } else { "scope" };
        if kind == Kind::Symbol {
            sql.push_str(" AND EXISTS(SELECT 1 FROM files scope WHERE scope.id=s.file");
        } else if kind != Kind::File {
            sql.push_str(&format!(" AND EXISTS(SELECT 1 FROM mentions m JOIN files scope ON m.target_key=scope.key WHERE m.source_kind='{tag}' AND m.source_id={alias}.id AND m.target_kind='file'"));
        }
        values.push(Value::Blob(query.scope.packed_paths()));
        values.push(Value::Blob(query.scope.packed_languages()));
        sql.push_str(&format!(
            " AND atlas_scope({column}.path,{column}.language,?{},?{})",
            values.len() - 1,
            values.len()
        ));
        if kind != Kind::File {
            sql.push(')');
        }
    }
    sql.push_str(&format!(
        " ORDER BY a.last_touch_unix_ms DESC,{key} LIMIT 513"
    ));
    Ok(Plan {
        kind,
        tier,
        sql,
        values,
        lexical: fts.is_some(),
    })
}
fn oid_prefix(text: &str, exact: bool) -> Option<(Vec<u8>, Vec<u8>)> {
    if text.len() < 7
        || text.len() > 64
        || !text.bytes().all(|b| b.is_ascii_hexdigit())
        || exact && !matches!(text.len(), 40 | 64)
    {
        return None;
    }
    // Odd hex prefixes are represented by a byte interval, without scanning hex(oid).
    let mut low = Vec::with_capacity(text.len().div_ceil(2));
    for pair in text.as_bytes().chunks(2) {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = pair
            .get(1)
            .map_or(0, |v| (*v as char).to_digit(16).unwrap_or(0) as u8);
        low.push((hi << 4) | lo);
    }
    let mut high = low.clone();
    let mut carry = if text.len() % 2 == 1 { 16u16 } else { 1 };
    for b in high.iter_mut().rev() {
        let v = u16::from(*b) + carry;
        *b = v as u8;
        carry = v >> 8;
        if carry == 0 {
            break;
        }
    }
    // SQLite's BLOB ordering compares length only after shared bytes; a trailing
    // FF sentinel covers the maximum digest too, without treating a prefix as exact.
    if carry > 0 {
        high = vec![255; 33];
    }
    Some((low, high))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_filter_precedes_the_candidate_window() -> Result<(), Box<dyn std::error::Error>> {
        let db = rusqlite::Connection::open_in_memory()?;
        db.execute_batch(include_str!("../cache/schema.sql"))?;
        crate::cache::path_scope::register(&db)?;
        db.execute_batch("INSERT INTO names VALUES(1,'needle');")?;
        for id in 1i64..=514 {
            let path = if id == 514 {
                "src/inside.rs".to_owned()
            } else {
                format!("src2/outside-{id}.rs")
            };
            let mut file = [0u8; 16];
            file[..8].copy_from_slice(&id.to_be_bytes());
            let mut symbol = [0u8; 32];
            symbol[..8].copy_from_slice(&id.to_be_bytes());
            db.execute("INSERT INTO files(id,key,path,path_key,language,bytes,identity,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,?2,?3,?3,'Rust',1,x'01','\"Indexed\"',1,0,0)",rusqlite::params![id,file.as_slice(),path])?;
            db.execute("INSERT INTO symbols(id,key,file,name,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,exported,doc_line) VALUES(?1,?2,?1,1,'Function',0,1,1,0,1,1,0,'')",rusqlite::params![id,symbol.as_slice()])?;
        }
        let query = FindQuery {
            query: QueryText::new("needle")?,
            kind: SearchKind::Symbol,
            scope: SearchScope {
                paths: vec![RelativePath::new("src")?],
                languages: vec![Language::Rust],
            },
            next: None,
            budget: Validate.query_budget(10, 4096)?,
            mode: Some(SearchMode::Exact),
            order: SearchOrder::Relevance,
            full: false,
            regex: false,
        };
        let plan = plans(&query, SearchMode::Exact)?.remove(0);
        let mut statement = db.prepare(&plan.sql)?;
        let ids = statement
            .query_map(rusqlite::params_from_iter(plan.values), |r| {
                r.get::<_, i64>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            ids,
            vec![514],
            "out-of-directory matches consumed the candidate window"
        );
        Ok(())
    }
    #[test]
    fn plans_fit_statement_share() -> Result<(), Box<dyn std::error::Error>> {
        let db = rusqlite::Connection::open_in_memory()?;
        db.execute_batch(include_str!("../cache/schema.sql"))?;
        crate::cache::path_scope::register(&db)?;
        let query = FindQuery {
            query: QueryText::new("alpha")?,
            kind: SearchKind::All,
            scope: SearchScope {
                paths: vec![],
                languages: vec![],
            },
            next: None,
            budget: Validate.query_budget(10, 4096)?,
            mode: None,
            order: SearchOrder::Relevance,
            full: false,
            regex: false,
        };
        let mut count = 0;
        let mut failures = Vec::new();
        for mode in [
            SearchMode::Exact,
            SearchMode::Literal,
            SearchMode::Phrase,
            SearchMode::Broad,
        ] {
            for paths in [false, true] {
                for languages in [false, true] {
                    let mut query = query.clone();
                    if paths {
                        query.scope.paths.push(RelativePath::new("alpha.rs")?);
                    }
                    if languages {
                        query.scope.languages.push(Language::Rust);
                    }
                    for plan in plans(&query, mode)? {
                        let stmt = db.prepare(&plan.sql)?;
                        let bytes = stmt.get_status(rusqlite::StatementStatus::MemUsed);
                        if bytes > 16384 {
                            failures.push(format!("{bytes} bytes: {}", plan.sql));
                        }
                        count += 1;
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(count >= 48);
        Ok(())
    }
}
