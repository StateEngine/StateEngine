use super::feed::kind_name;
use crate::{
    cache::connection::SqlView,
    errors::{AtlasResult, cache_error},
    model::*,
};
use rusqlite::params;
use se_types::code::*;
pub(super) fn apply(sql: &SqlView<'_>, id: i64, record: &FeedRecord) -> AtlasResult<()> {
    let mut targets = Vec::with_capacity(256);
    for target in &record.mentions {
        resolve(sql, target, &mut targets)?;
    }
    // Scan at most 64 KiB already admitted by the core feed. Backticks are the
    // identifier syntax; paths and hexadecimal commit prefixes are literal.
    for (index, text) in record.body.split('`').enumerate() {
        if targets.len() >= 256 {
            break;
        }
        if index % 2 == 1
            && !text.is_empty()
            && text.len() <= 1024
            && !text.chars().any(char::is_whitespace)
        {
            resolve(
                sql,
                &MentionTarget::Identifier(QueryText::new(text)?),
                &mut targets,
            )?;
        }
        for word in text.split_whitespace() {
            if targets.len() >= 256 {
                break;
            }
            let word = word.trim_matches(|c: char| {
                matches!(
                    c,
                    '`' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
                )
            });
            let path = word
                .rsplit_once(':')
                .filter(|(_, line)| !line.is_empty() && line.bytes().all(|c| c.is_ascii_digit()))
                .map_or(word, |(path, _)| path);
            if (path.contains('/') || path.contains('.'))
                && let Ok(path) = RelativePath::new(path)
            {
                resolve(sql, &MentionTarget::File(path), &mut targets)?;
            }
            if (7..=64).contains(&word.len()) && word.bytes().all(|c| c.is_ascii_hexdigit()) {
                let mut stmt =
                    sql.prepare("SELECT oid FROM commits WHERE hex(oid) LIKE ?1 LIMIT 2")?;
                let mut rows = stmt
                    .query([format!("{}%", word.to_ascii_uppercase())])
                    .map_err(cache_error)?;
                if let Some(row) = rows.next().map_err(cache_error)? {
                    let oid: Vec<u8> = row.get(0).map_err(cache_error)?;
                    if rows.next().map_err(cache_error)?.is_none() {
                        push(&mut targets, "commit", oid, "ExplicitImport");
                    }
                }
            }
        }
    }
    let actor = record
        .actor
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(cache_error)?;
    let touch_kind = if record.pointer.kind == RecordKind::Edit {
        "tool_edit"
    } else {
        kind_name(record.pointer.kind)
    };
    for (kind, key, accuracy) in targets {
        sql.prepare("INSERT OR IGNORE INTO mentions(source_kind,source_id,target_kind,target_key,accuracy) VALUES('record',?1,?2,?3,?4)")?
            .execute(params![id,kind,key,accuracy]).map_err(cache_error)?;
        let restricted = (!matches!(record.visibility, RecordVisibility::Project)).then_some(id);
        sql.prepare("INSERT INTO touches(target_kind,target_key,ordinal,touch_kind,actor,at_unix_ms,source_record,restricted_record) SELECT ?1,?2,coalesce(max(ordinal),0)+1,?3,?4,?5,?6,?7 FROM touches WHERE target_kind=?1 AND target_key=?2")?
            .execute(params![kind,key,touch_kind,actor,record.occurred_unix_ms,id,restricted]).map_err(cache_error)?;
        sql.prepare("DELETE FROM touches WHERE target_kind=?1 AND target_key=?2 AND ordinal NOT IN (SELECT ordinal FROM touches WHERE target_kind=?1 AND target_key=?2 ORDER BY at_unix_ms DESC,ordinal DESC LIMIT 10)")?
            .execute(params![kind,key]).map_err(cache_error)?;
        // The materialized summary excludes restricted records. Query-time core
        // checks must be used before adding their contribution for a viewer.
        sql.prepare("INSERT INTO activity(target_kind,target_key,last_touch_unix_ms,inbound_resolved) SELECT ?1,?2,max(at_unix_ms),0 FROM touches WHERE target_kind=?1 AND target_key=?2 AND restricted_record IS NULL GROUP BY target_kind,target_key ON CONFLICT(target_kind,target_key) DO UPDATE SET last_touch_unix_ms=excluded.last_touch_unix_ms")?
            .execute(params![kind,key]).map_err(cache_error)?;
    }
    Ok(())
}
type Target = (String, Vec<u8>, String);
fn push(output: &mut Vec<Target>, kind: &str, key: Vec<u8>, accuracy: &str) {
    if output.len() < 256 && !output.iter().any(|(k, v, _)| k == kind && v == &key) {
        output.push((kind.into(), key, accuracy.into()));
    }
}
fn resolve(sql: &SqlView<'_>, target: &MentionTarget, output: &mut Vec<Target>) -> AtlasResult<()> {
    match target {
        MentionTarget::File(path) => {
            let mut stmt = sql.prepare("SELECT key FROM files WHERE path=?1")?;
            let mut rows = stmt.query([path.as_str()]).map_err(cache_error)?;
            if let Some(row) = rows.next().map_err(cache_error)? {
                push(
                    output,
                    "file",
                    row.get(0).map_err(cache_error)?,
                    "ExplicitImport",
                );
            } else {
                push(
                    output,
                    "path",
                    path.as_str().as_bytes().to_vec(),
                    "NameOnly",
                );
            }
        }
        MentionTarget::Symbol(symbol) => {
            push(output, "symbol", symbol.0.to_vec(), "ExplicitImport")
        }
        MentionTarget::Identifier(name) => {
            let mut stmt = sql.prepare(
                "SELECT s.key FROM symbols s JOIN names n ON n.id=s.name WHERE n.text=?1 LIMIT 2",
            )?;
            let mut rows = stmt.query([name.as_str()]).map_err(cache_error)?;
            if let Some(row) = rows.next().map_err(cache_error)? {
                let key = row.get(0).map_err(cache_error)?;
                if rows.next().map_err(cache_error)?.is_none() {
                    push(output, "symbol", key, "NameOnly");
                } else {
                    push(
                        output,
                        "identifier",
                        name.as_str().as_bytes().to_vec(),
                        "NameOnly",
                    );
                }
            } else {
                push(
                    output,
                    "identifier",
                    name.as_str().as_bytes().to_vec(),
                    "NameOnly",
                );
            }
        }
        MentionTarget::Commit(oid) => push(
            output,
            "commit",
            match oid {
                GitObjectId::Sha1(v) => v.to_vec(),
                GitObjectId::Sha256(v) => v.to_vec(),
            },
            "ExplicitImport",
        ),
        MentionTarget::Record(key) => push(
            output,
            "record",
            key.as_str().as_bytes().to_vec(),
            "ExplicitImport",
        ),
    }
    Ok(())
}
