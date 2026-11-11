use super::*;
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(crate) fn apply(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    rev: u64,
    facts: Value,
) -> StoreResult<()> {
    use EventBody::*;
    if !matches!(h.door, Door::Import) {
        return Err(invalid(
            "import facts require the owner-admitted import adapter",
        ));
    }
    match body {
        ImportStarted {
            import,
            format,
            policy_version,
            ..
        } => {
            if format.is_empty() || format.len() > 128 || !matches!(policy_version, 1 | 2) {
                return Err(invalid(
                    "supported import format and policy version required",
                ));
            }
            c.execute("INSERT INTO import_runs(import_id,first_seq,revision,last_seq,state) VALUES(?,?,?,?,'running')",crate::sql_value::sql_params![import.as_bytes(),seq,rev,seq]).map_err(sql)?;
        }
        ImportProgress {
            checkpoint: p,
            counts: value,
        } => {
            counts(&value)?;
            if p.source_key.is_empty()
                || p.source_key.len() > 4096
                || p.row_offset > i64::MAX as u64
                || p.byte_offset > i64::MAX as u64
            {
                return Err(invalid("bounded import source cursor required"));
            }
            let old: Option<(u64,u64)> = c.query_row("SELECT byte_offset,row_offset FROM import_progress WHERE import_id=? AND family=? AND source_key=?",crate::sql_value::sql_params![p.import.as_bytes(),family(p.family)?,p.source_key],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?))).optional().map_err(sql)?;
            if old.is_some_and(|(bytes, rows)| p.byte_offset < bytes || p.row_offset < rows) {
                return Err(fail(
                    StoreErrorCode::SourceChanged,
                    "import cursor cannot move backwards",
                ));
            }
            c.execute("INSERT INTO import_progress(import_id,family,source_key,revision,last_seq,byte_offset,row_offset,prefix_sha256) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(import_id,family,source_key) DO UPDATE SET revision=excluded.revision,last_seq=excluded.last_seq,byte_offset=excluded.byte_offset,row_offset=excluded.row_offset,prefix_sha256=excluded.prefix_sha256",crate::sql_value::sql_params![p.import.as_bytes(),family(p.family)?,p.source_key,rev,seq,p.byte_offset,p.row_offset,p.source_sha256]).map_err(sql)?;
        }
        ImportFinished {
            import,
            counts: value,
            complete,
            omissions,
            ..
        } => {
            counts(&value)?;
            if omissions.len() > 256
                || complete
                    && (value.unreadable != 0 || value.deferred != 0 || !omissions.is_empty())
            {
                return Err(invalid(
                    "import completion cannot hide unreadable rows or omissions",
                ));
            }
            c.execute(
                "UPDATE import_runs SET revision=?,last_seq=?,state=? WHERE import_id=?",
                crate::sql_value::sql_params![
                    rev,
                    seq,
                    if complete { "complete" } else { "partial" },
                    import.as_bytes()
                ],
            )
            .map_err(sql)?;
        }
        ImportUnreadable {
            import,
            evidence,
            code,
            ..
        } => {
            require_run(c, import)?;
            if code.is_empty()
                || code.len() > 128
                || evidence.incarnation.is_empty()
                || evidence.incarnation.len() > 256
            {
                return Err(invalid("bounded unreadable provenance required"));
            }
        }
        LegacyRetained {
            import,
            family: f,
            format_version,
            legacy_id,
            mapped_id,
            source,
            bytes,
            retained_from,
        } => {
            require_run(c, import)?;
            if format_version == 0
                || legacy_id.is_empty()
                || legacy_id.len() > 512
                || source.incarnation.is_empty()
            {
                return Err(invalid("bounded legacy source correspondence required"));
            }
            if bytes.is_some() && retained_from.is_some() {
                return Err(invalid(
                    "duplicate retained content needs its original owner, never another copy",
                ));
            }
            if let Some(original) = retained_from {
                let scope = scope_key(c, &h.scope, false)?;
                let original = key(c, "event", original.as_str(), &scope, false)?;
                let project = match &h.scope {
                    Scope::Registry => None,
                    Scope::Project(_) => Some(project_id(c, &h.scope, false)?),
                };
                let exists:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM events WHERE event_id=? AND project_id IS ? AND kind='legacy.retained' AND door='import' AND seq<?)",rusqlite::params![original,project,seq],|r|r.get(0)).map_err(sql)?;
                if !exists {
                    return Err(fail(
                        StoreErrorCode::ReferenceMissing,
                        "duplicate retained text must reference earlier imported history in this scope",
                    ));
                }
            }
            if let Some(bytes) = bytes {
                use sha2::{Digest, Sha256};
                if bytes.bytes.len() > 1024 * 1024
                    || Sha256::digest(&bytes.bytes).as_slice() != bytes.sha256
                {
                    return Err(invalid("legacy payload size/hash differs"));
                }
                crate::connection::payload(
                    c,
                    seq,
                    "legacy",
                    std::str::from_utf8(&bytes.bytes).map_err(invalid)?,
                )?;
            }
            let mapped = target_key(c, &mapped_id, &h.scope, &source)?;
            c.execute("INSERT INTO legacy_ids(import_id,family,legacy_id,typed_id,imported_seq) VALUES(?,?,?,?,?)",crate::sql_value::sql_params![import.as_bytes(),family(f)?,legacy_id,mapped,seq]).map_err(sql)?;
        }
        AliasImported {
            alias,
            principal,
            source,
            expected: want,
        } => {
            if !matches!(want, Expected::Absent) || alias.is_empty() || alias.len() > 128 {
                return Err(invalid("import alias bounds/expectation"));
            }
            let s = scope_key(c, &h.scope, false)?;
            let p = project_id(c, &h.scope, false)?;
            let id = key(
                c,
                principal.kind(),
                principal.wire(),
                if principal.kind() == "human" {
                    &[0]
                } else {
                    &s
                },
                false,
            )?;
            let event = key(c, "event", source.as_str(), &s, false)?;
            let exists: bool = c
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM events WHERE event_id=? AND project_id=?)",
                    crate::sql_value::sql_params![event, p],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            if !exists {
                return Err(fail(
                    StoreErrorCode::ReferenceMissing,
                    "alias source evidence is absent",
                ));
            }
            let existing: Option<Vec<u8>> = c
                .query_row(
                    "SELECT principal_id FROM aliases WHERE project_id=? AND alias=?",
                    rusqlite::params![p, alias],
                    |r| r.get(0),
                )
                .optional()
                .map_err(sql)?;
            if let Some(existing) = existing {
                if existing != id {
                    return Err(fail(
                        StoreErrorCode::NaturalKeyConflict,
                        "imported lookup alias already denotes a different principal",
                    ));
                }
            } else {
                c.execute(
                "INSERT INTO aliases(project_id,alias,principal_id,imported_seq) VALUES(?,?,?,?)",
                crate::sql_value::sql_params![p, alias, id, seq],
            )
            .map_err(sql)?;
            }
        }
        _ => return Err(invalid("import apply dispatch")),
    }
    codec::aux(c, seq, facts)
}
fn require_run(c: &Connection, import: RecordId) -> StoreResult<()> {
    let exists: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM import_runs WHERE import_id=?)",
            [import.as_bytes()],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !exists {
        return Err(fail(
            StoreErrorCode::ReferenceMissing,
            "import run is absent",
        ));
    }
    Ok(())
}
