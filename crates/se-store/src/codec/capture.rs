pub(crate) mod native;
use super::*;
use rusqlite::OptionalExtension;
use se_types::{AgentId, NativePath, SessionId};
pub(crate) fn provider(value: Provider) -> &'static str {
    match value {
        Provider::Claude => "claude",
        Provider::Codex => "codex",
        Provider::SeCode => "secode",
    }
}
pub(crate) fn parse_provider(value: &str) -> StoreResult<Provider> {
    match value {
        "claude" => Ok(Provider::Claude),
        "codex" => Ok(Provider::Codex),
        "secode" => Ok(Provider::SeCode),
        _ => Err(invalid("stored provider")),
    }
}
pub(crate) fn consent(value: Consent) -> &'static str {
    match value {
        Consent::Capture => "capture",
        Consent::Suppressed => "suppressed",
    }
}
pub(crate) fn parse_consent(value: &str) -> StoreResult<Consent> {
    match value {
        "capture" => Ok(Consent::Capture),
        "suppressed" => Ok(Consent::Suppressed),
        _ => Err(invalid("stored consent")),
    }
}
pub(crate) fn role(value: Role) -> &'static str {
    match value {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    }
}
fn parse_role(value: &str) -> StoreResult<Role> {
    match value {
        "system" => Ok(Role::System),
        "user" => Ok(Role::User),
        "assistant" => Ok(Role::Assistant),
        "tool" => Ok(Role::Tool),
        _ => Err(invalid("stored role")),
    }
}
pub(crate) fn record(bytes: Vec<u8>) -> StoreResult<RecordId> {
    RecordId::from_bytes(bytes.try_into().map_err(|_| invalid("record ID length"))?)
}
pub(crate) fn decode(
    c: &Connection,
    seq: i64,
    kind: &str,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    if kind != "session.turn" {
        let v = facts(c, seq)?;
        return Ok(match kind {
            "capture.source" => EventBody::CaptureSource {
                source: field(&v, "source")?,
                session: field(&v, "session")?,
                consent: field(&v, "consent")?,
                native_ref: field(&v, "native_ref")?,
                incarnation: field(&v, "incarnation")?,
                expected: field(&v, "expected")?,
            },
            "capture.progress" => EventBody::CaptureProgress {
                source: field(&v, "source")?,
                expected: field(&v, "expected")?,
                incarnation: field(&v, "incarnation")?,
                old_offset: field(&v, "old_offset")?,
                new_offset: field(&v, "new_offset")?,
                last_turn: field(&v, "last_turn")?,
                replay_evidence: v
                    .get("replay_evidence")
                    .map(|v| serde_json::from_value(v.clone()).map_err(invalid))
                    .transpose()?
                    .flatten(),
            },
            "capture.failed" => EventBody::CaptureFailed {
                source: field(&v, "source")?,
                session: field(&v, "session")?,
                from_offset: field(&v, "from_offset")?,
                to_offset: field(&v, "to_offset")?,
                code: field(&v, "code")?,
                cause: field(&v, "cause")?,
                retry: field(&v, "retry")?,
            },
            "capture.suppressed" => EventBody::CaptureSuppressed {
                source: field(&v, "source")?,
                session: field(&v, "session")?,
                expected: field(&v, "expected")?,
                reason: field(&v, "reason")?,
                from_offset: field(&v, "from_offset")?,
                to_offset: field(&v, "to_offset")?,
                count: field(&v, "count")?,
            },
            _ => return Err(invalid("capture kind")),
        });
    }
    let mut q = c
        .prepare("SELECT * FROM turn_data WHERE event_seq=?")
        .map_err(sql)?;
    let mut rows = q.query([seq]).map_err(sql)?;
    let row = rows
        .next()
        .map_err(sql)?
        .ok_or_else(|| invalid("turn fact absent"))?;
    let s = scope_key(c, scope, false)?;
    let agent: AgentId = decode_agent(
        c,
        wire(
            c,
            "agent",
            &row.get::<_, Vec<u8>>("agent_id").map_err(sql)?,
            &s,
        )?,
        &s,
    )?;
    let session: SessionId = wire(
        c,
        "session",
        &row.get::<_, Vec<u8>>("session_id").map_err(sql)?,
        &s,
    )?
    .try_into()
    .map_err(invalid)?;
    let path: Vec<u8> = c
        .query_row(
            "SELECT value FROM symbols WHERE id=?",
            [row.get::<_, i64>("source_path").map_err(sql)?],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let path: Option<NativePath> = serde_json::from_slice(&path).map_err(invalid)?;
    let metadata = facts(c, seq)?;
    Ok(EventBody::SessionTurn {
        turn: record(row.get("turn_id").map_err(sql)?)?,
        agent,
        session,
        provider: parse_provider(&row.get::<_, String>("provider").map_err(sql)?)?,
        vendor_ref: row.get("vendor_ref").map_err(sql)?,
        role: parse_role(&row.get::<_, String>("role").map_err(sql)?)?,
        text: stored_text(c, seq, "body")?,
        evidence: SourceEvidence {
            path,
            incarnation: field(&metadata, "source_incarnation")?,
            offset: u64::try_from(row.get::<_, i64>("source_offset").map_err(sql)?)
                .map_err(invalid)?,
            length: u64::try_from(row.get::<_, i64>("source_length").map_err(sql)?)
                .map_err(invalid)?,
            sha256: row
                .get::<_, Option<Vec<u8>>>("source_sha256")
                .map_err(sql)?
                .map(|v| v.try_into().map_err(|_| invalid("source sha length")))
                .transpose()?,
        },
    })
}
pub(crate) fn natural(c: &Connection, e: &NewEvent) -> StoreResult<Option<i64>> {
    match &e.body {
        EventBody::SessionTurn {session,provider:backend,vendor_ref,..} => {
            native::find(c, &e.header.scope, session, *backend, vendor_ref)
        },
        EventBody::CaptureSource {source,session,consent,native_ref,incarnation,..} => c.query_row("SELECT event_seq FROM aux_data INDEXED BY capture_source_natural WHERE json_extract(facts,'$.capture_kind')='source' AND json_extract(facts,'$.project')=? AND json_extract(facts,'$.source')=? AND json_extract(facts,'$.incarnation')=? AND json_extract(facts,'$.session')=? AND json_extract(facts,'$.consent')=? AND json_extract(facts,'$.native_ref')=?",rusqlite::params![crate::identity::project(&e.header.scope)?.as_str(),encode(source)?,encode(incarnation)?,session.as_str(),encode(consent)?.trim_matches('"'),native_ref],|r|r.get(0)).optional().map_err(sql),
        EventBody::CaptureProgress {source,incarnation,old_offset,new_offset,last_turn,..} => c.query_row("SELECT event_seq FROM aux_data INDEXED BY capture_progress_natural WHERE json_extract(facts,'$.capture_kind')='progress' AND json_extract(facts,'$.project')=? AND json_extract(facts,'$.source')=? AND json_extract(facts,'$.incarnation')=? AND json_extract(facts,'$.old_offset')=? AND json_extract(facts,'$.new_offset')=? AND json_extract(facts,'$.last_turn')=?",crate::sql_value::sql_params![crate::identity::project(&e.header.scope)?.as_str(),encode(source)?,encode(incarnation)?,old_offset,new_offset,encode(last_turn)?],|r|r.get(0)).optional().map_err(sql),
        _=>Ok(None),
    }
}
