//! Native provider conversations survive engine-session replacement. Search
//! source bindings, then exact indexed per-session item keys, never chat text.
use super::*;
use se_types::SessionId;

pub(crate) fn find(
    c: &Connection,
    scope: &Scope,
    session: &SessionId,
    backend: Provider,
    vendor: &str,
) -> StoreResult<Option<i64>> {
    let project = crate::connection::project_id(c, scope, false)?;
    let storage_scope = scope_key(c, scope, false)?;
    let id = key(c, "session", session.as_str(), &storage_scope, false)?;
    let exact = |id: &[u8],
                 agent: Option<&[u8]>,
                 vendor: &str,
                 chat_only: bool|
     -> StoreResult<Option<i64>> {
        c.query_row(
            "SELECT event_seq FROM turn_data WHERE project_id=? AND session_id=? AND provider=? AND vendor_ref=? AND (? IS NULL OR agent_id=?) AND (?=0 OR role IN ('user','assistant'))",
            rusqlite::params![project, id, provider(backend), vendor, agent, agent, chat_only],
            |row| row.get(0),
        ).optional().map_err(sql)
    };
    if let Some(seq) = exact(&id, None, vendor, false)? {
        return Ok(Some(seq));
    }
    // Import canonicalizes before applying its same-batch SessionPrepared.
    // Only an absent session has no retained match; an existing broken head
    // still takes the ordinary strict reader below and must refuse.
    let exists: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=? AND session_id=?)",
            rusqlite::params![project, id],
            |row| row.get(0),
        )
        .map_err(sql)?;
    if !exists {
        return Ok(None);
    }
    let head = crate::codec::session::head(c, &project, &id)?;
    if head.provider != provider(backend) || head.consent != "capture" {
        return Ok(None);
    }
    let project_wire = crate::identity::project(scope)?;
    let conversation: Option<String> = c.query_row(
        "SELECT json_extract(facts,'$.native_ref') FROM aux_data INDEXED BY capture_source_natural
         WHERE json_extract(facts,'$.capture_kind')='source' AND json_extract(facts,'$.project')=?
         AND json_extract(facts,'$.session')=? AND json_extract(facts,'$.consent')='Capture'
         ORDER BY event_seq LIMIT 1",
        rusqlite::params![project_wire.as_str(), session.as_str()], |row| row.get(0),
    ).optional().map_err(sql)?;
    let Some(conversation) = conversation else {
        return Ok(None);
    };
    let mut statement = c.prepare(
        "SELECT DISTINCT json_extract(facts,'$.session') FROM aux_data INDEXED BY capture_source_natural
         WHERE json_extract(facts,'$.capture_kind')='source' AND json_extract(facts,'$.project')=?
         AND json_extract(facts,'$.native_ref')=? AND json_extract(facts,'$.consent')='Capture'",
    ).map_err(sql)?;
    let sessions = statement
        .query_map(
            rusqlite::params![project_wire.as_str(), conversation],
            |row| row.get::<_, String>(0),
        )
        .map_err(sql)?;
    let mut first = None;
    for candidate in sessions {
        let candidate = candidate.map_err(sql)?;
        let id = key(c, "session", &candidate, &storage_scope, false)?;
        // Claude metadata embeds its engine-session/source binding. Reuse its
        // native chat UUIDs while preserving the existing Codex item contract.
        let tool_vendor = (backend == Provider::Codex)
            .then(|| vendor.strip_prefix(&format!("{}tool/", crate::TRANSCRIPT_EVENT_PREFIX)))
            .flatten()
            .and_then(|key| key.rsplit_once('/'))
            .filter(|(session, hash)| {
                session.parse::<SessionId>().is_ok()
                    && hash.len() == 64
                    && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .map(|(_, hash)| format!("{}tool/{candidate}/{hash}", crate::TRANSCRIPT_EVENT_PREFIX));
        if let Some(seq) = exact(
            &id,
            Some(&head.agent),
            tool_vendor.as_deref().unwrap_or(vendor),
            backend == Provider::Claude,
        )? {
            first = Some(first.map_or(seq, |old: i64| old.min(seq)));
        }
    }
    Ok(first)
}

/// A new session may verify the same item from a new file/range. The stored
/// event keeps its original session, source evidence and occurrence time.
pub(crate) fn resumed(event: &NewEvent, old: &StoredEvent) -> bool {
    matches!((&event.body, &old.body), (
        EventBody::SessionTurn { session: new_session, agent, provider, vendor_ref, role, text: InputText::Inline(text), evidence, .. },
        EventBody::SessionTurn { session: old_session, agent: old_agent, provider: old_provider, vendor_ref: old_vendor, role: old_role, text: StoredText::Present(old_text), evidence: old_evidence, .. }
    ) if new_session != old_session && agent == old_agent && provider==old_provider && vendor_ref == old_vendor && role == old_role && (*provider != Provider::Claude || matches!(role,Role::User|Role::Assistant)) && text == old_text
        && (!matches!(provider,Provider::SeCode|Provider::Acp) || (evidence.sha256.is_some() && evidence.sha256==old_evidence.sha256 && evidence.offset==old_evidence.offset && evidence.length==old_evidence.length)))
}
