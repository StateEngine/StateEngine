//! A turn a harness or owner client publishes for one existing session. Only the
//! session's own bound agent or a human owner may write it; the prose is one
//! erasable body payload and everything else is structural.
use super::*;
use crate::codec::capture::role;
use crate::published_turn::PublishedTurn;

/// Largest stored body: the same bound captured turns use.
const MAX_BODY: usize = 1024 * 1024;
/// Decision and paths without the chat text: what metadata history pages, such
/// as the Atlas feed's 128 KiB read, receive. The operation enforces the same.
const MAX_METADATA: usize = 64 * 1024;

pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    seq: i64,
    turn: PublishedTurn,
    body: Option<InputText>,
) -> StoreResult<()> {
    let p = project_id(c, &h.scope, false)?;
    let scope = scope_key(c, &h.scope, false)?;
    match &h.actor {
        Actor::Agent(actor)
            if *actor == turn.agent && h.session.as_ref() == Some(&turn.session) => {}
        Actor::Human(_) => {}
        _ => {
            return Err(scope_mismatch(
                "a session publishes only its own turns; the owner names the agent and session",
            ));
        }
    }
    if turn.role == Role::System {
        return Err(invalid(
            "published turn role must be user, assistant or tool",
        ));
    }
    if turn.content_sha256.is_some() && body.is_none() {
        return Err(invalid(
            "a published turn keeps content_sha256 only beside a stored body, so se forget can erase both",
        ));
    }
    let session = key(c, "session", turn.session.as_str(), &scope, false)?;
    let agent = key(c, "agent", turn.agent.as_str(), &scope, false)?;
    let head = codec::session::head(c, &p, &session)?;
    if head.agent != agent {
        return Err(scope_mismatch(
            "published turn session belongs to another agent",
        ));
    }
    let duplicate: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM published_turns WHERE project_id=? AND session_id=? AND harness=? AND vendor_turn=?)",
            crate::sql_value::sql_params![p, session, turn.harness, turn.vendor_turn],
            |r| crate::sql_value::value(r, 0),
        )
        .map_err(sql)?;
    if duplicate {
        return Err(fail(
            StoreErrorCode::NaturalKeyConflict,
            "this session already has a published turn with this harness turn ID; retry with the original idempotency key",
        ));
    }
    let parent = match &turn.nesting {
        Some(nesting) => Some(key(
            c,
            "session",
            nesting.parent_session.as_str(),
            &scope,
            false,
        )?),
        None => None,
    };
    let payload = match body {
        Some(text) => {
            let text = codec::text(text.as_materialized()?, MAX_BODY)?;
            metadata_within_bound(&text)?;
            Some(payload(c, seq, "body", &text)?)
        }
        None => None,
    };
    let usage = turn.usage.as_ref();
    let diff = turn.diff.as_ref();
    c.execute(
        "INSERT INTO published_turns(event_seq,project_id,agent_id,session_id,conversation,harness,model_provider,model,vendor_turn,occurred_at_us,role,body_payload,body_omitted_bytes,content_sha256,content_verified,input_tokens,output_tokens,cache_read_tokens,cache_write_tokens,cost_usd,files_changed,insertions,deletions,parent_session_id,nested_agent,nesting_depth)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        crate::sql_value::sql_params![
            seq,
            p,
            agent,
            session,
            turn.conversation,
            turn.harness,
            turn.model_provider,
            turn.model,
            turn.vendor_turn,
            turn.occurred_at_us,
            role(turn.role),
            payload,
            turn.body_omitted_bytes,
            turn.content_sha256.map(|d| d.to_vec()),
            turn.content_verified,
            usage.map(|u| u.input_tokens),
            usage.map(|u| u.output_tokens),
            usage.map(|u| u.cache_read_tokens),
            usage.map(|u| u.cache_write_tokens),
            usage.and_then(|u| u.cost_usd),
            diff.map(|d| d.files_changed),
            diff.map(|d| d.insertions),
            diff.map(|d| d.deletions),
            parent,
            turn.nesting.as_ref().map(|n| n.nested_agent.clone()),
            turn.nesting.as_ref().map(|n| n.depth),
        ],
    )
    .map_err(sql)?;
    Ok(())
}
/// The prose is one JSON object whose decision and paths fit `MAX_METADATA`.
fn metadata_within_bound(text: &str) -> StoreResult<()> {
    let shape = || invalid("published turn prose must be one JSON object");
    let mut prose: serde_json::Value = serde_json::from_str(text).map_err(|_| shape())?;
    prose.as_object_mut().ok_or_else(shape)?.remove("text");
    if prose.to_string().len() > MAX_METADATA {
        return Err(invalid(
            "published turn decision and paths exceed 64 KiB; list fewer paths",
        ));
    }
    Ok(())
}
