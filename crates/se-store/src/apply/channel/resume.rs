//! Phone lifecycle authority is consumed in the normal C1 writer transaction.
use super::*;
use crate::channel::{ActionId, ResumeAction};
pub(super) fn action(c: &Connection, id: &ActionId) -> StoreResult<ResumeAction> {
    let json: String = c
        .query_row(
            "SELECT action_json FROM channel_actions WHERE id=?",
            [id.as_str()],
            |r| crate::sql_value::value(r, 0),
        )
        .map_err(sql)?;
    serde_json::from_str(&json).map_err(invalid)
}
fn target(
    c: &Connection,
    state: &ChannelConnection,
    action: &ResumeAction,
    exclude: Option<&se_types::SessionId>,
) -> StoreResult<()> {
    if action.binding_revision != state.revision
        || state.resume_configuration != Some(action.target.configuration)
        || !matches!(state.pairing, Pairing::Paired { .. })
    {
        return Err(invalid("phone lifecycle binding revoked or changed"));
    }
    let crate::channel::ChannelPolicy::ConfirmResume {
        profile_revision,
        cost_limit: None,
        ..
    } = state.policy
    else {
        return Err(invalid("phone lifecycle is not preauthorized"));
    };
    if action.target.profile_revision != profile_revision
        || action.target.principal_revision != state.target.selection_revision
    {
        return Err(invalid(
            "phone lifecycle selection/profile differs from Owner consent",
        ));
    }
    let scope = Scope::Project(state.target.project.clone());
    let s = scope_key(c, &scope, false)?;
    let p = project_id(c, &scope, false)?;
    let a = key(c, "agent", state.target.agent.as_str(), &s, false)?;
    let principal: u64 = c
        .query_row(
            "SELECT revision FROM principals WHERE project_id=? AND principal_id=?",
            crate::sql_value::sql_params![p, a],
            |r| crate::sql_value::value(r, 0),
        )
        .map_err(sql)?;
    let profile: u64 = c
        .query_row(
            "SELECT revision FROM profiles WHERE project_id=? AND agent_id=?",
            crate::sql_value::sql_params![p, a],
            |r| crate::sql_value::value(r, 0),
        )
        .map_err(sql)?;
    if principal != action.target.principal_revision || profile != action.target.profile_revision {
        return Err(invalid("phone lifecycle principal/profile head changed"));
    }
    let excluded = exclude
        .map(|id| key(c, "session", id.as_str(), &s, false))
        .transpose()?;
    let previous:Option<Vec<u8>>=c.query_row("SELECT e.event_id FROM sessions x JOIN events e ON e.seq=x.last_seq WHERE x.project_id=? AND x.agent_id=? AND (? IS NULL OR x.session_id<>?) ORDER BY x.first_seq DESC LIMIT 1",crate::sql_value::sql_params![p,a,excluded,excluded],|r|crate::sql_value::value(r,0)).optional().map_err(sql)?;
    let expected = action
        .target
        .previous_session_event
        .as_ref()
        .map(|id| key(c, "event", id.as_str(), &s, false))
        .transpose()?;
    if previous != expected {
        return Err(invalid("phone lifecycle conversation/session head changed"));
    }
    let live:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=? AND agent_id=? AND state IN ('prepared','active') AND (? IS NULL OR session_id<>?))",crate::sql_value::sql_params![p,a,excluded,excluded],|r|crate::sql_value::value(r,0)).map_err(sql)?;
    if live {
        return Err(invalid(
            "phone lifecycle cannot override live or unresolved preparation",
        ));
    }
    Ok(())
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    state: &ChannelConnection,
    change: &Change,
    seq: i64,
) -> StoreResult<()> {
    let now: i64 = c
        .query_row(
            "SELECT recorded_at_us FROM events WHERE seq=?",
            [seq],
            |r| crate::sql_value::value(r, 0),
        )
        .map_err(sql)?;
    let mut value = match change {
        Change::ResumeOffered { action } => action.clone(),
        Change::ResumeConfirmed { action, .. }
        | Change::ResumeReleased { action, .. }
        | Change::ResumeFailed { action, .. } => self::action(c, action)?,
        _ => return Err(invalid("phone lifecycle dispatch")),
    };
    if value.connection != state.id {
        return Err(invalid("phone lifecycle action is outside connection"));
    }
    match change {
        Change::ResumeOffered { .. } => {
            target(c, state, &value, None)?;
            let Pairing::Paired { phone } = &state.pairing else {
                return Err(invalid("phone is unpaired"));
            };
            if value.state != "offered"
                || value.code.is_some()
                || value.expires_at_us <= now
                || value.expires_at_us > now.saturating_add(600000000)
                || value.subject != phone.subject
                || value.private_chat != phone.private_chat
            {
                return Err(invalid("phone lifecycle action bounds or subject"));
            }
            let s = scope_key(c, &h.scope, false)?;
            let m = key(c, "message", value.message.as_str(), &s, false)?;
            let saved:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM channel_updates WHERE connection_id=? AND message_id=? AND receipt_id IS NOT NULL)",crate::sql_value::sql_params![state.id.as_str(),m],|r|crate::sql_value::value(r,0)).map_err(sql)?;
            if !saved {
                return Err(invalid("phone lifecycle requires original saved mail"));
            }
            c.execute("INSERT INTO channel_actions(id,connection_id,original_id,state,action_json,last_seq) VALUES(?,?,?,'offered',?,?)",crate::sql_value::sql_params![value.id.as_str(),state.id.as_str(),m,codec::encode(&value)?,seq]).map_err(sql)?;
            update::enqueue(c, state, Some(&m), None, "resume", seq)?;
            return Ok(());
        }
        Change::ResumeConfirmed {
            subject,
            private_chat,
            ..
        } => {
            target(c, state, &value, None)?;
            if value.state != "offered"
                || value.expires_at_us <= now
                || value.subject != *subject
                || value.private_chat != *private_chat
            {
                return Err(invalid(
                    "phone confirmation expired, used or outside exact subject",
                ));
            }
            value.state = "confirmed".into();
        }
        Change::ResumeReleased { session, .. } => {
            target(c, state, &value, Some(session))?;
            if value.state != "confirmed" || value.expires_at_us <= now {
                return Err(invalid("phone confirmation expired or already consumed"));
            }
            let s = scope_key(c, &h.scope, false)?;
            let p = project_id(c, &h.scope, false)?;
            let session = key(c, "session", session.as_str(), &s, false)?;
            let agent = key(c, "agent", state.target.agent.as_str(), &s, false)?;
            let valid:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sessions x JOIN events e ON e.seq=x.first_seq JOIN events current ON current.seq=? WHERE x.project_id=? AND x.session_id=? AND x.agent_id=? AND x.state='prepared' AND e.operation_id=current.operation_id)",crate::sql_value::sql_params![seq,p,session,agent],|r|crate::sql_value::value(r,0)).map_err(sql)?;
            if !valid {
                return Err(invalid(
                    "phone grant must be consumed by the same C1 session preparation",
                ));
            }
            value.state = "released".into();
            let m = key(c, "message", value.message.as_str(), &s, false)?;
            update::enqueue(c, state, Some(&m), None, "resume_status", seq)?;
        }
        Change::ResumeFailed { code, .. } => {
            if code.is_empty()
                || code.len() > 64
                || !code
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(invalid("phone lifecycle failure code bounds"));
            }
            value.state = "failed".into();
            value.code = Some(code.clone());
            if matches!(state.pairing, Pairing::Paired { .. })
                && state.revision == value.binding_revision
            {
                let s = scope_key(c, &h.scope, false)?;
                let m = key(c, "message", value.message.as_str(), &s, false)?;
                update::enqueue(c, state, Some(&m), None, "resume_failed", seq)?;
            }
        }
        _ => return Err(invalid("phone lifecycle dispatch")),
    }
    c.execute(
        "UPDATE channel_actions SET state=?,action_json=?,last_seq=? WHERE id=?",
        crate::sql_value::sql_params![value.state, codec::encode(&value)?, seq, value.id.as_str()],
    )
    .map_err(sql)?;
    Ok(())
}
