//! Channel changes run under the ordinary writer's transaction and savepoint.
mod resume;
mod update;
use super::*;
use crate::channel::{Change, Connection as ChannelConnection, Pairing};
pub(crate) use update::{enqueue_mark, enqueue_reply};

pub(crate) fn load(
    c: &Connection,
    id: &crate::channel::ChannelId,
) -> StoreResult<ChannelConnection> {
    let json: Option<String> = c
        .query_row(
            "SELECT state_json FROM channel_connections WHERE id=?",
            [id.as_str()],
            |r| crate::sql_value::value(r, 0),
        )
        .optional()
        .map_err(sql)?;
    serde_json::from_str(
        &json.ok_or_else(|| fail(StoreErrorCode::ReferenceMissing, "channel absent"))?,
    )
    .map_err(invalid)
}
pub(crate) fn revision(c: &Connection, change: &Change) -> StoreResult<u64> {
    if matches!(change, Change::Connected { .. }) {
        return Ok(1);
    }
    let state = load(c, change.connection())?;
    let expected = match change {
        Change::PairingSeen { expected, .. }
        | Change::PairingConfirmed { expected, .. }
        | Change::PairingRestarted { expected, .. }
        | Change::Disconnected { expected, .. } => Some(*expected),
        Change::CredentialRemoved { .. } => Some(state.revision),
        _ => None,
    };
    if let Some(expected) = expected {
        if expected != state.revision {
            return Err(fail(
                StoreErrorCode::InvalidTransition,
                "channel revision conflict",
            ));
        }
        return state
            .revision
            .checked_add(1)
            .filter(|r| *r <= i64::MAX as u64)
            .ok_or_else(|| invalid("channel revision exhausted"));
    }
    Ok(1)
}
pub(crate) fn apply(
    c: &Connection,
    h: &EventHeader,
    change: Change,
    seq: i64,
    rev: u64,
    facts: Value,
) -> StoreResult<()> {
    if h.door != Door::Host || h.session.is_some() || !matches!(h.actor, Actor::Human(_)) {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "channel changes require native Owner host admission",
        ));
    }
    let mut state = match &change {
        Change::Connected { connection } => {
            validate(connection)?;
            if connection.revision != 1
                || connection.credential_removed
                || !matches!(connection.pairing, Pairing::Challenge { .. })
            {
                return Err(invalid("new channel requires a fresh pairing challenge"));
            }
            connection.clone()
        }
        _ => load(c, change.connection())?,
    };
    if h.actor != Actor::Human(state.owner.clone())
        || h.scope != Scope::Project(state.target.project.clone())
    {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "channel outside exact Owner/project scope",
        ));
    }
    if matches!(
        &change,
        Change::ResumeOffered { .. }
            | Change::ResumeConfirmed { .. }
            | Change::ResumeReleased { .. }
            | Change::ResumeFailed { .. }
    ) {
        resume::apply(c, h, &state, &change, seq)?;
        return codec::aux(c, seq, facts);
    }
    if let Change::UpdateHandled { .. }
    | Change::CursorAdvanced { .. }
    | Change::DelayQueued { .. }
    | Change::OutputStarted { .. }
    | Change::OutputFinished { .. } = &change
    {
        update::apply(c, h, &state, &change, seq)?;
        return codec::aux(c, seq, facts);
    }
    let now: i64 = c
        .query_row(
            "SELECT recorded_at_us FROM events WHERE seq=?",
            [seq],
            |r| crate::sql_value::value(r, 0),
        )
        .map_err(sql)?;
    match &change {
        Change::Connected { .. } => {
            let info = connection::info(c)?;
            if info.id != state.credential.store {
                return Err(invalid("credential belongs to another store"));
            }
            let count: i64 = c
                .query_row(
                    "SELECT count(*) FROM channel_connections WHERE active=1",
                    [],
                    |r| crate::sql_value::value(r, 0),
                )
                .map_err(sql)?;
            if count >= crate::channel::MAX_CONNECTIONS as i64 {
                return Err(fail(
                    StoreErrorCode::Backpressure,
                    "channel connection limit",
                ));
            }
            if let crate::channel::ChannelPolicy::ConfirmResume {
                profile_revision,
                cost_limit,
                ..
            } = state.policy
            {
                if state.resume_configuration.is_none() || cost_limit.is_some() {
                    return Err(invalid(
                        "phone lifecycle configuration/cost policy is unsupported",
                    ));
                }
                let p = project_id(c, &h.scope, false)?;
                let s = scope_key(c, &h.scope, false)?;
                let a = key(c, "agent", state.target.agent.as_str(), &s, false)?;
                let actual: Option<u64> = c
                    .query_row(
                        "SELECT revision FROM profiles WHERE project_id=? AND agent_id=?",
                        crate::sql_value::sql_params![p, a],
                        |r| crate::sql_value::value(r, 0),
                    )
                    .optional()
                    .map_err(sql)?;
                if actual != Some(profile_revision) {
                    return Err(invalid("phone lifecycle profile revision changed"));
                }
            } else if state.resume_configuration.is_some() {
                return Err(invalid("save-only channel cannot carry a lifecycle grant"));
            }
            // The approved selection is checked again at COMMIT, not just in the UI.
            let p = project_id(c, &h.scope, false)?;
            let s = scope_key(c, &h.scope, false)?;
            let agent = key(c, "agent", state.target.agent.as_str(), &s, false)?;
            let actual: Option<u64> = c.query_row("SELECT revision FROM principals WHERE project_id=? AND principal_id=? AND principal_kind='agent'", crate::sql_value::sql_params![p, agent], |r| crate::sql_value::value(r, 0)).optional().map_err(sql)?;
            if actual != Some(state.target.selection_revision) {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "agent selection revision changed",
                ));
            }
            if let Pairing::Challenge { expires_at_us, .. } = state.pairing
                && expires_at_us <= now
            {
                return Err(invalid("pairing challenge already expired"));
            }
        }
        Change::PairingSeen { digest, phone, .. } => {
            validate_phone(phone)?;
            let Pairing::Challenge {
                digest: expected,
                expires_at_us,
            } = state.pairing
            else {
                return Err(invalid("pairing challenge already consumed"));
            };
            if *digest != expected || expires_at_us <= now {
                return Err(invalid("pairing challenge invalid or expired"));
            }
            state.pairing = Pairing::AwaitingApproval {
                phone: phone.clone(),
                expires_at_us,
            };
        }
        Change::PairingConfirmed { .. } => {
            let Pairing::AwaitingApproval {
                ref phone,
                expires_at_us,
            } = state.pairing
            else {
                return Err(invalid("no pending phone identity to approve"));
            };
            if expires_at_us <= now {
                return Err(invalid("pairing approval expired"));
            }
            state.pairing = Pairing::Paired {
                phone: phone.clone(),
            };
        }
        Change::PairingRestarted {
            digest,
            expires_at_us,
            ..
        } => {
            if matches!(state.pairing, Pairing::Revoked | Pairing::Paired { .. })
                || *expires_at_us <= now
            {
                return Err(invalid(
                    "pairing restart requires an unpaired active channel and future expiry",
                ));
            }
            state.pairing = Pairing::Challenge {
                digest: *digest,
                expires_at_us: *expires_at_us,
            };
        }
        Change::Disconnected { .. } => {
            if matches!(state.pairing, Pairing::Revoked) {
                return Err(invalid("channel already revoked; resolve original key"));
            }
            state.pairing = Pairing::Revoked;
            c.execute(
                "UPDATE channel_updates SET pending=0,status_due_at_us=NULL WHERE connection_id=?",
                [state.id.as_str()],
            )
            .map_err(sql)?;
            c.execute("UPDATE channel_outbox SET state='revoked',last_seq=? WHERE connection_id=? AND state='queued'", crate::sql_value::sql_params![seq,state.id.as_str()]).map_err(sql)?;
        }
        Change::CredentialRemoved { credential, .. } => {
            if !matches!(state.pairing, Pairing::Revoked) || *credential != state.credential {
                return Err(invalid(
                    "forget requires revoked binding and exact exclusive credential revision",
                ));
            }
            state.credential_removed = true;
        }
        _ => return Err(invalid("channel change dispatch")),
    }
    state.revision = rev;
    let project = project_id(c, &h.scope, false)?;
    let owner = key(c, "human", state.owner.as_str(), &[0], false)?;
    let json = codec::encode(&state)?;
    if matches!(change, Change::Connected { .. }) {
        c.execute("INSERT INTO channel_connections(id,project_id,owner_id,connector,bot_id,credential_id,credential_revision,revision,active,credential_removed,state_json,last_seq) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",crate::sql_value::sql_params![state.id.as_str(), project, owner, state.connector.as_str(), state.bot.id, state.credential.id.as_str(),state.credential.revision,rev,1,false,json,seq]).map_err(sql)?;
    } else {
        c.execute("UPDATE channel_connections SET revision=?,active=?,credential_removed=?,state_json=?,last_seq=? WHERE id=?",crate::sql_value::sql_params![rev,!matches!(state.pairing, Pairing::Revoked),state.credential_removed,json,seq,state.id.as_str()]).map_err(sql)?;
    }
    if matches!(change, Change::PairingConfirmed { .. }) {
        update::enqueue(c, &state, None, None, "paired", seq)?;
    }
    codec::aux(c, seq, facts)
}
fn validate(state: &ChannelConnection) -> StoreResult<()> {
    let positive = |v: u64| v > 0 && v <= i64::MAX as u64;
    if !positive(state.credential.revision)
        || !positive(state.target.selection_revision)
        || state.credential.owner != state.owner
        || state.bot.username.is_empty()
        || state.bot.username.len() > 64
        || state.bot.display_name.len() > 256
    {
        return Err(invalid("channel identity/credential/selection bounds"));
    }
    if let crate::channel::ChannelPolicy::ConfirmResume {
        profile,
        profile_revision,
        ..
    } = &state.policy
        && (profile.is_empty() || profile.len() > 64 || !positive(*profile_revision))
    {
        return Err(invalid("resume policy bounds"));
    }
    Ok(())
}
fn validate_phone(phone: &crate::channel::PhoneIdentity) -> StoreResult<()> {
    if phone.display_name.len() > 256
        || phone
            .username
            .as_ref()
            .is_some_and(|s| s.len() > 64 || s.chars().any(char::is_control))
    {
        return Err(invalid("private phone identity bounds"));
    }
    Ok(())
}

/// Counts stop at the configured bound; old completed mail is never scanned.
pub(crate) fn capacity(c: &Connection, id: &crate::channel::ChannelId) -> StoreResult<bool> {
    let limit = crate::channel::MAX_PENDING as i64;
    let pending:i64=c.query_row("SELECT count(*) FROM(SELECT 1 FROM channel_updates WHERE connection_id=? AND pending=1 LIMIT ?)",crate::sql_value::sql_params![id.as_str(),limit],|r|crate::sql_value::value(r,0)).map_err(sql)?;
    let output:i64=c.query_row("SELECT count(*) FROM(SELECT 1 FROM channel_outbox WHERE connection_id=? AND state IN ('queued','sending') LIMIT ?)",crate::sql_value::sql_params![id.as_str(),limit],|r|crate::sql_value::value(r,0)).map_err(sql)?;
    Ok(pending < limit && output < limit)
}
