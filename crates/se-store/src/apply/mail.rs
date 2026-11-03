//! Validate a Bell reservation against live indexed recipient debt, without
//! changing message marks or permitting a sender to impersonate its recipient.
use super::*;
use crate::mail::MailNotice;
pub(super) fn validate_offer(
    c: &Connection,
    h: &EventHeader,
    effect: &RecordId,
    observation: &crate::mail::OfferObservation,
    lease: &LeaseIdentity,
) -> StoreResult<()> {
    observation.validate()?;
    if lease.mode != LeaseMode::Host || lease.generation != observation.generation {
        return Err(fail(
            StoreErrorCode::GenerationChanged,
            "observed Bell offers require the matching host writer generation",
        ));
    }
    let p = project_id(c, &h.scope, false)?;
    let requested: i64 = c
        .query_row(
            "SELECT requested_seq FROM effects WHERE project_id=? AND effect_id=?",
            crate::sql_value::sql_params![p, effect.as_bytes()],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let original = crate::codec::event::load_event(c, requested, &crate::connection::info(c)?)?;
    let EventBody::EffectRequested {
        kind: EffectKind::Bell,
        intent: EffectIntent::MailNotice(notice),
        ..
    } = original.body
    else {
        return Err(invalid(
            "typed mail observations require an original Bell notice reservation",
        ));
    };
    if observation.notice_id != notice.notice_id
        || observation.target_agent != notice.target_agent
        || observation.session != notice.session
        || observation.epoch != notice.epoch
        || observation.generation != notice.generation
        || observation.fingerprint != notice.fingerprint
        || observation.digest != notice.digest
        || observation.observed_at_us < original.header.occurred_at_us
        || observation.observed_at_us > h.occurred_at_us
    {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "mail offer observation differs from the original notice target or time window",
        ));
    }
    Ok(())
}
pub(super) fn validate(
    c: &Connection,
    h: &EventHeader,
    principal: &Option<Actor>,
    notice: &MailNotice,
) -> StoreResult<()> {
    notice.validate()?;
    let info = crate::connection::info(c)?;
    if notice.through.store != info.id || notice.through.incarnation != info.incarnation {
        return Err(fail(
            StoreErrorCode::GenerationChanged,
            "mail boundary belongs to another store incarnation",
        ));
    }
    if principal.as_ref() != Some(&Actor::Agent(notice.target_agent.clone())) {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "mail reservation principal differs from recipient",
        ));
    }
    let p = project_id(c, &h.scope, false)?;
    let s = scope_key(c, &h.scope, false)?;
    let agent = key(c, "agent", notice.target_agent.as_str(), &s, false)?;
    let session = key(c, "session", notice.session.as_str(), &s, false)?;
    let live:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=? AND agent_id=? AND session_id=? AND state='active')",crate::sql_value::sql_params![p,agent,session],|r|r.get(0)).map_err(sql)?;
    if !live {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "mail target session is not active for this recipient",
        ));
    }
    let current: Option<(u64, String)> = c
        .query_row(
            "SELECT owner_generation,owner_epoch FROM runtime_owner WHERE singleton=1",
            [],
            |r| Ok((crate::sql_value::value(r, 0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    if !current.is_some_and(|(g, e)| {
        g == notice.generation
            && serde_json::from_str::<se_types::HostEpoch>(&e)
                .is_ok_and(|epoch| epoch == notice.epoch)
    }) {
        return Err(fail(
            StoreErrorCode::GenerationChanged,
            "mail notice names a different host epoch/generation",
        ));
    }
    let high: u64 = c
        .query_row("SELECT COALESCE(MAX(seq),0) FROM events", [], |r| {
            crate::sql_value::value(r, 0)
        })
        .map_err(sql)?;
    if notice.through.sequence > high {
        return Err(invalid("mail boundary is ahead of committed history"));
    }
    let mut query=c.prepare("SELECT d.message_id FROM messages d JOIN marks m ON m.message_seq=d.sent_seq WHERE d.project_id=? AND d.recipient_id=? AND m.read_seq IS NULL AND m.dismissed_seq IS NULL AND d.superseded_by IS NULL AND d.sent_seq<=? ORDER BY d.sent_seq LIMIT ?").map_err(sql)?;
    let wanted = query
        .query_map(
            crate::sql_value::sql_params![p, agent, notice.through.sequence, notice.ids.len()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .map_err(sql)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sql)?;
    let actual = notice
        .ids
        .iter()
        .map(|id| key(c, "message", id.as_str(), &s, false))
        .collect::<StoreResult<Vec<_>>>()?;
    if wanted != actual {
        return Err(fail(
            StoreErrorCode::RevisionConflict,
            "notice must reserve the oldest unresolved recipient messages through its checked boundary",
        ));
    }
    // The existing partial recipient index excludes terminal effects. An
    // in-flight notice is reconciled/reused, never replaced by another queue.
    let pending:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM effects f INDEXED BY effects_principal_pending JOIN aux_data a ON a.event_seq=f.requested_seq WHERE f.project_id=? AND f.principal_id=? AND f.state IN ('pending','offered') AND json_extract(a.facts,'$.intent.mail_notice.session')=? AND json_extract(a.facts,'$.intent.mail_notice.generation')=? AND json_extract(a.facts,'$.intent.mail_notice.fingerprint')=?)",crate::sql_value::sql_params![p,agent,notice.session.as_str(),notice.generation,crate::codec::encode(&notice.fingerprint)?],|r|r.get(0)).map_err(sql)?;
    if pending {
        return Err(fail(
            StoreErrorCode::RevisionConflict,
            "reuse or reconcile the original unresolved mail reservation",
        ));
    }
    Ok(())
}
