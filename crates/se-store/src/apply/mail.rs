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
        return Err(scope_mismatch(
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
        return Err(scope_mismatch(
            "mail reservation principal differs from recipient",
        ));
    }
    let p = project_id(c, &h.scope, false)?;
    let s = scope_key(c, &h.scope, false)?;
    let agent = key(c, "agent", notice.target_agent.as_str(), &s, false)?;
    let session = key(c, "session", notice.session.as_str(), &s, false)?;
    let live:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=? AND agent_id=? AND session_id=? AND state='active')",crate::sql_value::sql_params![p,agent,session],|r|r.get(0)).map_err(sql)?;
    if !live {
        return Err(invalid_transition(
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
    for id in &notice.ids {
        let message = key(c, "message", id.as_str(), &s, false)?;
        let eligible: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM message_deliveries WHERE project_id=? AND recipient_id=? AND message_id=? AND read_seq IS NULL AND dismissed_seq IS NULL AND superseded_by IS NULL AND sent_seq<=?)",
            crate::sql_value::sql_params![p, agent, message, notice.through.sequence], |r| r.get(0),
        ).map_err(sql)?;
        if !eligible {
            return Err(revision_conflict(
                "notice contains a message that is no longer unread for this recipient at its checked boundary",
            ));
        }
    }
    validate_unconsumed(c, &p, &s, &agent, notice, &info)
}

fn validate_unconsumed(
    c: &Connection,
    p: &[u8],
    s: &[u8],
    agent: &[u8],
    notice: &MailNotice,
    info: &crate::StoreInfo,
) -> StoreResult<()> {
    // A captured input may leave unread debt, but an unconsumed notice must
    // be settled in this transaction before another notice can be reserved.
    let pending: Vec<i64> = {
        let mut q = c.prepare("SELECT requested_seq FROM effects f INDEXED BY effects_principal_pending JOIN aux_data a ON a.event_seq=f.requested_seq WHERE f.project_id=? AND f.principal_id=? AND f.state IN ('pending','offered') AND json_extract(a.facts,'$.intent.mail_notice.session')=? AND json_extract(a.facts,'$.intent.mail_notice.generation')=? AND json_extract(a.facts,'$.intent.mail_notice.fingerprint')=?").map_err(sql)?;
        let rows = q
            .query_map(
                crate::sql_value::sql_params![
                    p,
                    agent,
                    notice.session.as_str(),
                    notice.generation,
                    crate::codec::encode(&notice.fingerprint)?
                ],
                |r| r.get(0),
            )
            .map_err(sql)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(sql)?
    };
    for seq in pending {
        let original = crate::codec::event::load_event(c, seq, info)?;
        let EventBody::EffectRequested {
            intent: EffectIntent::MailNotice(old),
            ..
        } = original.body
        else {
            return Err(invalid("pending mail index is inconsistent"));
        };
        for id in &old.ids {
            let message = key(c, "message", id.as_str(), s, false)?;
            let unconsumed: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM message_deliveries WHERE project_id=? AND recipient_id=? AND message_id=? AND delivered_seq IS NULL AND read_seq IS NULL AND dismissed_seq IS NULL AND superseded_by IS NULL)", crate::sql_value::sql_params![p,agent,message], |r| r.get(0)).map_err(sql)?;
            if unconsumed {
                return Err(revision_conflict(
                    "reconcile the unconsumed notice before another reservation",
                ));
            }
        }
    }
    Ok(())
}
