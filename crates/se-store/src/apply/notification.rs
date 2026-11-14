//! Notification projections belong to each addressed recipient, independently
//! of accepted input, read/dismiss marks and immutable message content.
use super::*;

pub(super) fn require_schema(c: &Connection, quiet: bool) -> StoreResult<()> {
    if quiet && connection::info(c)?.schema_version < 4 {
        return Err(fail(
            StoreErrorCode::MigrationFailed,
            "quiet notification intent requires schema 4; start se up for the verified migration",
        ));
    }
    Ok(())
}

pub(super) fn sent(c: &Connection, seq: i64, recipient: &[u8], quiet: bool) -> StoreResult<()> {
    if connection::info(c)?.schema_version < 4 {
        return Ok(());
    }
    let human: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM principals p JOIN message_deliveries d ON d.project_id=p.project_id AND d.recipient_id=p.principal_id WHERE d.sent_seq=? AND d.recipient_id=? AND p.principal_kind='human')", crate::sql_value::sql_params![seq,recipient], |r|r.get(0)).map_err(sql)?;
    let remote = if connection::info(c)?.schema_version >= 12 {
        c.query_row(
            "SELECT EXISTS(SELECT 1 FROM remote_reply_outbox WHERE event_seq=?)",
            [seq],
            |r| r.get::<_, bool>(0),
        )
        .map_err(sql)?
    } else {
        false
    };
    let state = if human || remote {
        "not-applicable"
    } else if quiet {
        "quiet"
    } else {
        "pending"
    };
    let n=c.execute("UPDATE message_deliveries SET quiet=?,wake_state=?,wake_event_seq=? WHERE sent_seq=? AND recipient_id=?",crate::sql_value::sql_params![quiet,state,seq,seq,recipient]).map_err(sql)?;
    if n != 1 {
        return Err(fail(
            StoreErrorCode::ProjectionInconsistent,
            "notification recipient projection missing",
        ));
    }
    Ok(())
}

pub(super) fn reserved(
    c: &Connection,
    h: &EventHeader,
    notice: &crate::mail::MailNotice,
    seq: i64,
) -> StoreResult<()> {
    project(c, h, notice, seq, "reserved", None)
}

pub(super) fn observed(
    c: &Connection,
    h: &EventHeader,
    effect: &RecordId,
    observation: &crate::mail::OfferObservation,
    seq: i64,
) -> StoreResult<()> {
    if connection::info(c)?.schema_version < 4 {
        return Ok(());
    }
    let p = project_id(c, &h.scope, false)?;
    let requested: i64 = c
        .query_row(
            "SELECT requested_seq FROM effects WHERE project_id=? AND effect_id=?",
            crate::sql_value::sql_params![p, effect.as_bytes()],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let original = codec::event::load_event(c, requested, &connection::info(c)?)?;
    let EventBody::EffectRequested {
        intent: EffectIntent::MailNotice(notice),
        ..
    } = original.body
    else {
        return Err(invalid("notification observation is not mail"));
    };
    use crate::mail::OfferReport::*;
    let (state, code) = match &observation.report {
        Held => ("held", None),
        Failed { code } => ("failed", Some(code.as_str())),
        Unknown { code } => ("unknown", Some(code.as_str())),
        TransportWritten { .. } | VendorReported { .. } | NativeAdmitted { .. } => {
            ("offered", None)
        }
    };
    project(c, h, &notice, seq, state, code)
}

fn project(
    c: &Connection,
    h: &EventHeader,
    notice: &crate::mail::MailNotice,
    seq: i64,
    state: &str,
    code: Option<&str>,
) -> StoreResult<()> {
    if connection::info(c)?.schema_version < 4 {
        return Ok(());
    }
    let p = project_id(c, &h.scope, false)?;
    let s = scope_key(c, &h.scope, false)?;
    let recipient = key(c, "agent", notice.target_agent.as_str(), &s, false)?;
    for message in &notice.ids {
        let id = key(c, "message", message.as_str(), &s, false)?;
        let n=c.execute("UPDATE message_deliveries SET wake_state=?,wake_event_seq=?,wake_code=? WHERE project_id=? AND message_id=? AND recipient_id=? AND quiet=0 AND (wake_event_seq IS NULL OR wake_event_seq<?)",crate::sql_value::sql_params![state,seq,code,p,id,recipient,seq]).map_err(sql)?;
        if n != 1 {
            return Err(fail(
                StoreErrorCode::ProjectionInconsistent,
                "notice names missing or quiet recipient notification",
            ));
        }
    }
    Ok(())
}
