pub(crate) mod capture;
pub(crate) mod event;
pub(crate) mod process;
pub(crate) mod semantic;
pub(crate) mod session;
// Closed wave-1 metadata codec; text lives only in its typed payload column.
use crate::{error::*, identity::*, *};
use rusqlite::Connection;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
pub(crate) fn encode<T: Serialize>(v: &T) -> StoreResult<String> {
    serde_json::to_string(v).map_err(invalid)
}
pub(crate) fn field<T: DeserializeOwned>(v: &Value, k: &str) -> StoreResult<T> {
    serde_json::from_value(
        v.get(k)
            .cloned()
            .ok_or_else(|| invalid(format!("missing stored field {k}")))?,
    )
    .map_err(invalid)
}
pub(crate) fn aux(c: &Connection, seq: i64, v: Value) -> StoreResult<()> {
    c.execute(
        "INSERT INTO aux_data(event_seq,facts) VALUES(?,?)",
        crate::sql_value::sql_params![seq, encode(&v)?],
    )
    .map_err(sql)?;
    Ok(())
}
pub(crate) fn facts(c: &Connection, seq: i64) -> StoreResult<Value> {
    let s: String = c
        .prepare_cached("SELECT facts FROM aux_data WHERE event_seq=?")
        .map_err(sql)?
        .query_row([seq], |r| crate::sql_value::value(r, 0))
        .map_err(sql)?;
    serde_json::from_str(&s).map_err(invalid)
}
pub(crate) fn text(input: InputText, max: usize) -> StoreResult<String> {
    let s = match input {
        InputText::Inline(s) => s,
        InputText::Staged(_) => return later("staged capture text"),
    };
    if s.len() > max {
        return Err(fail(
            StoreErrorCode::BodyTooLarge,
            format!("text is {} bytes; limit {max}", s.len()),
        ));
    }
    Ok(s)
}
pub(crate) fn stored_text(c: &Connection, seq: i64, field: &str) -> StoreResult<StoredText> {
    let (length, encoding, hash): (u64, String, Vec<u8>) = c
        .prepare_cached(
            "SELECT length(content),encoding,sha256 FROM payloads WHERE event_seq=? AND field=?",
        )
        .map_err(sql)?
        .query_row(crate::sql_value::sql_params![seq, field], |r| {
            Ok((
                crate::sql_value::value(r, 0)?,
                crate::sql_value::value(r, 1)?,
                crate::sql_value::value(r, 2)?,
            ))
        })
        .map_err(sql)?;
    if length > 1024 * 1024 || encoding != "utf8" || hash.len() != 32 {
        return Err(fail(
            StoreErrorCode::Unreadable,
            "stored text length/encoding/hash is invalid",
        ));
    }
    let bytes: Vec<u8> = c
        .prepare_cached("SELECT content FROM payloads WHERE event_seq=? AND field=?")
        .map_err(sql)?
        .query_row(crate::sql_value::sql_params![seq, field], |r| {
            crate::sql_value::value(r, 0)
        })
        .map_err(sql)?;
    use sha2::{Digest, Sha256};
    if Sha256::digest(&bytes).as_slice() != hash {
        return Err(fail(
            StoreErrorCode::Unreadable,
            "stored text hash differs from its immutable payload",
        ));
    }
    Ok(StoredText::Present(String::from_utf8(bytes).map_err(
        |e| fail(StoreErrorCode::Unreadable, e.to_string()),
    )?))
}
pub(crate) fn body(
    c: &Connection,
    seq: i64,
    kind: &str,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(match kind {
        "process.registered" | "process.transition" => process::body(c, seq, kind, scope)?,
        "message.sent" => {
            let (message,recipient,kind,refs,reply):(Vec<u8>,Vec<u8>,String,String,Option<Vec<u8>>)=c.prepare_cached("SELECT message_id,recipient_id,message_kind,refs,reply_to FROM message_data WHERE event_seq=?").map_err(sql)?.query_row([seq],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?,crate::sql_value::value(r,3)?,crate::sql_value::value(r,4)?))).map_err(sql)?;
            let s = scope_key(c, scope, false)?;
            MessageSent {
                message: wire(c, "message", &message, &s)?.parse().map_err(invalid)?,
                recipient: actor(c, &recipient, &s)?,
                kind,
                body: stored_text(c, seq, "body")?,
                refs: serde_json::from_str(&refs).map_err(invalid)?,
                reply_to: reply
                    .map(|v| wire(c, "message", &v, &s).and_then(|v| v.parse().map_err(invalid)))
                    .transpose()?,
            }
        }
        "message.read" | "message.dismissed" | "message.delivered" => {
            let (message,recipient,evidence):(Vec<u8>,Vec<u8>,Option<Vec<u8>>)=c.query_row("SELECT d.message_id,m.recipient_id,m.evidence_event FROM mark_data m JOIN message_data d
                    ON d.event_seq=m.message_seq WHERE m.event_seq=?",[seq],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?))).map_err(sql)?;
            let s = scope_key(c, scope, false)?;
            let message = wire(c, "message", &message, &s)?.parse().map_err(invalid)?;
            let recipient = actor(c, &recipient, &s)?;
            match kind {
                "message.read" => MessageRead { message, recipient },
                "message.dismissed" => MessageDismissed { message, recipient },
                _ => MessageDelivered {
                    message,
                    recipient,
                    evidence: wire(
                        c,
                        "event",
                        &evidence.ok_or_else(|| invalid("delivered without evidence"))?,
                        &s,
                    )?
                    .parse()
                    .map_err(invalid)?,
                },
            }
        }
        "working_state.set" => {
            let (agent, expected): (Vec<u8>, Option<u64>) = c
                .query_row(
                    "SELECT agent_id,expected_revision FROM working_state_data WHERE event_seq=?",
                    [seq],
                    |r| {
                        Ok((
                            crate::sql_value::value(r, 0)?,
                            crate::sql_value::value(r, 1)?,
                        ))
                    },
                )
                .map_err(sql)?;
            WorkingStateSet {
                agent: wire(c, "agent", &agent, &scope_key(c, scope, false)?)?
                    .parse()
                    .map_err(invalid)?,
                text: stored_text(c, seq, "body")?,
                expected: expected
                    .map(revision)
                    .transpose()?
                    .map(Expected::Revision)
                    .unwrap_or(Expected::Absent),
            }
        }
        "decision.proposed"
        | "decision.ratified"
        | "decision.rejected"
        | "decision.retracted"
        | "decision.superseded" => crate::apply::decision::decode(c, seq, kind, scope)?,
        "session.prepared" | "session.activated" | "session.ended" | "session.revoked" => {
            session::decode(c, seq, kind, scope)?
        }
        "session.turn" | "capture.source" | "capture.progress" | "capture.failed"
        | "capture.suppressed" => capture::decode(c, seq, kind, scope)?,
        _ => {
            let v = facts(c, seq)?;
            match kind {
                "project.registered" => ProjectRegistered {
                    project: field(&v, "project")?,
                    name: field(&v, "name")?,
                    roots: field(&v, "roots")?,
                    owner: field(&v, "owner")?,
                    history_from: field(&v, "history_from")?,
                    expected: field(&v, "expected")?,
                },
                "principal.registered" => PrincipalRegistered {
                    principal: field(&v, "principal")?,
                    kind: field(&v, "kind")?,
                    owner: field(&v, "owner")?,
                    created_by: field(&v, "created_by")?,
                    name: field(&v, "name")?,
                    role: field(&v, "role")?,
                    expected: field(&v, "expected")?,
                },
                "principal.renamed" => PrincipalRenamed {
                    principal: field(&v, "principal")?,
                    name: field(&v, "name")?,
                    expected: field(&v, "expected")?,
                },
                "profile.saved" => ProfileSaved {
                    agent: field(&v, "agent")?,
                    profile: field(&v, "profile")?,
                    expected: field(&v, "expected")?,
                },
                "grant.recorded" => GrantRecorded {
                    principal: field(&v, "principal")?,
                    key: field(&v, "key")?,
                    active: field(&v, "active")?,
                    expected: field(&v, "expected")?,
                },
                "credential.issued" => CredentialIssued {
                    credential: field(&v, "credential")?,
                    session: field(&v, "session")?,
                    purpose: field(&v, "purpose")?,
                    secret_sha256: field(&v, "secret_sha256")?,
                    expires_at_us: field(&v, "expires_at_us")?,
                    activation_deadline_us: field(&v, "activation_deadline_us")?,
                    expected: field(&v, "expected")?,
                },
                "credential.activated" => CredentialActivated {
                    credential: field(&v, "credential")?,
                    session: field(&v, "session")?,
                    expected: field(&v, "expected")?,
                    first_request: field(&v, "first_request")?,
                },
                "credential.revoked" => CredentialRevoked {
                    credential: field(&v, "credential")?,
                    expected: field(&v, "expected")?,
                    reason: stored_text(c, seq, "reason")?,
                },
                "cursor.recorded" => CursorRecorded {
                    cursor: Box::new(crate::apply::cursor::decode(
                        v.get("cursor")
                            .ok_or_else(|| invalid("stored cursor record missing"))?,
                    )?),
                },
                "cursor.acknowledged" => CursorAcknowledged {
                    cursor: field(&v, "cursor")?,
                    expected: field(&v, "expected")?,
                    evidence: field(&v, "evidence")?,
                },
                "project.removed" => ProjectRemoved {
                    project: field(&v, "project")?,
                    expected: field(&v, "expected")?,
                    witnesses: field(&v, "witnesses")?,
                    preserved: field(&v, "preserved")?,
                },
                "effect.requested" => {
                    let intent: EffectIntent = field(&v, "intent")?;
                    if let EffectIntent::MailNotice(notice) = &intent {
                        notice.validate().map_err(|error| {
                            fail(
                                StoreErrorCode::Unreadable,
                                format!("stored mail notice: {}", error.cause),
                            )
                        })?;
                    }
                    EffectRequested {
                        principal: field(&v, "principal")?,
                        effect: field(&v, "effect")?,
                        kind: field(&v, "kind")?,
                        intent,
                        cause: field(&v, "cause")?,
                        request_key: field(&v, "request_key")?,
                    }
                }
                "effect.offered" => {
                    let evidence: crate::mail::OfferEvidence = field(&v, "evidence")?;
                    if let crate::mail::OfferEvidence::Observed(observation) = &evidence {
                        observation.validate().map_err(|error| {
                            fail(
                                StoreErrorCode::Unreadable,
                                format!("stored Bell offer observation: {}", error.cause),
                            )
                        })?;
                    }
                    EffectOffered {
                        effect: field(&v, "effect")?,
                        principal: field(&v, "principal")?,
                        attempt: field(&v, "attempt")?,
                        evidence,
                    }
                }
                "effect.settled" => EffectSettled {
                    effect: field(&v, "effect")?,
                    expected: field(&v, "expected")?,
                    outcome: field(&v, "outcome")?,
                    evidence: field(&v, "evidence")?,
                    failure: field(&v, "failure")?,
                    attempts: field(&v, "attempts")?,
                },
                "integration.recorded" => IntegrationRecorded {
                    integration: field(&v, "integration")?,
                    path: field(&v, "path")?,
                    key: field(&v, "key")?,
                    marker: field(&v, "marker")?,
                    prior_sha256: field(&v, "prior_sha256")?,
                    written_sha256: field(&v, "written_sha256")?,
                    state: field(&v, "state")?,
                    witness: field(&v, "witness")?,
                    expected: field(&v, "expected")?,
                },
                "runtime.owner" => RuntimeOwnerEstablished {
                    epoch: field(&v, "epoch")?,
                    generation: field(&v, "generation")?,
                    expected_owner_generation: field(&v, "expected_owner_generation")?,
                    expected: field(&v, "expected")?,
                    witnesses: field(&v, "witnesses")?,
                    recovered: None,
                },
                _ => {
                    return Err(fail(
                        StoreErrorCode::Unreadable,
                        format!("unsupported stored event kind {kind}"),
                    ));
                }
            }
        }
    })
}
pub(crate) fn revision(value: u64) -> StoreResult<Revision> {
    if value > i64::MAX as u64 {
        return Err(invalid("entity revision exceeds store range"));
    }
    Ok(Revision {
        value: std::num::NonZeroU64::new(value).ok_or_else(|| invalid("zero entity revision"))?,
    })
}
pub(crate) fn metadata<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    use EventBody::*;
    Ok(match body {
        ProjectRegistered {
            project,
            name,
            roots,
            owner,
            history_from,
            expected,
        } => (
            "project.registered",
            json!({"project":project,"name":name,"roots":roots,"owner":owner,"history_from":history_from,"expected":expected}),
        ),
        PrincipalRegistered {
            principal,
            kind,
            owner,
            created_by,
            name,
            role,
            expected,
        } => (
            "principal.registered",
            json!({"principal":principal,"kind":kind,"owner":owner,"created_by":created_by,"name":name,"role":role,"expected":expected}),
        ),
        PrincipalRenamed {
            principal,
            name,
            expected,
        } => (
            "principal.renamed",
            json!({"principal":principal,"name":name,"expected":expected}),
        ),
        ProfileSaved {
            agent,
            profile,
            expected,
        } => (
            "profile.saved",
            json!({"agent":agent,"profile":profile,"expected":expected}),
        ),
        GrantRecorded {
            principal,
            key,
            active,
            expected,
        } => (
            "grant.recorded",
            json!({"principal":principal,"key":key,"active":active,"expected":expected}),
        ),
        ProcessRegistered { identity, initial } => (
            "process.registered",
            json!({"identity":identity,"initial":initial}),
        ),
        ProcessTransition {
            process,
            identity,
            expected,
            from,
            to,
            observation,
            outcome,
            containment,
        } => (
            "process.transition",
            json!({"process":process,"identity":identity,"expected":expected,"from":from,"to":to,"observation":observation,"outcome":outcome,"containment":containment}),
        ),
        SessionPrepared {
            session,
            agent,
            provider,
            surface,
            native_ref,
            consent,
            generation,
            expected,
        } => (
            "session.prepared",
            json!({"session":session,"agent":agent,"provider":provider,"surface":surface,"native_ref":native_ref,"consent":consent,"generation":generation,"expected":expected}),
        ),
        SessionActivated {
            session,
            expected,
            incumbent,
            process,
            containment,
            witnesses,
        } => (
            "session.activated",
            json!({"session":session,"expected":expected,"incumbent":incumbent,"process":process,"containment":containment,"witnesses":witnesses}),
        ),
        SessionEnded {
            session,
            expected,
            final_turn,
            final_cursor,
            ..
        } => (
            "session.ended",
            json!({"session":session,"expected":expected,"final_turn":final_turn,"final_cursor":final_cursor}),
        ),
        SessionRevoked {
            session, expected, ..
        } => (
            "session.revoked",
            json!({"session":session,"expected":expected}),
        ),
        SessionTurn {
            turn,
            agent,
            session,
            provider,
            vendor_ref,
            role,
            evidence,
            ..
        } => (
            "session.turn",
            json!({"turn":turn,"agent":agent,"session":session,"provider":provider,"vendor_ref":vendor_ref,"role":role,"evidence":evidence}),
        ),
        CaptureSource {
            source,
            session,
            consent,
            native_ref,
            incarnation,
            expected,
        } => (
            "capture.source",
            json!({"capture_kind":"source","source":source,"session":session,"consent":consent,"native_ref":native_ref,"incarnation":incarnation,"expected":expected}),
        ),
        CaptureProgress {
            source,
            expected,
            incarnation,
            old_offset,
            new_offset,
            last_turn,
        } => (
            "capture.progress",
            json!({"capture_kind":"progress","source":source,"expected":expected,"incarnation":incarnation,"old_offset":old_offset,"new_offset":new_offset,"last_turn":last_turn}),
        ),
        CaptureFailed {
            source,
            session,
            from_offset,
            to_offset,
            code,
            cause,
            retry,
        } => (
            "capture.failed",
            json!({"source":source,"session":session,"from_offset":from_offset,"to_offset":to_offset,"code":code,"cause":cause,"retry":retry}),
        ),
        CaptureSuppressed {
            source,
            session,
            expected,
            reason,
            from_offset,
            to_offset,
            count,
        } => (
            "capture.suppressed",
            json!({"source":source,"session":session,"expected":expected,"reason":reason,"from_offset":from_offset,"to_offset":to_offset,"count":count}),
        ),
        CredentialIssued {
            credential,
            session,
            purpose,
            secret_sha256,
            expires_at_us,
            activation_deadline_us,
            expected,
        } => (
            "credential.issued",
            json!({"credential":credential,"session":session,"purpose":purpose,"secret_sha256":secret_sha256,"expires_at_us":expires_at_us,"activation_deadline_us":activation_deadline_us,"expected":expected}),
        ),
        CredentialActivated {
            credential,
            session,
            expected,
            first_request,
        } => (
            "credential.activated",
            json!({"credential":credential,"session":session,"expected":expected,"first_request":first_request}),
        ),
        CredentialRevoked {
            credential,
            expected,
            ..
        } => (
            "credential.revoked",
            json!({"credential":credential,"expected":expected}),
        ),
        MessageSent {
            message,
            recipient,
            kind,
            refs,
            reply_to,
            ..
        } => (
            "message.sent",
            json!({"message":message,"recipient":recipient,"kind":kind,"refs":refs,"reply_to":reply_to}),
        ),
        MessageRead { message, recipient } => (
            "message.read",
            json!({"message":message,"recipient":recipient}),
        ),
        MessageDismissed { message, recipient } => (
            "message.dismissed",
            json!({"message":message,"recipient":recipient}),
        ),
        MessageDelivered {
            message,
            recipient,
            evidence,
        } => (
            "message.delivered",
            json!({"message":message,"recipient":recipient,"evidence":evidence}),
        ),
        WorkingStateSet {
            agent, expected, ..
        } => (
            "working_state.set",
            json!({"agent":agent,"expected":expected}),
        ),
        RuntimeOwnerEstablished {
            epoch,
            generation,
            expected_owner_generation,
            expected,
            witnesses,
            recovered,
        } if recovered.is_none() => (
            "runtime.owner",
            json!({"epoch":epoch,"generation":generation,"expected_owner_generation":expected_owner_generation,"expected":expected,"witnesses":witnesses}),
        ),
        DecisionProposed {
            decision,
            key,
            prior,
            kind,
            ..
        } => (
            "decision.proposed",
            json!({"decision":decision,"key":key,"prior":prior,"kind":kind}),
        ),
        DecisionRatified {
            decision,
            expected,
            approval,
        } => (
            "decision.ratified",
            json!({"decision":decision,"expected":expected,"approval":approval}),
        ),
        DecisionRejected {
            decision, expected, ..
        } => (
            "decision.rejected",
            json!({"decision":decision,"expected":expected}),
        ),
        DecisionRetracted {
            decision, expected, ..
        } => (
            "decision.retracted",
            json!({"decision":decision,"expected":expected}),
        ),
        DecisionSuperseded {
            prior,
            replacement,
            prior_expected,
            replacement_expected,
            approval,
        } => (
            "decision.superseded",
            json!({"prior":prior,"replacement":replacement,"prior_expected":prior_expected,"replacement_expected":replacement_expected,"approval":approval}),
        ),
        CursorRecorded { cursor } => (
            "cursor.recorded",
            json!({"cursor": crate::apply::cursor::metadata(cursor)?}),
        ),
        CursorAcknowledged {
            cursor,
            expected,
            evidence,
        } => (
            "cursor.acknowledged",
            json!({"cursor":cursor,"expected":expected,"evidence":evidence}),
        ),
        ProjectRemoved {
            project,
            expected,
            witnesses,
            preserved,
        } => (
            "project.removed",
            json!({"project":project,"expected":expected,"witnesses":witnesses,"preserved":preserved}),
        ),
        EffectRequested {
            principal,
            effect,
            kind,
            intent,
            cause,
            request_key,
        } => (
            "effect.requested",
            json!({"principal":principal,"effect":effect,"kind":kind,"intent":intent,"cause":cause,"request_key":request_key}),
        ),
        EffectOffered {
            effect,
            principal,
            attempt,
            evidence,
        } => (
            "effect.offered",
            json!({"effect":effect,"principal":principal,"attempt":attempt,"evidence":evidence}),
        ),
        EffectSettled {
            effect,
            expected,
            outcome,
            evidence,
            failure,
            attempts,
        } => (
            "effect.settled",
            json!({"effect":effect,"expected":expected,"outcome":outcome,"evidence":evidence,"failure":failure,"attempts":attempts}),
        ),
        IntegrationRecorded {
            integration,
            path,
            key,
            marker,
            prior_sha256,
            written_sha256,
            state,
            witness,
            expected,
        } => (
            "integration.recorded",
            json!({"integration":integration,"path":path,"key":key,"marker":marker,"prior_sha256":prior_sha256,"written_sha256":written_sha256,"state":state,"witness":witness,"expected":expected}),
        ),
        _ => return later("this event kind"),
    })
}
