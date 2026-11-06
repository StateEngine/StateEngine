//! Decode persisted event bodies using the shared codec helpers.
use super::*;

pub(crate) fn body(
    c: &Connection,
    seq: i64,
    kind: &str,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(match kind {
        "runtime.owner" | "runtime.handover" | "backup.recorded" | "turn.erased"
        | "message.erased" | "erasure.requested" | "erasure.completed" | "recovery.recorded" => {
            super::maintenance::body(c, seq, kind)?
        }
        "import.started" | "import.progress" | "import.finished" | "import.unreadable"
        | "legacy.retained" | "alias.imported" => crate::import::decode(c, seq, kind)?,
        "process.registered" | "process.transition" => process::body(c, seq, kind, scope)?,
        "message.superseded" => {
            let v = facts(c, seq)?;
            MessageSuperseded {
                message: field(&v, "message")?,
                replacement: field(&v, "replacement")?,
                expected: field(&v, "expected")?,
            }
        }
        "message.sent" => {
            let (message,recipient,kind,refs,reply):(Vec<u8>,Vec<u8>,String,String,Option<Vec<u8>>)=c.prepare_cached("SELECT message_id,recipient_id,message_kind,refs,reply_to FROM message_data WHERE event_seq=?").map_err(sql)?.query_row([seq],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?,crate::sql_value::value(r,3)?,crate::sql_value::value(r,4)?))).map_err(sql)?;
            let s = scope_key(c, scope, false)?;
            MessageSent {
                message: wire(c, "message", &message, &s)?
                    .try_into()
                    .map_err(invalid)?,
                recipient: actor(c, &recipient, &s)?,
                quiet: if connection::info(c)?.schema_version >= 4 {
                    c.query_row(
                        "SELECT quiet FROM message_data WHERE event_seq=?",
                        [seq],
                        |r| r.get(0),
                    )
                    .map_err(sql)?
                } else {
                    false
                },
                kind,
                body: stored_text(c, seq, "body")?,
                refs: serde_json::from_str(&refs).map_err(invalid)?,
                reply_to: reply
                    .map(|v| wire(c, "message", &v, &s).and_then(|v| v.try_into().map_err(invalid)))
                    .transpose()?,
            }
        }
        "message.work_sent" => {
            let v = facts(c, seq)?;
            WorkMessageSent {
                message: field(&v, "message")?,
                work: field(&v, "work")?,
                quiet: v
                    .get("quiet")
                    .map(|v| serde_json::from_value(v.clone()).map_err(invalid))
                    .transpose()?
                    .unwrap_or(false),
                kind: field(&v, "kind")?,
                body: stored_text(c, seq, "body")?,
                refs: field(&v, "refs")?,
                reply_to: field(&v, "reply_to")?,
            }
        }
        "message.read" | "message.dismissed" | "message.delivered" => {
            let statement = if crate::connection::info(c)?.schema_version >= 3 {
                "SELECT d.message_id,m.recipient_id,m.evidence_event FROM mark_data m JOIN message_data d ON d.event_seq=m.message_seq WHERE m.event_seq=?1 UNION ALL SELECT message_id,recipient_id,evidence_event FROM work_mark_data WHERE event_seq=?1"
            } else {
                "SELECT d.message_id,m.recipient_id,m.evidence_event FROM mark_data m JOIN message_data d ON d.event_seq=m.message_seq WHERE m.event_seq=?1"
            };
            let (message, recipient, evidence): (Vec<u8>, Vec<u8>, Option<Vec<u8>>) = c
                .query_row(statement, [seq], |r| {
                    Ok((
                        crate::sql_value::value(r, 0)?,
                        crate::sql_value::value(r, 1)?,
                        crate::sql_value::value(r, 2)?,
                    ))
                })
                .map_err(sql)?;
            let s = scope_key(c, scope, false)?;
            let message = wire(c, "message", &message, &s)?
                .try_into()
                .map_err(invalid)?;
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
                    .try_into()
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
                agent: decode_agent(
                    c,
                    wire(c, "agent", &agent, &scope_key(c, scope, false)?)?,
                    &scope_key(c, scope, false)?,
                )?,
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
        | "capture.verified" | "capture.suppressed" => capture::decode(c, seq, kind, scope)?,
        _ => {
            let v = facts(c, seq)?;
            match kind {
                "project.updated" => ProjectUpdated {
                    project: field(&v, "project")?,
                    name: field(&v, "name")?,
                    roots: field(&v, "roots")?,
                    expected: field(&v, "expected")?,
                },
                "project.moved" => ProjectMoved {
                    project: field(&v, "project")?,
                    name: field(&v, "name")?,
                    from: field(&v, "from")?,
                    to: field(&v, "to")?,
                    head: field(&v, "head")?,
                    branch: field(&v, "branch")?,
                    expected: field(&v, "expected")?,
                },
                "project.registered" => ProjectRegistered {
                    project: field(&v, "project")?,
                    name: field(&v, "name")?,
                    roots: field(&v, "roots")?,
                    owner: field(&v, "owner")?,
                    history_from: field(&v, "history_from")?,
                    expected: field(&v, "expected")?,
                },
                "principal.registered" => PrincipalRegistered {
                    principal: actor_value(
                        c,
                        v.get("principal")
                            .ok_or_else(|| invalid("principal metadata absent"))?,
                        &scope_key(c, scope, false)?,
                    )?,
                    kind: field(&v, "kind")?,
                    owner: field(&v, "owner")?,
                    created_by: v
                        .get("created_by")
                        .filter(|v| !v.is_null())
                        .map(|v| actor_value(c, v, &scope_key(c, scope, false)?))
                        .transpose()?,
                    name: field(&v, "name")?,
                    role: field(&v, "role")?,
                    expected: field(&v, "expected")?,
                },
                "principal.renamed" => PrincipalRenamed {
                    principal: actor_value(
                        c,
                        v.get("principal")
                            .ok_or_else(|| invalid("principal metadata absent"))?,
                        &scope_key(c, scope, false)?,
                    )?,
                    name: field(&v, "name")?,
                    expected: field(&v, "expected")?,
                },
                "profile.saved" => ProfileSaved {
                    agent: decode_agent(c, field(&v, "agent")?, &scope_key(c, scope, false)?)?,
                    profile: field(&v, "profile")?,
                    expected: field(&v, "expected")?,
                },
                "grant.recorded" => GrantRecorded {
                    principal: actor_value(
                        c,
                        v.get("principal")
                            .ok_or_else(|| invalid("principal metadata absent"))?,
                        &scope_key(c, scope, false)?,
                    )?,
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
                        principal: v
                            .get("principal")
                            .filter(|v| !v.is_null())
                            .map(|v| actor_value(c, v, &scope_key(c, scope, false)?))
                            .transpose()?,
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
                        principal: actor_value(
                            c,
                            v.get("principal")
                                .ok_or_else(|| invalid("principal metadata absent"))?,
                            &scope_key(c, scope, false)?,
                        )?,
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
