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
        "channel.recorded" => ChannelRecorded {
            change: field(&facts(c, seq)?, "change")?,
        },
        "remote.security" => RemoteSecurity {
            transition: field(&facts(c, seq)?, "transition")?,
        },
        "remote.launch_attributed" => RemoteLaunchAttributed {
            record: field(&facts(c, seq)?, "record")?,
        },
        "remote.mailbox_recorded" => RemoteMailboxRecorded {
            change: field(&facts(c, seq)?, "change")?,
        },
        "remote.message_attributed" => RemoteMessageAttributed {
            record: field(&facts(c, seq)?, "record")?,
        },
        "runtime.owner" | "runtime.handover" | "backup.recorded" | "turn.erased"
        | "message.erased" | "erasure.requested" | "erasure.completed" | "recovery.recorded" => {
            se_store_codec::maintenance::decode(kind, &facts(c, seq)?, &mut |field| {
                stored_text(c, seq, field)
            })?
        }
        "import.started" | "import.progress" | "import.finished" | "import.unreadable"
        | "legacy.retained" | "alias.imported" => crate::import::decode(c, seq, kind)?,
        "process.registered" | "process.transition" => process::body(c, seq, kind, scope)?,
        "message.superseded" => message_superseded(c, seq)?,
        "message.sent" => message_sent(c, seq, scope)?,
        "message.work_sent" => message_work_sent(c, seq)?,
        "message.read" | "message.dismissed" | "message.delivered" => {
            message_mark(c, seq, scope, kind)?
        }
        "working_state.set" => working_state_set(c, seq, scope)?,
        "decision.proposed"
        | "decision.ratified"
        | "decision.rejected"
        | "decision.retracted"
        | "decision.superseded" => super::retired_decision::decode(c, seq, kind, scope)?,
        "session.prepared" | "session.activated" | "session.ended" | "session.revoked" => {
            session::decode(c, seq, kind, scope)?
        }
        "session.turn" | "capture.source" | "capture.progress" | "capture.failed"
        | "capture.verified" | "capture.suppressed" => capture::decode(c, seq, kind, scope)?,
        _ => other_body(c, seq, kind, scope)?,
    })
}

fn message_superseded(c: &Connection, seq: i64) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    let v = facts(c, seq)?;
    Ok(MessageSuperseded {
        message: field(&v, "message")?,
        replacement: field(&v, "replacement")?,
        expected: field(&v, "expected")?,
    })
}

fn message_sent(c: &Connection, seq: i64, scope: &Scope) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    let (message,recipient,kind,refs,reply):(Vec<u8>,Vec<u8>,String,String,Option<Vec<u8>>)=c.prepare_cached("SELECT message_id,recipient_id,message_kind,refs,reply_to FROM message_data WHERE event_seq=?").map_err(sql)?.query_row([seq],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?,crate::sql_value::value(r,3)?,crate::sql_value::value(r,4)?))).map_err(sql)?;
    let s = scope_key(c, scope, false)?;
    Ok(MessageSent {
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
    })
}

fn message_work_sent(c: &Connection, seq: i64) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    let v = facts(c, seq)?;
    Ok(WorkMessageSent {
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
    })
}

fn message_mark(
    c: &Connection,
    seq: i64,
    scope: &Scope,
    kind: &str,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
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
    Ok(match kind {
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
    })
}

fn working_state_set(
    c: &Connection,
    seq: i64,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
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
    Ok(WorkingStateSet {
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
    })
}

fn other_body(
    c: &Connection,
    seq: i64,
    kind: &str,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    let v = facts(c, seq)?;
    Ok(match kind {
        "project.captain_changed" => project_captain_changed(v)?,
        "captain.message_routed" => captain_message_routed(v)?,
        "assignment.opened" => assignment_opened(v)?,
        "assignment.transitioned" => assignment_transitioned(v)?,
        "project.updated" => project_updated(v)?,
        "project.moved" => project_moved(v)?,
        "project.registered" => project_registered(v)?,
        "principal.registered" => principal_registered(c, v, scope)?,
        "principal.renamed" => principal_renamed(c, v, scope)?,
        "agent.retired" => agent_retired(v)?,
        "profile.saved" => profile_saved(c, v, scope)?,
        "grant.recorded" => grant_recorded(c, v, scope)?,
        "credential.issued" => credential_issued(v)?,
        "credential.activated" => credential_activated(v)?,
        "credential.rotated" => credential_rotated(v)?,
        "credential.revoked" => credential_revoked(c, seq, v)?,
        "cursor.recorded" => cursor_recorded(v)?,
        "cursor.acknowledged" => cursor_acknowledged(v)?,
        "project.removed" => project_removed(v)?,
        "effect.requested" => effect_requested(c, v, scope)?,
        "effect.offered" => effect_offered(c, v, scope)?,
        "effect.settled" => effect_settled(v)?,
        "integration.recorded" => integration_recorded(v)?,
        _ => {
            return Err(fail(
                StoreErrorCode::Unreadable,
                format!("unsupported stored event kind {kind}"),
            ));
        }
    })
}

fn project_captain_changed(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(ProjectCaptainChanged {
        project: field(&v, "project")?,
        captain: field(&v, "captain")?,
        expected: field(&v, "expected")?,
    })
}

fn captain_message_routed(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(CaptainMessageRouted {
        message_event: field(&v, "message_event")?,
        captain: field(&v, "captain")?,
    })
}

fn assignment_opened(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(AssignmentOpened {
        project: field(&v, "project")?,
        assignment: field(&v, "assignment")?,
        assignee: field(&v, "assignee")?,
        captain: field(&v, "captain")?,
        floor_event: field(&v, "floor_event")?,
        expected: field(&v, "expected")?,
    })
}

fn assignment_transitioned(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(AssignmentTransitioned {
        assignment: field(&v, "assignment")?,
        action: field(&v, "action")?,
        captain: field(&v, "captain")?,
        floor_event: field(&v, "floor_event")?,
        expected: field(&v, "expected")?,
    })
}

fn project_updated(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(ProjectUpdated {
        project: field(&v, "project")?,
        name: field(&v, "name")?,
        roots: field(&v, "roots")?,
        expected: field(&v, "expected")?,
    })
}

fn project_moved(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(ProjectMoved {
        project: field(&v, "project")?,
        name: field(&v, "name")?,
        from: field(&v, "from")?,
        to: field(&v, "to")?,
        head: field(&v, "head")?,
        branch: field(&v, "branch")?,
        expected: field(&v, "expected")?,
    })
}

fn project_registered(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(ProjectRegistered {
        project: field(&v, "project")?,
        name: field(&v, "name")?,
        roots: field(&v, "roots")?,
        owner: field(&v, "owner")?,
        history_from: field(&v, "history_from")?,
        expected: field(&v, "expected")?,
    })
}

fn principal_registered(
    c: &Connection,
    v: serde_json::Value,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(PrincipalRegistered {
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
        ephemeral: v
            .get("ephemeral")
            .filter(|v| !v.is_null())
            .map(|v| serde_json::from_value(v.clone()).map_err(invalid))
            .transpose()?,
        expected: field(&v, "expected")?,
    })
}

fn agent_retired(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(AgentRetired {
        agent: field(&v, "agent")?,
        reason: field(&v, "reason")?,
        final_session: field(&v, "final_session")?,
    })
}

fn principal_renamed(
    c: &Connection,
    v: serde_json::Value,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(PrincipalRenamed {
        principal: actor_value(
            c,
            v.get("principal")
                .ok_or_else(|| invalid("principal metadata absent"))?,
            &scope_key(c, scope, false)?,
        )?,
        name: field(&v, "name")?,
        expected: field(&v, "expected")?,
    })
}

fn profile_saved(
    c: &Connection,
    v: serde_json::Value,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(ProfileSaved {
        agent: decode_agent(c, field(&v, "agent")?, &scope_key(c, scope, false)?)?,
        profile: field(&v, "profile")?,
        expected: field(&v, "expected")?,
    })
}

fn grant_recorded(
    c: &Connection,
    v: serde_json::Value,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(GrantRecorded {
        principal: actor_value(
            c,
            v.get("principal")
                .ok_or_else(|| invalid("principal metadata absent"))?,
            &scope_key(c, scope, false)?,
        )?,
        key: field(&v, "key")?,
        active: field(&v, "active")?,
        expected: field(&v, "expected")?,
    })
}

fn credential_issued(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(CredentialIssued {
        credential: field(&v, "credential")?,
        session: field(&v, "session")?,
        purpose: field(&v, "purpose")?,
        secret_sha256: field(&v, "secret_sha256")?,
        expires_at_us: field(&v, "expires_at_us")?,
        activation_deadline_us: field(&v, "activation_deadline_us")?,
        expected: field(&v, "expected")?,
    })
}

fn credential_activated(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(CredentialActivated {
        credential: field(&v, "credential")?,
        session: field(&v, "session")?,
        expected: field(&v, "expected")?,
        first_request: field(&v, "first_request")?,
    })
}

fn credential_rotated(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(CredentialRotated {
        credential: field(&v, "credential")?,
        session: field(&v, "session")?,
        secret_sha256: field(&v, "secret_sha256")?,
        expires_at_us: field(&v, "expires_at_us")?,
        restart: field(&v, "restart")?,
        expected: field(&v, "expected")?,
    })
}

fn credential_revoked(
    c: &Connection,
    seq: i64,
    v: serde_json::Value,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(CredentialRevoked {
        credential: field(&v, "credential")?,
        expected: field(&v, "expected")?,
        reason: stored_text(c, seq, "reason")?,
    })
}

fn cursor_recorded(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(CursorRecorded {
        cursor: Box::new(se_store_codec::cursor::decode(
            v.get("cursor")
                .ok_or_else(|| invalid("stored cursor record missing"))?,
        )?),
    })
}

fn cursor_acknowledged(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(CursorAcknowledged {
        cursor: field(&v, "cursor")?,
        expected: field(&v, "expected")?,
        evidence: field(&v, "evidence")?,
    })
}

fn project_removed(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(ProjectRemoved {
        project: field(&v, "project")?,
        expected: field(&v, "expected")?,
        witnesses: field(&v, "witnesses")?,
        preserved: field(&v, "preserved")?,
    })
}

fn effect_requested(
    c: &Connection,
    v: serde_json::Value,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    let intent: EffectIntent = field(&v, "intent")?;
    if let EffectIntent::MailNotice(notice) = &intent {
        notice.validate().map_err(|error| {
            fail(
                StoreErrorCode::Unreadable,
                format!("stored mail notice: {}", error.cause),
            )
        })?;
    }
    Ok(EffectRequested {
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
    })
}

fn effect_offered(
    c: &Connection,
    v: serde_json::Value,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    let evidence: crate::mail::OfferEvidence = field(&v, "evidence")?;
    if let crate::mail::OfferEvidence::Observed(observation) = &evidence {
        observation.validate().map_err(|error| {
            fail(
                StoreErrorCode::Unreadable,
                format!("stored Bell offer observation: {}", error.cause),
            )
        })?;
    }
    Ok(EffectOffered {
        effect: field(&v, "effect")?,
        principal: actor_value(
            c,
            v.get("principal")
                .ok_or_else(|| invalid("principal metadata absent"))?,
            &scope_key(c, scope, false)?,
        )?,
        attempt: field(&v, "attempt")?,
        evidence,
    })
}

fn effect_settled(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(EffectSettled {
        effect: field(&v, "effect")?,
        expected: field(&v, "expected")?,
        outcome: field(&v, "outcome")?,
        evidence: field(&v, "evidence")?,
        failure: field(&v, "failure")?,
        attempts: field(&v, "attempts")?,
    })
}

fn integration_recorded(v: serde_json::Value) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(IntegrationRecorded {
        integration: field(&v, "integration")?,
        path: field(&v, "path")?,
        key: field(&v, "key")?,
        marker: field(&v, "marker")?,
        prior_sha256: field(&v, "prior_sha256")?,
        written_sha256: field(&v, "written_sha256")?,
        state: field(&v, "state")?,
        witness: field(&v, "witness")?,
        expected: field(&v, "expected")?,
    })
}
