//! Encode event metadata while payload text stays in its typed column.
use super::*;
use EventBody::*;

// Omitting the default preserves pre-notification canonical fingerprints.
fn notification(mut facts: Value, quiet: bool) -> Value {
    if quiet {
        facts["quiet"] = Value::Bool(true);
    }
    facts
}

pub fn metadata<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    Ok(match body {
        ChannelRecorded { .. }
        | RemoteSecurity { .. }
        | RemoteLaunchAttributed { .. }
        | RemoteDelegateAttributed { .. }
        | RemoteMailboxRecorded { .. }
        | RemoteMessageAttributed { .. } => channel_remote(body)?,
        ProjectCaptainChanged { .. }
        | CaptainMessageRouted { .. }
        | AssignmentOpened { .. }
        | AssignmentTransitioned { .. }
        | ProjectRegistered { .. }
        | ProjectUpdated { .. }
        | ProjectMoved { .. } => project_lifecycle(body)?,
        PrincipalRegistered { .. }
        | PrincipalRenamed { .. }
        | AgentRetired { .. }
        | ProfileSaved { .. }
        | GrantRecorded { .. }
        | ProcessRegistered { .. }
        | ProcessTransition { .. } => principal_process(body)?,
        SessionPrepared { .. }
        | SessionActivated { .. }
        | SessionEnded { .. }
        | SessionRevoked { .. }
        | SessionTurn { .. } => session_turn(body)?,
        CaptureSource { .. }
        | CaptureProgress { .. }
        | CaptureVerified { .. }
        | CaptureFailed { .. }
        | CaptureSuppressed { .. } => capture(body)?,
        CredentialIssued { .. }
        | CredentialActivated { .. }
        | CredentialRotated { .. }
        | CredentialRevoked { .. } => credential(body)?,
        MessageSent { .. }
        | WorkMessageSent { .. }
        | MessageSuperseded { .. }
        | MessageRead { .. }
        | MessageDismissed { .. }
        | MessageDelivered { .. }
        | WorkingStateSet { .. } => mail_state(body)?,
        RuntimeOwnerEstablished { recovered, .. } if recovered.is_none() => {
            runtime_owner_none(body)?
        }
        DecisionProposed { .. }
        | DecisionRatified { .. }
        | DecisionRejected { .. }
        | DecisionRetracted { .. }
        | DecisionSuperseded { .. }
        | CursorRecorded { .. }
        | CursorAcknowledged { .. } => decision_cursor(body)?,
        ProjectRemoved { .. }
        | EffectRequested { .. }
        | EffectOffered { .. }
        | EffectSettled { .. }
        | IntegrationRecorded { .. } => effect_integration(body)?,
        ImportStarted { .. }
        | ImportProgress { .. }
        | ImportFinished { .. }
        | ImportUnreadable { .. }
        | LegacyRetained { .. }
        | AliasImported { .. } => crate::import::metadata(body)?,
        RuntimeOwnerEstablished { .. }
        | RuntimeHandoverRecorded { .. }
        | BackupRecorded { .. }
        | TurnErased { .. }
        | MessageErased { .. }
        | ErasureRequested { .. }
        | ErasureCompleted { .. }
        | RecoveryRecorded { .. } => crate::maintenance::metadata(body)?,
    })
}

fn channel_remote<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    Ok(match body {
        ChannelRecorded { change } => ("channel.recorded", json!({"change":change})),
        RemoteSecurity { transition } => ("remote.security", json!({"transition":transition})),
        RemoteLaunchAttributed { record } => ("remote.launch_attributed", json!({"record":record})),
        RemoteDelegateAttributed { record } => {
            ("remote.delegate_attributed", json!({"record":record}))
        }
        RemoteMailboxRecorded { change } => ("remote.mailbox_recorded", json!({"change":change})),
        RemoteMessageAttributed { record } => {
            ("remote.message_attributed", json!({"record":record}))
        }
        _ => return unmapped(),
    })
}

fn project_lifecycle<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    Ok(match body {
        ProjectCaptainChanged {
            project,
            captain,
            expected,
        } => (
            "project.captain_changed",
            json!({"project":project,"captain":captain,"expected":expected}),
        ),
        CaptainMessageRouted {
            message_event,
            captain,
        } => (
            "captain.message_routed",
            json!({"message_event":message_event,"captain":captain}),
        ),
        AssignmentOpened {
            project,
            assignment,
            assignee,
            captain,
            floor_event,
            expected,
        } => (
            "assignment.opened",
            json!({"project":project,"assignment":assignment,"assignee":assignee,"captain":captain,"floor_event":floor_event,"expected":expected}),
        ),
        AssignmentTransitioned {
            assignment,
            action,
            captain,
            floor_event,
            expected,
        } => (
            "assignment.transitioned",
            json!({"assignment":assignment,"action":action,"captain":captain,"floor_event":floor_event,"expected":expected}),
        ),
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
        ProjectUpdated {
            project,
            name,
            roots,
            expected,
        } => (
            "project.updated",
            json!({"project":project,"name":name,"roots":roots,"expected":expected}),
        ),
        ProjectMoved {
            project,
            name,
            from,
            to,
            head,
            branch,
            expected,
        } => (
            "project.moved",
            json!({"project":project,"name":name,"from":from,"to":to,"head":head,"branch":branch,"expected":expected}),
        ),
        _ => return unmapped(),
    })
}

fn principal_process<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    Ok(match body {
        PrincipalRegistered {
            principal,
            kind,
            owner,
            created_by,
            name,
            role,
            ephemeral,
            expected,
        } => {
            let mut facts = json!({"principal":principal,"kind":kind,"owner":owner,"created_by":created_by,"name":name,"role":role,"expected":expected});
            if let Some(ephemeral) = ephemeral {
                facts["ephemeral"] = json!(ephemeral);
            }
            ("principal.registered", facts)
        }
        PrincipalRenamed {
            principal,
            name,
            expected,
        } => (
            "principal.renamed",
            json!({"principal":principal,"name":name,"expected":expected}),
        ),
        AgentRetired {
            agent,
            reason,
            final_session,
        } => (
            "agent.retired",
            json!({"agent":agent,"reason":reason,"final_session":final_session}),
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
        _ => return unmapped(),
    })
}

fn session_turn<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    Ok(match body {
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
        _ => return unmapped(),
    })
}

fn capture<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    Ok(match body {
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
            replay_evidence,
        } => (
            "capture.progress",
            json!({"capture_kind":"progress","source":source,"expected":expected,"incarnation":incarnation,"old_offset":old_offset,"new_offset":new_offset,"last_turn":last_turn,"replay_evidence":replay_evidence}),
        ),
        CaptureVerified {
            source,
            session,
            offset,
        } => (
            "capture.verified",
            json!({"source":source,"session":session,"offset":offset}),
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
        _ => return unmapped(),
    })
}

fn credential<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    Ok(match body {
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
        CredentialRotated {
            credential,
            session,
            secret_sha256,
            expires_at_us,
            restart,
            expected,
        } => (
            "credential.rotated",
            json!({"credential":credential,"session":session,"secret_sha256":secret_sha256,
                "expires_at_us":expires_at_us,"restart":restart,"expected":expected}),
        ),
        CredentialRevoked {
            credential,
            expected,
            ..
        } => (
            "credential.revoked",
            json!({"credential":credential,"expected":expected}),
        ),
        _ => return unmapped(),
    })
}

fn mail_state<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    Ok(match body {
        MessageSent {
            message,
            recipient,
            kind,
            refs,
            reply_to,
            quiet,
            ..
        } => (
            "message.sent",
            notification(
                json!({"message":message,"recipient":recipient,"kind":kind,"refs":refs,"reply_to":reply_to}),
                *quiet,
            ),
        ),
        WorkMessageSent {
            message,
            work,
            kind,
            refs,
            reply_to,
            quiet,
            ..
        } => (
            "message.work_sent",
            notification(
                json!({"message":message,"work":work,"kind":kind,"refs":refs,"reply_to":reply_to}),
                *quiet,
            ),
        ),
        MessageSuperseded {
            message,
            replacement,
            expected,
        } => (
            "message.superseded",
            json!({"message":message,"replacement":replacement,"expected":expected}),
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
        _ => return unmapped(),
    })
}

fn runtime_owner_none<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    Ok(match body {
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
        _ => return unmapped(),
    })
}

fn decision_cursor<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    Ok(match body {
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
            json!({"cursor": crate::cursor::metadata(cursor)?}),
        ),
        CursorAcknowledged {
            cursor,
            expected,
            evidence,
        } => (
            "cursor.acknowledged",
            json!({"cursor":cursor,"expected":expected,"evidence":evidence}),
        ),
        _ => return unmapped(),
    })
}

fn effect_integration<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    Ok(match body {
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
        _ => return unmapped(),
    })
}

/// Defensive fallback: the router above only sends each body to its own group.
fn unmapped() -> StoreResult<(&'static str, Value)> {
    Err(invalid("unmapped event body"))
}
