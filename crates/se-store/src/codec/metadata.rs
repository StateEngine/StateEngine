//! Encode event metadata while payload text stays in its typed column.
use super::*;

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
        ProjectUpdated {
            project,
            name,
            roots,
            expected,
        } => (
            "project.updated",
            json!({"project":project,"name":name,"roots":roots,"expected":expected}),
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
        WorkMessageSent {
            message,
            work,
            kind,
            refs,
            reply_to,
            ..
        } => (
            "message.work_sent",
            json!({"message":message,"work":work,"kind":kind,"refs":refs,"reply_to":reply_to}),
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
        | RecoveryRecorded { .. } => super::maintenance::metadata(body)?,
    })
}
