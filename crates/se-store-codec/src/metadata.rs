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

// Each arm keeps its own function so the dispatcher stays a flat table; the
// inner match is routed to the named variant only, so the wildcard is safe.
macro_rules! meta_arm {
    ($name:ident, $variant:ident, [$($fields:ident),*], $ret:ty, $body:expr) => {
        fn $name<T>(body: &EventBody<T>) -> $ret {
            match body {
                $variant { $($fields),*, .. } => $body,
                _ => unreachable!(),
            }
        }
    };
}

pub fn metadata<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    use EventBody::*;
    Ok(match body {
        ChannelRecorded { .. } => channel_recorded(body),
        RemoteSecurity { .. } => remote_security(body),
        RemoteLaunchAttributed { .. } => remote_launch_attributed(body),
        RemoteMailboxRecorded { .. } => remote_mailbox_recorded(body),
        RemoteMessageAttributed { .. } => remote_message_attributed(body),
        ProjectCaptainChanged { .. } => project_captain_changed(body),
        CaptainMessageRouted { .. } => captain_message_routed(body),
        AssignmentOpened { .. } => assignment_opened(body),
        AssignmentTransitioned { .. } => assignment_transitioned(body),
        ProjectRegistered { .. } => project_registered(body),
        ProjectUpdated { .. } => project_updated(body),
        ProjectMoved { .. } => project_moved(body),
        PrincipalRegistered { .. } => principal_registered(body),
        PrincipalRenamed { .. } => principal_renamed(body),
        ProfileSaved { .. } => profile_saved(body),
        GrantRecorded { .. } => grant_recorded(body),
        ProcessRegistered { .. } => process_registered(body),
        ProcessTransition { .. } => process_transition(body),
        SessionPrepared { .. } => session_prepared(body),
        SessionActivated { .. } => session_activated(body),
        SessionEnded { .. } => session_ended(body),
        SessionRevoked { .. } => session_revoked(body),
        SessionTurn { .. } => session_turn(body),
        CaptureSource { .. } => capture_source(body),
        CaptureProgress { .. } => capture_progress(body),
        CaptureVerified { .. } => capture_verified(body),
        CaptureFailed { .. } => capture_failed(body),
        CaptureSuppressed { .. } => capture_suppressed(body),
        CredentialIssued { .. } => credential_issued(body),
        CredentialActivated { .. } => credential_activated(body),
        CredentialRotated { .. } => credential_rotated(body),
        CredentialRevoked { .. } => credential_revoked(body),
        MessageSent { .. } => message_sent(body),
        WorkMessageSent { .. } => work_message_sent(body),
        MessageSuperseded { .. } => message_superseded(body),
        MessageRead { .. } => message_read(body),
        MessageDismissed { .. } => message_dismissed(body),
        MessageDelivered { .. } => message_delivered(body),
        WorkingStateSet { .. } => working_state_set(body),
        RuntimeOwnerEstablished { recovered, .. } if recovered.is_none() => {
            runtime_owner_established(body)
        }
        DecisionProposed { .. } => decision_proposed(body),
        DecisionRatified { .. } => decision_ratified(body),
        DecisionRejected { .. } => decision_rejected(body),
        DecisionRetracted { .. } => decision_retracted(body),
        DecisionSuperseded { .. } => decision_superseded(body),
        CursorRecorded { .. } => cursor_recorded(body)?,
        CursorAcknowledged { .. } => cursor_acknowledged(body),
        ProjectRemoved { .. } => project_removed(body),
        EffectRequested { .. } => effect_requested(body),
        EffectOffered { .. } => effect_offered(body),
        EffectSettled { .. } => effect_settled(body),
        IntegrationRecorded { .. } => integration_recorded(body),
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

meta_arm!(
    channel_recorded,
    ChannelRecorded,
    [change],
    (&'static str, Value),
    ("channel.recorded", json!({"change":change}))
);

meta_arm!(
    remote_security,
    RemoteSecurity,
    [transition],
    (&'static str, Value),
    ("remote.security", json!({"transition":transition}))
);

meta_arm!(
    remote_launch_attributed,
    RemoteLaunchAttributed,
    [record],
    (&'static str, Value),
    ("remote.launch_attributed", json!({"record":record}))
);

meta_arm!(
    remote_mailbox_recorded,
    RemoteMailboxRecorded,
    [change],
    (&'static str, Value),
    ("remote.mailbox_recorded", json!({"change":change}))
);

meta_arm!(
    remote_message_attributed,
    RemoteMessageAttributed,
    [record],
    (&'static str, Value),
    { ("remote.message_attributed", json!({"record":record})) }
);

meta_arm!(
    project_captain_changed,
    ProjectCaptainChanged,
    [project, captain, expected],
    (&'static str, Value),
    (
        "project.captain_changed",
        json!({"project":project,"captain":captain,"expected":expected}),
    )
);

meta_arm!(
    captain_message_routed,
    CaptainMessageRouted,
    [message_event, captain],
    (&'static str, Value),
    (
        "captain.message_routed",
        json!({"message_event":message_event,"captain":captain}),
    )
);

meta_arm!(
    assignment_opened,
    AssignmentOpened,
    [
        project,
        assignment,
        assignee,
        captain,
        floor_event,
        expected
    ],
    (&'static str, Value),
    (
        "assignment.opened",
        json!({"project":project,"assignment":assignment,"assignee":assignee,"captain":captain,"floor_event":floor_event,"expected":expected}),
    )
);

meta_arm!(
    assignment_transitioned,
    AssignmentTransitioned,
    [assignment, action, captain, floor_event, expected],
    (&'static str, Value),
    (
        "assignment.transitioned",
        json!({"assignment":assignment,"action":action,"captain":captain,"floor_event":floor_event,"expected":expected}),
    )
);

meta_arm!(
    project_registered,
    ProjectRegistered,
    [project, name, roots, owner, history_from, expected],
    (&'static str, Value),
    (
        "project.registered",
        json!({"project":project,"name":name,"roots":roots,"owner":owner,"history_from":history_from,"expected":expected}),
    )
);

meta_arm!(
    project_updated,
    ProjectUpdated,
    [project, name, roots, expected],
    (&'static str, Value),
    (
        "project.updated",
        json!({"project":project,"name":name,"roots":roots,"expected":expected}),
    )
);

meta_arm!(
    project_moved,
    ProjectMoved,
    [project, name, from, to, head, branch, expected],
    (&'static str, Value),
    (
        "project.moved",
        json!({"project":project,"name":name,"from":from,"to":to,"head":head,"branch":branch,"expected":expected}),
    )
);

meta_arm!(
    principal_registered,
    PrincipalRegistered,
    [principal, kind, owner, created_by, name, role, expected],
    (&'static str, Value),
    (
        "principal.registered",
        json!({"principal":principal,"kind":kind,"owner":owner,"created_by":created_by,"name":name,"role":role,"expected":expected}),
    )
);

meta_arm!(
    principal_renamed,
    PrincipalRenamed,
    [principal, name, expected],
    (&'static str, Value),
    (
        "principal.renamed",
        json!({"principal":principal,"name":name,"expected":expected}),
    )
);

meta_arm!(
    profile_saved,
    ProfileSaved,
    [agent, profile, expected],
    (&'static str, Value),
    (
        "profile.saved",
        json!({"agent":agent,"profile":profile,"expected":expected}),
    )
);

meta_arm!(
    grant_recorded,
    GrantRecorded,
    [principal, key, active, expected],
    (&'static str, Value),
    (
        "grant.recorded",
        json!({"principal":principal,"key":key,"active":active,"expected":expected}),
    )
);

meta_arm!(
    process_registered,
    ProcessRegistered,
    [identity, initial],
    (&'static str, Value),
    (
        "process.registered",
        json!({"identity":identity,"initial":initial}),
    )
);

meta_arm!(
    process_transition,
    ProcessTransition,
    [
        process,
        identity,
        expected,
        from,
        to,
        observation,
        outcome,
        containment
    ],
    (&'static str, Value),
    (
        "process.transition",
        json!({"process":process,"identity":identity,"expected":expected,"from":from,"to":to,"observation":observation,"outcome":outcome,"containment":containment}),
    )
);

meta_arm!(
    session_prepared,
    SessionPrepared,
    [
        session, agent, provider, surface, native_ref, consent, generation, expected
    ],
    (&'static str, Value),
    (
        "session.prepared",
        json!({"session":session,"agent":agent,"provider":provider,"surface":surface,"native_ref":native_ref,"consent":consent,"generation":generation,"expected":expected}),
    )
);

meta_arm!(
    session_activated,
    SessionActivated,
    [
        session,
        expected,
        incumbent,
        process,
        containment,
        witnesses
    ],
    (&'static str, Value),
    (
        "session.activated",
        json!({"session":session,"expected":expected,"incumbent":incumbent,"process":process,"containment":containment,"witnesses":witnesses}),
    )
);

meta_arm!(
    session_ended,
    SessionEnded,
    [session, expected, final_turn, final_cursor],
    (&'static str, Value),
    (
        "session.ended",
        json!({"session":session,"expected":expected,"final_turn":final_turn,"final_cursor":final_cursor}),
    )
);

meta_arm!(
    session_revoked,
    SessionRevoked,
    [session, expected],
    (&'static str, Value),
    (
        "session.revoked",
        json!({"session":session,"expected":expected}),
    )
);

meta_arm!(
    session_turn,
    SessionTurn,
    [turn, agent, session, provider, vendor_ref, role, evidence],
    (&'static str, Value),
    (
        "session.turn",
        json!({"turn":turn,"agent":agent,"session":session,"provider":provider,"vendor_ref":vendor_ref,"role":role,"evidence":evidence}),
    )
);

meta_arm!(
    capture_source,
    CaptureSource,
    [source, session, consent, native_ref, incarnation, expected],
    (&'static str, Value),
    (
        "capture.source",
        json!({"capture_kind":"source","source":source,"session":session,"consent":consent,"native_ref":native_ref,"incarnation":incarnation,"expected":expected}),
    )
);

meta_arm!(
    capture_progress,
    CaptureProgress,
    [
        source,
        expected,
        incarnation,
        old_offset,
        new_offset,
        last_turn,
        replay_evidence
    ],
    (&'static str, Value),
    (
        "capture.progress",
        json!({"capture_kind":"progress","source":source,"expected":expected,"incarnation":incarnation,"old_offset":old_offset,"new_offset":new_offset,"last_turn":last_turn,"replay_evidence":replay_evidence}),
    )
);

meta_arm!(
    capture_verified,
    CaptureVerified,
    [source, session, offset],
    (&'static str, Value),
    (
        "capture.verified",
        json!({"source":source,"session":session,"offset":offset}),
    )
);

meta_arm!(
    capture_failed,
    CaptureFailed,
    [source, session, from_offset, to_offset, code, cause, retry],
    (&'static str, Value),
    (
        "capture.failed",
        json!({"source":source,"session":session,"from_offset":from_offset,"to_offset":to_offset,"code":code,"cause":cause,"retry":retry}),
    )
);

meta_arm!(
    capture_suppressed,
    CaptureSuppressed,
    [
        source,
        session,
        expected,
        reason,
        from_offset,
        to_offset,
        count
    ],
    (&'static str, Value),
    (
        "capture.suppressed",
        json!({"source":source,"session":session,"expected":expected,"reason":reason,"from_offset":from_offset,"to_offset":to_offset,"count":count}),
    )
);

meta_arm!(
    credential_issued,
    CredentialIssued,
    [
        credential,
        session,
        purpose,
        secret_sha256,
        expires_at_us,
        activation_deadline_us,
        expected
    ],
    (&'static str, Value),
    (
        "credential.issued",
        json!({"credential":credential,"session":session,"purpose":purpose,"secret_sha256":secret_sha256,"expires_at_us":expires_at_us,"activation_deadline_us":activation_deadline_us,"expected":expected}),
    )
);

meta_arm!(
    credential_activated,
    CredentialActivated,
    [credential, session, expected, first_request],
    (&'static str, Value),
    (
        "credential.activated",
        json!({"credential":credential,"session":session,"expected":expected,"first_request":first_request}),
    )
);

meta_arm!(
    credential_rotated,
    CredentialRotated,
    [
        credential,
        session,
        secret_sha256,
        expires_at_us,
        restart,
        expected
    ],
    (&'static str, Value),
    (
        "credential.rotated",
        json!({"credential":credential,"session":session,"secret_sha256":secret_sha256,
                "expires_at_us":expires_at_us,"restart":restart,"expected":expected}),
    )
);

meta_arm!(
    credential_revoked,
    CredentialRevoked,
    [credential, expected],
    (&'static str, Value),
    (
        "credential.revoked",
        json!({"credential":credential,"expected":expected}),
    )
);

meta_arm!(
    message_sent,
    MessageSent,
    [message, recipient, kind, refs, reply_to, quiet],
    (&'static str, Value),
    (
        "message.sent",
        notification(
            json!({"message":message,"recipient":recipient,"kind":kind,"refs":refs,"reply_to":reply_to}),
            *quiet,
        ),
    )
);

meta_arm!(
    work_message_sent,
    WorkMessageSent,
    [message, work, kind, refs, reply_to, quiet],
    (&'static str, Value),
    (
        "message.work_sent",
        notification(
            json!({"message":message,"work":work,"kind":kind,"refs":refs,"reply_to":reply_to}),
            *quiet,
        ),
    )
);

meta_arm!(
    message_superseded,
    MessageSuperseded,
    [message, replacement, expected],
    (&'static str, Value),
    (
        "message.superseded",
        json!({"message":message,"replacement":replacement,"expected":expected}),
    )
);

meta_arm!(
    message_read,
    MessageRead,
    [message, recipient],
    (&'static str, Value),
    (
        "message.read",
        json!({"message":message,"recipient":recipient}),
    )
);

meta_arm!(
    message_dismissed,
    MessageDismissed,
    [message, recipient],
    (&'static str, Value),
    (
        "message.dismissed",
        json!({"message":message,"recipient":recipient}),
    )
);

meta_arm!(
    message_delivered,
    MessageDelivered,
    [message, recipient, evidence],
    (&'static str, Value),
    (
        "message.delivered",
        json!({"message":message,"recipient":recipient,"evidence":evidence}),
    )
);

meta_arm!(
    working_state_set,
    WorkingStateSet,
    [agent, expected],
    (&'static str, Value),
    (
        "working_state.set",
        json!({"agent":agent,"expected":expected}),
    )
);

meta_arm!(
    runtime_owner_established,
    RuntimeOwnerEstablished,
    [
        epoch,
        generation,
        expected_owner_generation,
        expected,
        witnesses
    ],
    (&'static str, Value),
    (
        "runtime.owner",
        json!({"epoch":epoch,"generation":generation,"expected_owner_generation":expected_owner_generation,"expected":expected,"witnesses":witnesses}),
    )
);

meta_arm!(
    decision_proposed,
    DecisionProposed,
    [decision, key, prior, kind],
    (&'static str, Value),
    (
        "decision.proposed",
        json!({"decision":decision,"key":key,"prior":prior,"kind":kind}),
    )
);

meta_arm!(
    decision_ratified,
    DecisionRatified,
    [decision, expected, approval],
    (&'static str, Value),
    (
        "decision.ratified",
        json!({"decision":decision,"expected":expected,"approval":approval}),
    )
);

meta_arm!(
    decision_rejected,
    DecisionRejected,
    [decision, expected],
    (&'static str, Value),
    (
        "decision.rejected",
        json!({"decision":decision,"expected":expected}),
    )
);

meta_arm!(
    decision_retracted,
    DecisionRetracted,
    [decision, expected],
    (&'static str, Value),
    (
        "decision.retracted",
        json!({"decision":decision,"expected":expected}),
    )
);

meta_arm!(
    decision_superseded,
    DecisionSuperseded,
    [
        prior,
        replacement,
        prior_expected,
        replacement_expected,
        approval
    ],
    (&'static str, Value),
    (
        "decision.superseded",
        json!({"prior":prior,"replacement":replacement,"prior_expected":prior_expected,"replacement_expected":replacement_expected,"approval":approval}),
    )
);

meta_arm!(
    cursor_recorded,
    CursorRecorded,
    [cursor],
    StoreResult<(&'static str, Value)>,
    Ok((
        "cursor.recorded",
        json!({"cursor": crate::cursor::metadata(cursor)?}),
    ))
);

meta_arm!(
    cursor_acknowledged,
    CursorAcknowledged,
    [cursor, expected, evidence],
    (&'static str, Value),
    (
        "cursor.acknowledged",
        json!({"cursor":cursor,"expected":expected,"evidence":evidence}),
    )
);

meta_arm!(
    project_removed,
    ProjectRemoved,
    [project, expected, witnesses, preserved],
    (&'static str, Value),
    (
        "project.removed",
        json!({"project":project,"expected":expected,"witnesses":witnesses,"preserved":preserved}),
    )
);

meta_arm!(
    effect_requested,
    EffectRequested,
    [principal, effect, kind, intent, cause, request_key],
    (&'static str, Value),
    (
        "effect.requested",
        json!({"principal":principal,"effect":effect,"kind":kind,"intent":intent,"cause":cause,"request_key":request_key}),
    )
);

meta_arm!(
    effect_offered,
    EffectOffered,
    [effect, principal, attempt, evidence],
    (&'static str, Value),
    (
        "effect.offered",
        json!({"effect":effect,"principal":principal,"attempt":attempt,"evidence":evidence}),
    )
);

meta_arm!(
    effect_settled,
    EffectSettled,
    [effect, expected, outcome, evidence, failure, attempts],
    (&'static str, Value),
    (
        "effect.settled",
        json!({"effect":effect,"expected":expected,"outcome":outcome,"evidence":evidence,"failure":failure,"attempts":attempts}),
    )
);

meta_arm!(
    integration_recorded,
    IntegrationRecorded,
    [
        integration,
        path,
        key,
        marker,
        prior_sha256,
        written_sha256,
        state,
        witness,
        expected
    ],
    (&'static str, Value),
    (
        "integration.recorded",
        json!({"integration":integration,"path":path,"key":key,"marker":marker,"prior_sha256":prior_sha256,"written_sha256":written_sha256,"state":state,"witness":witness,"expected":expected}),
    )
);
