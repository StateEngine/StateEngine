//! Entity revision checks and dispatch before any projection is applied.
use super::*;

pub(crate) fn expected(
    c: &Connection,
    table: &str,
    filter: &str,
    keys: &[&dyn rusqlite::ToSql],
    want: Expected,
) -> StoreResult<u64> {
    let old: Option<u64> = c
        .query_row(
            &format!("SELECT revision FROM {table} WHERE {filter}"),
            keys,
            |r| crate::sql_value::value(r, 0),
        )
        .optional()
        .map_err(sql)?;
    let matches = match want {
        Expected::Absent => old.is_none(),
        Expected::Revision(r) => old == Some(r.value.get()),
    };
    if !matches {
        let mut e = fail(
            StoreErrorCode::RevisionConflict,
            format!("{table} expected entity revision differs"),
        );
        e.detail = StoreDetail::Conflict {
            expected: want,
            observed: old.map(codec::revision).transpose()?,
        };
        return Err(e);
    }
    old.unwrap_or(0)
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or_else(|| invalid("entity revision exhausted"))
}
pub(crate) fn revision_for(c: &Connection, e: &NewEvent) -> StoreResult<u64> {
    use EventBody::*;
    let s = scope_key(c, &e.header.scope, false)?;
    match &e.body {
        ProjectRegistered {
            project,
            expected: want,
            ..
        } => {
            let p = key(c, "project", project.as_str(), &[0], false)?;
            expected(c, "projects", "project_id=?", &[&p], *want)
        }
        PrincipalRegistered {
            principal,
            expected: want,
            ..
        }
        | PrincipalRenamed {
            principal,
            expected: want,
            ..
        } => {
            let a = key(
                c,
                principal.kind(),
                principal.wire(),
                if principal.kind() == "human" {
                    &[0]
                } else {
                    &s
                },
                false,
            )?;
            match &e.header.scope {
                Scope::Registry => expected(c, "owners", "human_id=?", &[&a], *want),
                _ => {
                    let p = project_id(c, &e.header.scope, false)?;
                    expected(
                        c,
                        "principals",
                        "project_id=? AND principal_id=?",
                        &[&p, &a],
                        *want,
                    )
                }
            }
        }
        ProfileSaved {
            agent,
            expected: want,
            ..
        }
        | WorkingStateSet {
            agent,
            expected: want,
            ..
        } => {
            let p = project_id(c, &e.header.scope, false)?;
            let a = key(c, "agent", agent.as_str(), &s, false)?;
            expected(
                c,
                if matches!(&e.body, ProfileSaved { .. }) {
                    "profiles"
                } else {
                    "working_state"
                },
                "project_id=? AND agent_id=?",
                &[&p, &a],
                *want,
            )
        }
        GrantRecorded {
            principal,
            key: grant,
            expected: want,
            ..
        } => {
            let a = key(
                c,
                principal.kind(),
                principal.wire(),
                if principal.kind() == "human" {
                    &[0]
                } else {
                    &s
                },
                false,
            )?;
            expected(
                c,
                "grants",
                "scope_key=? AND principal_id=? AND grant_key=?",
                &[&s, &a, &codec::encode(grant)?],
                *want,
            )
        }
        MessageSent { message, .. } | WorkMessageSent { message, .. } => {
            let p = project_id(c, &e.header.scope, false)?;
            let m = key(c, "message", message.as_str(), &s, false)?;
            expected(
                c,
                connection::mail_table(c)?,
                "project_id=? AND message_id=?",
                &[&p, &m],
                Expected::Absent,
            )
        }
        MessageSuperseded {
            message,
            expected: want,
            ..
        } => {
            let p = project_id(c, &e.header.scope, false)?;
            let m = key(c, "message", message.as_str(), &s, false)?;
            expected(
                c,
                "messages",
                "project_id=? AND message_id=?",
                &[&p, &m],
                *want,
            )
        }
        MessageRead { message, .. }
        | MessageDismissed { message, .. }
        | MessageDelivered { message, .. } => {
            let p = project_id(c, &e.header.scope, false)?;
            let m = key(c, "message", message.as_str(), &s, false)?;
            let rev: u64 = c
                .query_row(
                    &format!(
                        "SELECT revision FROM {} WHERE project_id=? AND message_id=? LIMIT 1",
                        connection::mail_table(c)?
                    ),
                    crate::sql_value::sql_params![p, m],
                    |r| crate::sql_value::value(r, 0),
                )
                .optional()
                .map_err(sql)?
                .ok_or_else(|| {
                    fail(
                        StoreErrorCode::ReferenceMissing,
                        format!("message {} is absent", message.as_str()),
                    )
                })?;
            rev.checked_add(1)
                .filter(|v| *v <= i64::MAX as u64)
                .ok_or_else(|| invalid("message revision exhausted"))
        }
        EventBody::DecisionProposed { .. }
        | EventBody::DecisionRatified { .. }
        | EventBody::DecisionRejected { .. }
        | EventBody::DecisionRetracted { .. }
        | EventBody::DecisionSuperseded { .. } => decision::revision(c, e),
        RuntimeOwnerEstablished { expected: want, .. } => {
            expected(c, "runtime_owner", "singleton=1", &[], *want)
        }
        ProcessRegistered { .. } | ProcessTransition { .. } => process::revision(c, e),
        SessionPrepared { .. }
        | SessionActivated { .. }
        | SessionEnded { .. }
        | SessionRevoked { .. } => session::revision(c, e),
        SessionTurn { .. }
        | CaptureSource { .. }
        | CaptureProgress { .. }
        | CaptureFailed { .. }
        | CaptureVerified { .. }
        | CaptureSuppressed { .. } => capture::revision(c, e),
        CredentialIssued { .. } | CredentialActivated { .. } | CredentialRevoked { .. } => {
            credential::revision(c, e)
        }
        EffectRequested { .. }
        | EffectOffered { .. }
        | EffectSettled { .. }
        | IntegrationRecorded { .. } => effect::revision(c, e),
        ProjectRemoved { .. } | ProjectUpdated { .. } => project::revision(c, e),
        CursorRecorded { .. } | CursorAcknowledged { .. } => cursor::revision(c, e),
        ImportStarted { .. }
        | ImportProgress { .. }
        | ImportFinished { .. }
        | ImportUnreadable { .. }
        | LegacyRetained { .. }
        | AliasImported { .. } => crate::import::revision(c, e),
        ChannelRecorded { change } => super::channel::revision(c, change),
        _ => later("event revision"),
    }
}
