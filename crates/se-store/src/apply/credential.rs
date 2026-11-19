use super::*;
pub(super) fn revision(c: &Connection, e: &NewEvent) -> StoreResult<u64> {
    let (id, want) = match &e.body {
        EventBody::CredentialIssued {
            credential,
            expected,
            ..
        }
        | EventBody::CredentialActivated {
            credential,
            expected,
            ..
        }
        | EventBody::CredentialRotated {
            credential,
            expected,
            ..
        }
        | EventBody::CredentialRevoked {
            credential,
            expected,
            ..
        } => (credential, *expected),
        _ => return Err(invalid("credential revision dispatch")),
    };
    let p = project_id(c, &e.header.scope, false)?;
    expected(
        c,
        "credentials",
        "credential_id=? AND project_id=?",
        &[&id.as_bytes().as_slice(), &p],
        want,
    )
}
pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    rev: u64,
    facts: Value,
) -> StoreResult<()> {
    use EventBody::*;
    let body = match body {
        CredentialRotated {
            credential,
            session,
            secret_sha256,
            expires_at_us,
            ..
        } => {
            return rotate_apply(
                c,
                h,
                seq,
                rev,
                facts,
                (credential, session, secret_sha256, expires_at_us),
            );
        }
        other => other,
    };
    let p = project_id(c, &h.scope, true)?;
    let scope = scope_key(c, &h.scope, true)?;
    let recorded = recorded_at(c, seq)?;
    match body {
        CredentialIssued {
            credential,
            session,
            purpose,
            secret_sha256,
            expires_at_us,
            activation_deadline_us,
            expected,
        } => {
            issue(
                c,
                &p,
                &scope,
                seq,
                rev,
                Issuance {
                    credential,
                    session,
                    purpose,
                    secret_sha256,
                    expires_at_us,
                    activation_deadline_us,
                    expected,
                    recorded,
                },
            )?;
            codec::aux(c, seq, facts)?;
        }
        CredentialActivated {
            credential,
            session,
            ..
        } => {
            let session = key(c, "session", session.as_str(), &scope, false)?;
            let head = codec::session::head(c, &p, &session)?;
            if head.state != "active" {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "credential activation requires same-transaction active session binding",
                ));
            }
            let changed=c.execute("UPDATE credentials SET revision=?,last_seq=?,activated_seq=?,state='active' WHERE credential_id=? AND project_id=? AND session_id=? AND revision=? AND state='prepared' AND activation_deadline_us>=? AND expires_at_us>?",crate::sql_value::sql_params![rev,seq,seq,credential.as_bytes().as_slice(),p,session,rev-1,recorded,recorded]).map_err(sql)?;
            if changed != 1 {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "credential expired, terminal or bound to another session",
                ));
            }
            codec::aux(c, seq, facts)?;
        }
        CredentialRevoked {
            credential, reason, ..
        } => {
            let changed=c.execute("UPDATE credentials SET revision=?,last_seq=?,state='revoked' WHERE credential_id=? AND project_id=? AND revision=? AND state IN ('prepared','active')",crate::sql_value::sql_params![rev,seq,credential.as_bytes().as_slice(),p,rev-1]).map_err(sql)?;
            if changed != 1 {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "credential already terminal",
                ));
            }
            payload(
                c,
                seq,
                "reason",
                &codec::text(reason.as_materialized()?, 16384)?,
            )?;
            codec::aux(c, seq, facts)?;
        }
        _ => return Err(invalid("credential apply dispatch")),
    }
    Ok(())
}

fn recorded_at(c: &Connection, seq: i64) -> StoreResult<i64> {
    c.query_row(
        "SELECT recorded_at_us FROM events WHERE seq=?",
        [seq],
        |r| r.get(0),
    )
    .map_err(sql)
}

struct Rotation {
    credential: RecordId,
    session: se_types::SessionId,
    secret_sha256: [u8; 32],
    expires_at_us: i64,
    recorded: i64,
}
fn rotate(
    c: &Connection,
    project: &[u8],
    scope: &[u8],
    seq: i64,
    rev: u64,
    change: Rotation,
) -> StoreResult<()> {
    if change.secret_sha256 == [0; 32] || change.expires_at_us <= change.recorded {
        return Err(invalid(
            "rotated credential requires a nonzero digest and future expiry",
        ));
    }
    let session = key(c, "session", change.session.as_str(), scope, false)?;
    let head = codec::session::head(c, project, &session)?;
    if head.state != "active" {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "rotated credential requires an active session",
        ));
    }
    let changed = c.execute(
        "UPDATE credentials SET revision=?,last_seq=?,secret_sha256=?,expires_at_us=? WHERE credential_id=? AND project_id=? AND session_id=? AND revision=? AND state='active'",
        crate::sql_value::sql_params![rev, seq, change.secret_sha256, change.expires_at_us,
            change.credential.as_bytes().as_slice(), project, session, rev-1],
    ).map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "credential is not the active original session grant",
        ));
    }
    Ok(())
}

fn rotate_apply(
    c: &Connection,
    h: &EventHeader,
    seq: i64,
    rev: u64,
    facts: Value,
    (credential, session, secret_sha256, expires_at_us): (
        RecordId,
        se_types::SessionId,
        [u8; 32],
        i64,
    ),
) -> StoreResult<()> {
    let project = project_id(c, &h.scope, true)?;
    let scope = scope_key(c, &h.scope, true)?;
    let recorded: i64 = c
        .query_row(
            "SELECT recorded_at_us FROM events WHERE seq=?",
            [seq],
            |r| r.get(0),
        )
        .map_err(sql)?;
    rotate(
        c,
        &project,
        &scope,
        seq,
        rev,
        Rotation {
            credential,
            session,
            secret_sha256,
            expires_at_us,
            recorded,
        },
    )?;
    codec::aux(c, seq, facts)
}

struct Issuance {
    credential: RecordId,
    session: se_types::SessionId,
    purpose: String,
    secret_sha256: [u8; 32],
    expires_at_us: i64,
    activation_deadline_us: i64,
    expected: Expected,
    recorded: i64,
}
fn issue(
    c: &Connection,
    p: &[u8],
    scope: &[u8],
    seq: i64,
    rev: u64,
    value: Issuance,
) -> StoreResult<()> {
    if value.expected != Expected::Absent
        || value.purpose.is_empty()
        || value.purpose.len() > 128
        || value.secret_sha256 == [0; 32]
        || value.expires_at_us <= value.recorded
        || value.activation_deadline_us <= value.recorded
        || value.activation_deadline_us > value.expires_at_us
        || value.activation_deadline_us
            > value
                .recorded
                .checked_add(600_000_000)
                .ok_or_else(|| invalid("credential deadline overflow"))?
    {
        return Err(invalid("credential issuance identity/deadline bounds"));
    }
    let session = key(c, "session", value.session.as_str(), scope, false)?;
    let head = codec::session::head(c, p, &session)?;
    if !matches!(head.state.as_str(), "prepared" | "active") {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "credential session is terminal",
        ));
    }
    c.execute("INSERT INTO credentials(credential_id,project_id,session_id,purpose,secret_sha256,expires_at_us,revision,last_seq,activation_deadline_us,state) VALUES(?,?,?,?,?,?,?,?,?,'prepared')",
        crate::sql_value::sql_params![value.credential.as_bytes().as_slice(),p,session,value.purpose,value.secret_sha256,value.expires_at_us,rev,seq,value.activation_deadline_us]).map_err(sql)?;
    Ok(())
}
