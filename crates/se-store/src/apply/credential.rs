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
    let p = project_id(c, &h.scope, true)?;
    let scope = scope_key(c, &h.scope, true)?;
    let recorded: i64 = c
        .query_row(
            "SELECT recorded_at_us FROM events WHERE seq=?",
            [seq],
            |r| r.get(0),
        )
        .map_err(sql)?;
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
            if expected != Expected::Absent
                || purpose.is_empty()
                || purpose.len() > 128
                || secret_sha256 == [0; 32]
                || expires_at_us <= recorded
                || activation_deadline_us <= recorded
                || activation_deadline_us > expires_at_us
                || activation_deadline_us
                    > recorded
                        .checked_add(600_000_000)
                        .ok_or_else(|| invalid("credential deadline overflow"))?
            {
                return Err(invalid("credential issuance identity/deadline bounds"));
            }
            let session = key(c, "session", session.as_str(), &scope, false)?;
            let head = codec::session::head(c, &p, &session)?;
            if !matches!(head.state.as_str(), "prepared" | "active") {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "credential session is terminal",
                ));
            }
            c.execute("INSERT INTO credentials(credential_id,project_id,session_id,purpose,secret_sha256,expires_at_us,revision,last_seq,activation_deadline_us,state) VALUES(?,?,?,?,?,?,?,?,?,'prepared')",crate::sql_value::sql_params![credential.as_bytes().as_slice(),p,session,purpose,secret_sha256,expires_at_us,rev,seq,activation_deadline_us]).map_err(sql)?;
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
            payload(c, seq, "reason", &codec::text(reason, 16384)?)?;
            codec::aux(c, seq, facts)?;
        }
        _ => return Err(invalid("credential apply dispatch")),
    }
    Ok(())
}
