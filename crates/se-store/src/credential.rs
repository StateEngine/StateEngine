use crate::{error::*, identity, open::SqliteReader, *};
use se_types::Read;
pub(crate) fn read(reader: &SqliteReader, hash: [u8; 32]) -> StoreResult<Read<CredentialRecord>> {
    let phase = reader.read_phase()?;
    let result = phase.credential(hash);
    phase.finish(result)
}
pub(crate) fn read_at(
    c: &rusqlite::Connection,
    info: &StoreInfo,
    hash: [u8; 32],
) -> StoreResult<Read<CredentialRecord>> {
    if info.state != StoreState::Ready {
        return Err(fail(
            StoreErrorCode::NotReady,
            "credential lookup store is in maintenance",
        ));
    }
    let mut q=c.prepare("SELECT c.credential_id,c.project_id,c.session_id,c.purpose,c.expires_at_us,c.activation_deadline_us,c.state,c.revision,s.agent_id FROM credentials c LEFT JOIN sessions s ON s.project_id=c.project_id AND s.session_id=c.session_id WHERE c.secret_sha256=?").map_err(sql)?;
    let mut rows = q.query([hash.as_slice()]).map_err(sql)?;
    let value = if let Some(row) = rows.next().map_err(sql)? {
        let project: Vec<u8> = row.get(1).map_err(sql)?;
        let scope = [&[1u8][..], project.as_slice()].concat();
        let agent: Option<Vec<u8>> = row.get(8).map_err(sql)?;
        let agent = agent.ok_or_else(|| {
            fail(
                StoreErrorCode::ProjectionInconsistent,
                "credential session head absent",
            )
        })?;
        let state = match row.get::<_, String>(6).map_err(sql)?.as_str() {
            "prepared" => CredentialState::Prepared,
            "active" => CredentialState::Active,
            "revoked" => CredentialState::Revoked,
            _ => return Err(fail(StoreErrorCode::Unreadable, "credential state invalid")),
        };
        Read::Present {
            value: CredentialRecord {
                credential: crate::codec::capture::record(row.get(0).map_err(sql)?)?,
                project: identity::wire(c, "project", &project, &[0])?
                    .parse()
                    .map_err(invalid)?,
                agent: identity::wire(c, "agent", &agent, &scope)?
                    .parse()
                    .map_err(invalid)?,
                session: identity::wire(
                    c,
                    "session",
                    &row.get::<_, Vec<u8>>(2).map_err(sql)?,
                    &scope,
                )?
                .parse()
                .map_err(invalid)?,
                purpose: row.get(3).map_err(sql)?,
                expires_at_us: row.get(4).map_err(sql)?,
                activation_deadline_us: row.get(5).map_err(sql)?,
                state,
                revision: crate::codec::revision(crate::sql_value::value(row, 7).map_err(sql)?)?,
            },
        }
    } else {
        Read::Absent {
            checked: "credential hash absent in finite store snapshot".into(),
        }
    };
    drop(rows);
    drop(q);
    Ok(value)
}
/// Whether a later launch was prepared for this credential's agent after its
/// session: a still-prepared credential is then no longer the current launch.
pub(crate) fn superseded_at(
    c: &rusqlite::Connection,
    info: &StoreInfo,
    hash: [u8; 32],
) -> StoreResult<bool> {
    if info.state != StoreState::Ready {
        return Err(fail(
            StoreErrorCode::NotReady,
            "credential lookup store is in maintenance",
        ));
    }
    c.query_row("SELECT EXISTS(SELECT 1 FROM credentials c JOIN sessions s ON s.project_id=c.project_id AND s.session_id=c.session_id JOIN sessions later ON later.project_id=s.project_id AND later.agent_id=s.agent_id AND later.first_seq>s.first_seq WHERE c.secret_sha256=?)",[hash.as_slice()],|r|r.get(0)).map_err(sql)
}
/// Whether this credential's session has a process whose stop reconciliation
/// could not prove and the owner has not released: its agent's operations
/// stay fenced whatever the credential's own state.
pub(crate) fn stop_unproved_at(
    c: &rusqlite::Connection,
    info: &StoreInfo,
    hash: [u8; 32],
) -> StoreResult<bool> {
    if info.state != StoreState::Ready {
        return Err(fail(
            StoreErrorCode::NotReady,
            "credential lookup store is in maintenance",
        ));
    }
    c.query_row("SELECT EXISTS(SELECT 1 FROM credentials c JOIN processes p ON p.project_id=c.project_id AND p.state='stop-unproved' AND p.ownership_released=0 JOIN process_data d ON d.event_seq=p.last_seq AND d.target_session_id=c.session_id WHERE c.secret_sha256=?)",[hash.as_slice()],|r|r.get(0)).map_err(sql)
}
