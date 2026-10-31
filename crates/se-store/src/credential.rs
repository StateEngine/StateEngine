use crate::{connection, error::*, identity, open::SqliteReader, *};
use se_types::Read;
use std::sync::atomic::Ordering;
pub(crate) fn read(reader: &SqliteReader, hash: [u8; 32]) -> StoreResult<Read<CredentialRecord>> {
    reader
        .slots
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < 2).then_some(n + 1)
        })
        .map_err(|_| {
            fail(
                StoreErrorCode::Backpressure,
                "two finite read snapshots already in use",
            )
        })?;
    let result = (|| {
        let c = reader.connect()?;
        c.execute_batch("BEGIN").map_err(sql)?;
        if connection::info(&c)?.state != StoreState::Ready {
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
                    project: identity::wire(&c, "project", &project, &[0])?
                        .parse()
                        .map_err(invalid)?,
                    agent: identity::wire(&c, "agent", &agent, &scope)?
                        .parse()
                        .map_err(invalid)?,
                    session: identity::wire(
                        &c,
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
                    revision: crate::codec::revision(
                        crate::sql_value::value(row, 7).map_err(sql)?,
                    )?,
                },
            }
        } else {
            Read::Absent {
                checked: "credential hash absent in finite store snapshot".into(),
            }
        };
        drop(rows);
        drop(q);
        c.execute_batch("ROLLBACK").map_err(sql)?;
        Ok(value)
    })();
    reader.slots.fetch_sub(1, Ordering::AcqRel);
    result
}
