use super::*;
use se_types::{Read, remote::RemoteGrantId};

type GrantRow = (
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    Vec<u8>,
    String,
    String,
    i64,
    i64,
    String,
    i64,
    i64,
    i64,
);
fn uuid(value: Vec<u8>) -> StoreResult<[u8; 16]> {
    value
        .try_into()
        .map_err(|_| invalid("remote UUID byte length"))
}
pub(crate) fn grant(c: &Connection, id: &RemoteGrantId) -> StoreResult<Option<GrantRecord>> {
    let row: Option<GrantRow> = c.query_row(
        "SELECT principal_id,device_id,credential_sha256,host,store_id,subject,scope,issued_at_us,authority_revision,state,last_use_at_us,expires_at_us,lease_revision FROM remote_grants WHERE grant_id=?",
        [key(id.as_str())?], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?)),
    ).optional().map_err(sql)?;
    row.map(
        |(
            principal,
            device,
            credential_sha256,
            host,
            store,
            subject,
            scope,
            issued_at_us,
            authority_revision,
            state,
            last_use_at_us,
            expires_at_us,
            lease_revision,
        )| {
            Ok(GrantRecord {
                grant: id.clone(),
                principal: se_types::remote::RemotePrincipalId::from_bytes(uuid(principal)?)
                    .map_err(invalid)?,
                device: se_types::remote::RemoteDeviceId::from_bytes(uuid(device)?)
                    .map_err(invalid)?,
                credential_sha256: decode(credential_sha256)?,
                host: decode(host)?,
                store: se_types::StoreId::from_bytes(uuid(store)?).map_err(invalid)?,
                subject: decode(subject)?,
                scope: decode(scope)?,
                issued_at_us,
                authority_revision: crate::codec::revision(
                    u64::try_from(authority_revision).map_err(invalid)?,
                )?,
                state: match state.as_str() {
                    "active" => GrantState::Active,
                    "revoked" => GrantState::Revoked,
                    _ => return Err(invalid("grant state")),
                },
                last_use_at_us,
                expires_at_us,
                lease_revision: crate::codec::revision(
                    u64::try_from(lease_revision).map_err(invalid)?,
                )?,
            })
        },
    )
    .transpose()
}

impl ReadPhase {
    pub fn remote_grant(&self, id: &RemoteGrantId) -> StoreResult<Read<GrantRecord>> {
        ready(&self.info)?;
        Ok(match grant(&self.db, id)? {
            Some(value) => Read::Present { value },
            None => Read::Absent {
                checked: "remote grant ID absent on this finite pin".into(),
            },
        })
    }
    /// Finite Owner control inventory, with continuation instead of hidden rows.
    pub fn remote_grants(
        &self,
        after: Option<&RemoteGrantId>,
        limit: usize,
    ) -> StoreResult<(Vec<GrantRecord>, bool)> {
        ready(&self.info)?;
        if !(1..=100).contains(&limit) {
            return Err(invalid("remote grant page limit"));
        }
        let mut q=self.db.prepare("SELECT grant_id FROM remote_grants WHERE (?1 IS NULL OR grant_id>?1) ORDER BY grant_id LIMIT ?2").map_err(sql)?;
        let ids = q
            .query_map(
                rusqlite::params![
                    after.map(|id| key(id.as_str())).transpose()?,
                    (limit + 1) as i64
                ],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        let more = ids.len() > limit;
        let values = ids
            .into_iter()
            .take(limit)
            .map(|id| {
                let id = RemoteGrantId::from_bytes(
                    id.try_into().map_err(|_| invalid("remote grant UUID"))?,
                )
                .map_err(invalid)?;
                grant(&self.db, &id)?
                    .ok_or_else(|| invalid("grant disappeared inside its pinned inventory"))
            })
            .collect::<StoreResult<Vec<_>>>()?;
        Ok((values, more))
    }
}

impl ReadPhase {
    /// Read back the exact immutable event bound by the existing writer receipt.
    pub fn remote_transition(&self, receipt: &CommitReceipt) -> StoreResult<SecurityTransition> {
        ready(&self.info)?;
        if !receipt.first.belongs(&self.info) || !receipt.events.contains(&receipt.primary_event) {
            return Err(denied());
        }
        let event = crate::read::load_event(
            &self.db,
            i64::try_from(receipt.first.sequence()).map_err(invalid)?,
            &self.info,
        )?;
        if event.header.event != receipt.primary_event || event.header.scope != Scope::Registry {
            return Err(denied());
        }
        match event.body {
            EventBody::RemoteSecurity { transition } => Ok(transition),
            _ => Err(denied()),
        }
    }
}
