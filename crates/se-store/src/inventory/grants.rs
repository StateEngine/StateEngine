//! Native Owner grant inventory and immutable security receipt read-back.
use super::*;
use se_types::{Read, remote::RemoteGrantId};

impl ReadPhase {
    pub fn remote_grant(&self, id: &RemoteGrantId) -> StoreResult<Read<GrantRecord>> {
        ready(&self.info)?;
        Ok(match grant_at(&self.db, id)? {
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
                grant_at(&self.db, &id)?
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
