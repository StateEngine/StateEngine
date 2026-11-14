//! Finite native Owner source-address inventory and revocation read-back.
use super::*;
use crate::remote::{source_pending as pending, source_permission as permission};
use se_types::{Read, remote::RemoteAgentAddress};

impl ReadPhase {
    pub fn remote_source_revocation(
        &self,
        address: &RemoteAgentAddress,
    ) -> StoreResult<Read<se_types::IdempotencyKey>> {
        ready(&self.info)?;
        if self.info.schema_version < 12 {
            return Ok(Read::Absent {
                checked: "this store predates source revocation intents".into(),
            });
        }
        Ok(match pending(&self.db, address)? {
            Some(value) => Read::Present { value },
            None => Read::Absent {
                checked: "no unresolved source revocation intent".into(),
            },
        })
    }
    pub fn remote_source_permission(
        &self,
        address: &RemoteAgentAddress,
    ) -> StoreResult<Read<SourcePermission>> {
        ready(&self.info)?;
        if self.info.schema_version < 12 {
            return Ok(Read::Absent {
                checked: "source policy predates this store schema".into(),
            });
        }
        Ok(match permission(&self.db, address)? {
            Some(value) => Read::Present { value },
            None => Read::Absent {
                checked: "no source-address override; existing machine grant permissions apply"
                    .into(),
            },
        })
    }

    /// Owner-only caller supplies a finite page; no unbounded source census.
    pub fn remote_source_contacts(
        &self,
        after: Option<&RemoteAgentAddress>,
        limit: u16,
    ) -> StoreResult<(Vec<SourceContact>, bool)> {
        ready(&self.info)?;
        if self.info.schema_version < 12 || !(1..=100).contains(&limit) {
            return Err(invalid(
                "source inventory requires schema 12 and 1..100 rows",
            ));
        }
        let mut q = self.db.prepare("SELECT address FROM (SELECT address FROM remote_source_contacts UNION SELECT address FROM remote_source_permissions UNION SELECT address FROM remote_source_revocations) WHERE (?1 IS NULL OR address>?1) ORDER BY address LIMIT ?2").map_err(sql)?;
        let addresses = q
            .query_map(
                rusqlite::params![after.map(encode).transpose()?, i64::from(limit) + 1],
                |r| r.get::<_, String>(0),
            )
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        let more = addresses.len() > usize::from(limit);
        let contacts = addresses
            .into_iter()
            .take(usize::from(limit))
            .map(|value| {
                let address = decode(value)?;
                Ok(SourceContact {
                    permission: permission(&self.db, &address)?,
                    pending_revocation: pending(&self.db, &address)?,
                    address,
                })
            })
            .collect::<StoreResult<Vec<_>>>()?;
        Ok((contacts, more))
    }
}
