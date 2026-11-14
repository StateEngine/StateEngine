//! Fair native courier pages have no limit on the retained contact inventory.
use super::*;
use se_types::remote::{RemoteAgentAddress, RemoteHostId, RemoteTarget};

impl ReadPhase {
    pub fn has_remote_mail_for(&self, source: &RemoteAgentAddress) -> StoreResult<bool> {
        if self.info.schema_version < 12 {
            return Ok(false);
        }
        self.db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM remote_mail_catalog WHERE source_address=?)",
                [encode(source)?],
                |r| r.get(0),
            )
            .map_err(sql)
    }
    pub fn remote_mail_catalog(
        &self,
        source: &RemoteAgentAddress,
        after: Option<&MailRoute>,
        limit: u16,
    ) -> StoreResult<(Vec<MailRoute>, bool)> {
        ready(&self.info)?;
        if self.info.schema_version < 12 || !(1..=20).contains(&limit) {
            return Err(invalid("remote route schema or finite page limit"));
        }
        let mut q=self.db.prepare("SELECT peer_host,target FROM remote_mail_catalog WHERE source_address=?1 AND (?2 IS NULL OR peer_host>?2 OR (peer_host=?2 AND target>?3)) ORDER BY peer_host,target LIMIT ?4").map_err(sql)?;
        let rows = q
            .query_map(
                rusqlite::params![
                    encode(source)?,
                    after.map(|r| encode(&r.peer)).transpose()?,
                    after.map(|r| encode(&r.target)).transpose()?,
                    i64::from(limit) + 1
                ],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        let more = rows.len() > usize::from(limit);
        let routes = rows
            .into_iter()
            .take(usize::from(limit))
            .map(|(peer, target)| {
                Ok(MailRoute {
                    peer: decode(peer)?,
                    target: decode(target)?,
                })
            })
            .collect::<StoreResult<Vec<_>>>()?;
        Ok((routes, more))
    }
    pub fn remote_mail_route(
        &self,
        source: &RemoteAgentAddress,
        peer: RemoteHostId,
        target: &RemoteTarget,
    ) -> StoreResult<Option<MailContact>> {
        ready(&self.info)?;
        if self.info.schema_version < 12 {
            return Ok(None);
        }
        let facts:Option<String>=self.db.query_row("SELECT facts FROM remote_mail_routes WHERE source_address=? AND peer_host=? AND target=?",
            rusqlite::params![encode(source)?,encode(&peer)?,encode(target)?],|r|r.get(0)).optional().map_err(sql)?;
        facts.map(decode).transpose()
    }
    pub fn remote_pending_contact_page(
        &self,
        source: &RemoteAgentAddress,
        after: u64,
        limit: u16,
    ) -> StoreResult<(Vec<(PendingContact, u64)>, bool)> {
        ready(&self.info)?;
        if self.info.schema_version < 12 || !(1..=20).contains(&limit) {
            return Err(invalid(
                "remote pending-contact schema or finite page limit",
            ));
        }
        let mut q=self.db.prepare("SELECT facts,event_seq FROM remote_contact_pending WHERE source_address=? AND event_seq>? ORDER BY event_seq LIMIT ?").map_err(sql)?;
        let rows = q
            .query_map(
                rusqlite::params![
                    encode(source)?,
                    i64::try_from(after).map_err(invalid)?,
                    i64::from(limit) + 1
                ],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        let more = rows.len() > usize::from(limit);
        let pending = rows
            .into_iter()
            .take(usize::from(limit))
            .map(|(facts, seq)| Ok((decode(facts)?, u64::try_from(seq).map_err(invalid)?)))
            .collect::<StoreResult<Vec<_>>>()?;
        Ok((pending, more))
    }
}
