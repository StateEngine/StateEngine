//! Replay the actual operation which owns an already visible event.
use super::*;

impl SqliteSnapshot {
    /// Owner-only receipt lookup for nonmutating linked grant reissuance.
    /// The original request key and operation membership remain unchanged.
    pub fn event_receipt(&mut self, event: EventId) -> StoreResult<Read<CommitReceipt>> {
        if !matches!(self.scope.visibility, Visibility::Owner) {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "event receipt requires owner visibility",
            ));
        }
        let Some(seq) = self.event_seq(&event)? else {
            return Ok(self.absent("receipt event"));
        };
        let row: Option<(Vec<u8>, Option<String>)> = self.db.query_row(
            "SELECT o.operation_id,o.request_key FROM events e JOIN operations o ON o.operation_id=e.operation_id WHERE e.seq=? AND o.erased=0",
            [seq], |r| Ok((crate::sql_value::value(r, 0)?, crate::sql_value::value(r, 1)?)),
        ).optional().map_err(|error| self.read_sql(error))?;
        let Some((operation, key)) = row else {
            return Ok(self.absent("event operation receipt"));
        };
        let key = key
            .map(se_types::IdempotencyKey::new)
            .transpose()
            .map_err(|_| invalid("retained operation request key"))?;
        let mut value = crate::transaction::receipt(&self.db, &operation, &self.info, key)?;
        value.state = CommitState::Replayed;
        Ok(Read::Present { value })
    }
}
