//! Native Owner controls recover their exact FULL transition without rewriting it.
use crate::{
    error::*,
    remote::{SecurityTransition, denied, ready},
    *,
};
use rusqlite::OptionalExtension;
use se_types::Read;

impl ReadPhase {
    pub fn remote_security_receipt(
        &self,
        owner: &se_types::HumanId,
        key_value: &se_types::IdempotencyKey,
    ) -> StoreResult<Read<(CommitReceipt, SecurityTransition)>> {
        ready(&self.info)?;
        let owner = crate::identity::key(&self.db, "human", owner.as_str(), &[0], false)?;
        let known: bool = self
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM owners WHERE human_id=?)",
                [&owner],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if !known {
            return Err(denied());
        }
        let scope = crate::identity::scope_key(&self.db, &Scope::Registry, false)?;
        let row:Option<(Vec<u8>,bool)>=self.db.query_row("SELECT operation_id,erased FROM operations WHERE scope_key=? AND actor_id=? AND request_key=?",
            rusqlite::params![scope,owner,key_value.as_str()],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(sql)?;
        let Some((operation, erased)) = row else {
            return Ok(Read::Absent {
                checked: "this native Owner key has no committed security transition".into(),
            });
        };
        if erased {
            return Err(fail(
                StoreErrorCode::Unreadable,
                "the original Owner transition receipt was erased; restore retained history before resolving this key",
            ));
        }
        let mut receipt =
            crate::transaction::receipt(&self.db, &operation, &self.info, Some(key_value.clone()))?;
        receipt.state = CommitState::Replayed;
        let transition = self.remote_transition(&receipt)?;
        Ok(Read::Present {
            value: (receipt, transition),
        })
    }
}
