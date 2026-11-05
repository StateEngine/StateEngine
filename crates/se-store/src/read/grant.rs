//! A permission decision may read the caller's own create grant without making
//! the owner-authored event visible to ordinary event/history readers.
use super::*;

impl SqliteSnapshot {
    pub(super) fn grant_event(
        &self,
        seq: i64,
        principal: &Actor,
        key: &GrantKey,
    ) -> StoreResult<StoredEvent> {
        let Visibility::SelfOnly(agent) = &self.scope.visibility else {
            return self.record(seq);
        };
        if *principal != Actor::Agent(agent.clone())
            || !matches!(key, GrantKey::AgentCanCreate(target) if target == agent)
        {
            return self.record(seq);
        }
        let event = load_event(&self.db, seq, &self.info)
            .map_err(|error| context(error, &self.path, StoreIoStage::ReadSnapshot))?;
        if event.header.scope != self.scope.admission.scope
            || !matches!(&event.body, EventBody::GrantRecorded {
                principal: target, key: GrantKey::AgentCanCreate(granted), ..
            } if target == principal && granted == agent)
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "create-grant projection is outside the caller's own permission",
            ));
        }
        Ok(event)
    }
}
