//! The cold embedded pair uses the same append/apply implementation, with
//! whole-pair rollback instead of independent operation savepoints.
use super::*;
impl Engine {
    pub(crate) fn first_binding(&mut self, binding: FirstBinding) -> StoreResult<FirstBindingReceipt> {
        validate(&binding)?;
        let (mut results, _) = self.commit(vec![binding.owner, binding.session], true, true)?;
        let session = results.pop().ok_or_else(|| invalid("first session receipt missing"))??;
        let owner = results.pop().ok_or_else(|| invalid("first owner receipt missing"))??;
        Ok(FirstBindingReceipt { owner, session })
    }
}
fn validate(binding: &FirstBinding) -> StoreResult<()> {
    let owner = &binding.owner;
    let session = &binding.session;
    if owner.request.is_none() || session.request.is_none()
        || owner.admission.scope != Scope::Registry || owner.admission.session.is_some()
        || !matches!(owner.admission.actor, Actor::Human(_))
        || !matches!(session.admission.scope, Scope::Project(_))
        || owner.expected_incarnation != session.expected_incarnation
        || owner.admission.generation != session.admission.generation
        || owner.events.len() != 1 || owner.import_checkpoint.is_some() || session.import_checkpoint.is_some()
    { return Err(invalid("first binding requires separate keyed registry-owner and project-session admissions")); }
    let EventBody::RuntimeOwnerEstablished { generation, recovered: None, .. } = &owner.events[0].body else {
        return Err(invalid("first binding owner must be one ordinary cold runtime.owner"));
    };
    if generation.get() != owner.admission.generation { return Err(invalid("first binding owner generation differs")); }
    let mut prepared = None;
    let mut activated = None;
    for event in &session.events {
        if event.header.door == Door::Import { return Err(invalid("first binding is not historical import")); }
        match &event.body {
            EventBody::SessionPrepared { session, generation: g, surface: Some(SessionSurface::SeCode), native_ref, .. }
                if prepared.is_none() && activated.is_none() && *g == generation.get() && !native_ref.is_empty() => { prepared = Some(session); }
            EventBody::SessionActivated { session, process: None, containment: ContainmentFact::NotLaunched, .. }
                if activated.is_none() && prepared == Some(session) => { activated = Some(session); }
            EventBody::SessionEnded { session, .. } | EventBody::SessionRevoked { session, .. }
                if activated.is_none() && prepared != Some(session) => {}
            _ => return Err(invalid("first binding permits only its embedded preparation, incumbent terminal facts and activation")),
        }
    }
    if activated.is_none() || session.admission.session.as_ref().is_some_and(|id| Some(id) != activated) {
        return Err(invalid("first binding requires the actual prepared session activation"));
    }
    Ok(())
}
pub(super) fn check_pair(c: &Connection, batches: &[StoreResult<AtomicBatch>], info: &StoreInfo) -> StoreResult<()> {
    let mut existing = Vec::new();
    for batch in batches {
        let batch = batch.as_ref().map_err(Clone::clone)?;
        let request = batch.request.as_ref().ok_or_else(|| invalid("first binding key missing"))?;
        let scope = scope_key(c, &batch.admission.scope, false)?;
        let actor = key(c, batch.admission.actor.kind(), batch.admission.actor.wire(), if batch.admission.actor.kind() == "human" { &[0] } else { &scope }, false)?;
        let op: Option<Vec<u8>> = c.query_row("SELECT operation_id FROM operations WHERE scope_key=? AND actor_id=? AND request_key=?",rusqlite::params![scope,actor,request.key.as_str()],|row| row.get(0)).optional().map_err(sql)?;
        existing.push(op);
    }
    if existing.iter().filter(|op| op.is_some()).count() == 1 {
        return Err(fail(StoreErrorCode::ProjectionInconsistent, "first binding has only one retained operation; preserve this store"));
    }
    if existing.iter().all(Option::is_some) {
        let mut owner_generation = None;
        for (index, op) in existing.into_iter().enumerate() {
            let batch = batches[index].as_ref().map_err(Clone::clone)?;
            let retained = receipt(c, &op.ok_or_else(|| invalid("retained pair disappeared"))?, info, batch.request.as_ref().map(|r| r.key.clone()))?;
            if retained.durability != CommitDurability::Full { return Err(fail(StoreErrorCode::ProjectionInconsistent, "first binding lacks FULL stamps")); }
            let mut activations = 0;
            let mut preparations = 0;
            for id in &retained.events {
                let scope = scope_key(c, &batch.admission.scope, false)?;
                let event = key(c, "event", id.as_str(), &scope, false)?;
                let seq = c.query_row("SELECT seq FROM events WHERE event_id=?",[event],|row| row.get(0)).map_err(sql)?;
                let event = crate::read::load_event(c, seq, info)?;
                if event.header.scope != batch.admission.scope || event.header.actor != batch.admission.actor { return Err(fail(StoreErrorCode::ProjectionInconsistent, "first binding membership scope/actor differs")); }
                match event.body {
                    EventBody::RuntimeOwnerEstablished { generation, recovered: None, .. } if index == 0 && retained.events.len() == 1 => { owner_generation = Some(generation.get()); }
                    EventBody::SessionPrepared { generation, surface: Some(SessionSurface::SeCode), .. } if index == 1 && owner_generation == Some(generation) => { preparations += 1; }
                    EventBody::SessionActivated { process: None, containment: ContainmentFact::NotLaunched, .. } if index == 1 => { activations += 1; }
                    EventBody::SessionEnded { .. } | EventBody::SessionRevoked { .. } if index == 1 => {}
                    _ => return Err(fail(StoreErrorCode::ProjectionInconsistent, "first binding retained membership differs")),
                }
            }
            if index == 1 && (activations != 1 || preparations != 1 || owner_generation.is_none()) { return Err(fail(StoreErrorCode::ProjectionInconsistent, "first binding retained activation missing")); }
        }
    } else {
        let phase: Option<Option<String>> = c.query_row("SELECT phase FROM runtime_owner WHERE singleton=1",[],|row| row.get(0)).optional().map_err(sql)?;
        if phase.flatten().as_deref().is_some_and(|phase| matches!(phase,"Prepared" | "Claimed")) { return Err(fail(StoreErrorCode::InvalidTransition,"first binding cannot cross an unresolved handover")); }
    }
    Ok(())
}
