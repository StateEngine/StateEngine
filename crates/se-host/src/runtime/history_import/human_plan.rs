//! Source-ordered names and correspondence checks precede every adoption write.
use super::*;
use se_types::HumanId;
use std::collections::{BTreeMap, BTreeSet};
pub(super) type Names = std::sync::Arc<BTreeMap<HumanId, String>>;

pub(super) fn inspect(
    context: &ExecutionContext,
    admission: &Admission,
    plan: &plan::Plan,
    mappings: &BTreeMap<HumanId, HumanId>,
    deadline: &Deadline,
) -> Result<Names> {
    let mut humans = BTreeMap::new();
    match source::SourceFile::open(plan.root.join(".stateengine/humans.jsonl"), None, deadline)? {
        Read::Present { mut value } => {
            while let Some(row) = value.next(deadline)? {
                let Some(row) = row.value else { continue };
                let Some(text) = row.get("human_id").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let id = HumanId::from_legacy(text)?;
                let name = row
                    .get("display_name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                if let Some(previous) = humans.insert(id, name.clone())
                    && previous != name
                {
                    return Err(scope::unreadable(
                        "source human names",
                        "one source ID has conflicting recorded names",
                    ));
                }
                if humans.len() > 4096 {
                    return Err(scope::unreadable(
                        "source human names",
                        "more than 4096 source humans",
                    ));
                }
            }
            value.verify(deadline)?;
        }
        Read::Absent { .. } => (),
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => return Err(scope::unreadable("source human names", &what)),
    }
    for project in &plan.projects {
        deadline.remaining()?;
        let mut own = admission.clone();
        own.scope = Scope::Project(project.id.clone());
        read::snapshot(context, &own, |read| {
            for source in humans.keys() {
                let target = mappings.get(source).unwrap_or(source);
                let key = format!("owned:owners:human:{source}");
                let event = node::event_id(&own.scope, &key).map_err(|e| store_error(&e))?;
                match read.event(event).map_err(|e| store_error(&e))? {
                    Read::Present { value } => {
                        let EventBody::LegacyRetained { mapped_id, .. } = value.body else {
                            return Err(scope::unreadable(
                                "human correspondence",
                                "original source owner has another event kind",
                            ));
                        };
                        let proposed =
                            import::LegacyTarget::Principal(Actor::Human(target.clone()));
                        if mapped_id != proposed {
                            return Err(se_types::SeError::new(se_types::Detail::StateConflict(se_types::details::StateConflict {
                                subject: "historical human correspondence".into(),
                                reason: format!("source human {source} in project {} has earlier correspondence {mapped_id:?}; requested target is {target}", project.id),
                                next_step: "Reuse the earlier correspondence, including its --map-human argument; another request key cannot replace it. Preserve this home and use a separate destination for a different identity correspondence.".into(),
                            })));
                        }
                    }
                    Read::Absent { .. } => (),
                    Read::Unreadable { source, reason, .. } => {
                        return Err(scope::unreadable(&source, &reason));
                    }
                    Read::Unknown { what } => {
                        return Err(scope::unreadable("human correspondence", &what));
                    }
                }
            }
            for (source, target) in mappings {
                // Explicitly mapping onto the importing owner is intentional:
                // project adoption already registers that current owner.
                if own.actor == Actor::Human(target.clone()) {
                    continue;
                }
                match read
                    .principal(Actor::Human(target.clone()))
                    .map_err(|e| store_error(&e))?
                {
                    Read::Present { .. } => (),
                    Read::Absent { .. } => {
                        return Err(scope::unreadable(
                            "--map-human target",
                            &format!(
                                "source human {source} names target {target}, which is not registered in project {}; no import run or project was adopted",
                                project.id
                            ),
                        ));
                    }
                    Read::Unreadable { source, reason, .. } => {
                        return Err(scope::unreadable(&source, &reason));
                    }
                    Read::Unknown { what } => {
                        return Err(scope::unreadable("--map-human target", &what));
                    }
                }
            }
            Ok(())
        })?;
    }
    let mut first = BTreeSet::new();
    let mut names = BTreeMap::new();
    let mut assigned = BTreeSet::new();
    // BTreeMap order makes the lowest exact source ID own the plain spelling,
    // even when the source rows arrive in a different order.
    for (id, recorded) in humans {
        if mappings.contains_key(&id) {
            continue; // Existing targets keep their own names.
        }
        let Some(recorded) = recorded.filter(|name| !name.is_empty()) else {
            continue;
        };
        let name = if first.insert(recorded.to_ascii_lowercase()) {
            recorded
        } else {
            node::historical_human_name(&recorded, &id)
        };
        if !assigned.insert(name.to_ascii_lowercase()) {
            return Err(scope::unreadable(
                "source human names",
                "deterministic source names collide; preserve the source and supply explicit human correspondence",
            ));
        }
        names.insert(id, name);
    }
    Ok(std::sync::Arc::new(names))
}
