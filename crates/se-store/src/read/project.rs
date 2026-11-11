//! Targeted retained registration lookup; never enumerate the event floor.
use super::*;

impl SqliteSnapshot {
    pub(super) fn read_removed_projects(
        &mut self,
        query: RemovedProjectQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>> {
        let Actor::Human(owner) = &self.scope.admission.actor else {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "retained project lookup requires the owner",
            ));
        };
        if self.scope.admission.scope != Scope::Registry
            || !matches!(self.scope.visibility, Visibility::Owner)
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "retained project lookup requires owner registry scope",
            ));
        }
        let (predicate, selector) = match query {
            RemovedProjectQuery::Name(name) => ("json_extract(a.facts,'$.name')=?", name),
            RemovedProjectQuery::Root(root) => (
                "EXISTS(SELECT 1 FROM json_each(a.facts,'$.roots') r WHERE json_extract(r.value,'$.path')=json(?))",
                codec::encode(&root)?,
            ),
        };
        self.list_heads(
            "projects",
            "first_seq",
            &format!("state='removed' AND EXISTS(SELECT 1 FROM aux_data a WHERE a.event_seq=projects.first_seq AND json_extract(a.facts,'$.owner')=? AND {predicate})"),
            vec![
                rusqlite::types::Value::Text(owner.as_str().into()),
                rusqlite::types::Value::Text(selector),
            ],
            budget,
        )
    }
}
