//! Owner catalog selectors: stable ID order within a catalog revision.
//! Separate from the CLI's deliberately live, creation-ordered lists.
use super::query::event_size;
use super::*;

impl SqliteSnapshot {
    /// Revision of project registrations and this selected project's agent roster.
    pub fn selector_revision(&self) -> StoreResult<u64> {
        if !matches!(self.scope.visibility, Visibility::Owner)
            || !matches!(self.scope.admission.actor, Actor::Human(_))
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "selector revision requires owner scope",
            ));
        }
        self.db.query_row(
            "SELECT MAX(COALESCE((SELECT MAX(last_seq) FROM projects),0), COALESCE((SELECT MAX(last_seq) FROM principals WHERE project_id=?),0))",
            [self.project_bytes()?], |r| crate::sql_value::value(r, 0),
        ).map_err(|e| self.read_sql(e))
    }

    pub fn selector_projects(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        self.selector_heads(false, budget)
    }
    pub fn selector_agents(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        self.selector_heads(true, budget)
    }
    fn selector_heads(
        &self,
        agents: bool,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>> {
        let deadline = query::deadline(&budget)?;
        if !matches!(self.scope.visibility, Visibility::Owner)
            || !matches!(self.scope.admission.actor, Actor::Human(_))
            || self.scope.admission.session.is_some()
            || (!agents && self.scope.admission.scope != Scope::Registry)
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "selector requires owner scope",
            ));
        }
        let (table, id, kind, prefix, filter, keys, identity_scope) = if agents {
            (
                "principals",
                "principal_id",
                "agent",
                "ag_",
                "project_id=? AND principal_kind='agent'",
                vec![rusqlite::types::Value::Blob(self.project_bytes()?)],
                scope_key(&self.db, &self.scope.admission.scope, false)?,
            )
        } else {
            (
                "projects",
                "project_id",
                "project",
                "prj_",
                "state='active'",
                vec![],
                vec![0],
            )
        };
        // Include removed projects in the revision: removals must stale a cursor.
        let revision_filter = if agents { filter } else { "1=1" };
        let revision: u64 = if agents {
            self.selector_revision()?
        } else {
            self.db
                .query_row(
                    &format!(
                        "SELECT COALESCE(MAX(last_seq),0) FROM {table} WHERE {revision_filter}"
                    ),
                    rusqlite::params_from_iter(keys.iter()),
                    |r| crate::sql_value::value(r, 0),
                )
                .map_err(|e| self.read_sql(e))?
        };
        let binding = format!(
            "selector:{table}:{}:{revision}",
            self.scope.admission.generation
        );
        let (h, after) = self.window(&budget, &binding, true).map_err(|mut e| {
            if budget.page.after.is_some() && e.code == StoreErrorCode::CursorInvalid {
                e.code = StoreErrorCode::CursorStale;
            }
            e
        })?;
        // Canonical IDs have no identities row; legacy IDs retain their exact
        // registered spelling. Both participate in the same binary text order.
        let hex = format!("lower(hex(t.{id}))");
        let canonical = format!(
            "'{prefix}' || substr({hex},1,8) || '-' || substr({hex},9,4) || '-' || substr({hex},13,4) || '-' || substr({hex},17,4) || '-' || substr({hex},21,12)"
        );
        let sql = format!(
            "WITH catalog AS (SELECT t.revision,t.last_seq,t.first_seq,
             COALESCE((SELECT wire_id FROM identities i WHERE i.storage_key=t.{id} AND i.kind='{kind}' AND i.scope_key=?),{canonical}) AS wire
             FROM {table} t WHERE {filter}),
             ordered AS (SELECT revision,last_seq,ROW_NUMBER() OVER (ORDER BY wire COLLATE BINARY) AS ordinal FROM catalog)
             SELECT revision,last_seq,ordinal FROM ordered WHERE ordinal>? ORDER BY ordinal LIMIT ?"
        );
        let mut params = vec![rusqlite::types::Value::Blob(identity_scope)];
        params.extend(keys);
        params.push(rusqlite::types::Value::Integer(
            i64::try_from(after).map_err(invalid)?,
        ));
        params.push(rusqlite::types::Value::Integer(
            i64::from(budget.page.limit.get()) + 1,
        ));
        let rows = self.query_seqs_before(&sql, params, deadline)?;
        let mut items = Vec::new();
        let mut bytes = 0;
        let mut last = after;
        let mut stop = StopReason::Exhausted;
        for (revision, seq, ordinal) in rows {
            query::check_deadline(deadline)?;
            if items.len() == budget.page.limit.get() as usize {
                stop = StopReason::ItemLimit;
                break;
            }
            let current = if agents {
                self.principal_metadata(seq)?
            } else {
                self.project_metadata(seq)?
            };
            // The original carries immutable role/identity after a rename.
            let first: i64 = self
                .db
                .query_row(
                    &format!("SELECT first_seq FROM {table} WHERE last_seq=?"),
                    [seq],
                    |r| crate::sql_value::value(r, 0),
                )
                .map_err(|e| self.read_sql(e))?;
            let original = if first != seq {
                Some(Box::new(if agents {
                    self.principal_metadata(first)?
                } else {
                    self.project_metadata(first)?
                }))
            } else {
                None
            };
            let cost = event_size(&current)?
                + original
                    .as_ref()
                    .map(|e| event_size(e))
                    .transpose()?
                    .unwrap_or(0);
            if bytes + cost > u64::from(budget.page.max_bytes.get()) {
                if items.is_empty() {
                    return Err(fail(
                        StoreErrorCode::ReadBudgetTooSmall,
                        "first selector record exceeds bytes",
                    ));
                }
                stop = StopReason::ByteLimit;
                break;
            }
            items.push(ProjectionRecord {
                revision: codec::revision(revision)?,
                original,
                current,
            });
            bytes += cost;
            last = ordinal;
        }
        query::check_deadline(deadline)?;
        self.page(
            items,
            &budget,
            &binding,
            page::PageFacts {
                h,
                after,
                last,
                bytes,
                stop,
                remaining: None,
            },
        )
    }
}
