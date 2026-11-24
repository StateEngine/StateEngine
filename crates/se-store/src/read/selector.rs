//! Owner catalog selectors: stable ID order within a catalog revision.
//! Separate from the CLI's deliberately live, creation-ordered lists.
use super::query::event_size;
use super::*;
use rusqlite::types::Value;

struct SelectorTarget {
    table: &'static str,
    id: &'static str,
    kind: &'static str,
    prefix: &'static str,
    filter: &'static str,
    keys: Vec<Value>,
    identity_scope: Vec<u8>,
    revision: u64,
}

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
        &mut self,
        agents: bool,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>> {
        let deadline = query::deadline(&budget)?;
        let target = self.selector_target(agents)?;
        let binding = format!(
            "selector:{}:{}:{}",
            target.table, self.scope.admission.generation, target.revision
        );
        let (h, after) = self.window(&budget, &binding, true).map_err(|mut e| {
            if budget.page.after.is_some() && e.code == StoreErrorCode::CursorInvalid {
                e.code = StoreErrorCode::CursorStale;
            }
            e
        })?;
        // Canonical IDs have no identities row; legacy IDs retain their exact
        // registered spelling. Both participate in the same binary text order.
        let hex = format!("lower(hex(t.{}))", target.id);
        let canonical = format!(
            "'{}' || substr({hex},1,8) || '-' || substr({hex},9,4) || '-' || substr({hex},13,4) || '-' || substr({hex},17,4) || '-' || substr({hex},21,12)",
            target.prefix
        );
        let sql = format!(
            "WITH catalog AS (SELECT t.revision,t.last_seq,t.first_seq,
             COALESCE((SELECT wire_id FROM identities i WHERE i.storage_key=t.{} AND i.kind='{}' AND i.scope_key=?),{canonical}) AS wire
             FROM {} t WHERE {}),
             ordered AS (SELECT revision,last_seq,ROW_NUMBER() OVER (ORDER BY wire COLLATE BINARY) AS ordinal FROM catalog)
             SELECT revision,last_seq,ordinal FROM ordered WHERE ordinal>? ORDER BY ordinal LIMIT ?",
            target.id, target.kind, target.table, target.filter
        );
        let mut params = vec![Value::Blob(target.identity_scope)];
        params.extend(target.keys);
        params.push(Value::Integer(i64::try_from(after).map_err(invalid)?));
        params.push(Value::Integer(i64::from(budget.page.limit.get()) + 1));
        let rows = self.query_seqs_before(&sql, params, deadline)?;
        self.collect_page(
            rows,
            page::PageCollect {
                budget: &budget,
                binding: &binding,
                h,
                after,
                deadline,
                oversize_cause: "first selector record exceeds bytes",
            },
            |(revision, seq, ordinal)| {
                let (record, cost) =
                    self.load_selector_record(target.table, agents, revision, seq)?;
                Ok((record, cost, ordinal))
            },
        )
    }

    fn selector_target(&self, agents: bool) -> StoreResult<SelectorTarget> {
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
        if agents {
            Ok(SelectorTarget {
                table: "principals",
                id: "principal_id",
                kind: "agent",
                prefix: "ag_",
                filter: "project_id=? AND principal_kind='agent'",
                keys: vec![Value::Blob(self.project_bytes()?)],
                identity_scope: scope_key(&self.db, &self.scope.admission.scope, false)?,
                revision: self.selector_revision()?,
            })
        } else {
            // Include removed projects in the revision: removals must stale a cursor.
            let revision = self
                .db
                .query_row("SELECT COALESCE(MAX(last_seq),0) FROM projects", [], |r| {
                    crate::sql_value::value(r, 0)
                })
                .map_err(|e| self.read_sql(e))?;
            Ok(SelectorTarget {
                table: "projects",
                id: "project_id",
                kind: "project",
                prefix: "prj_",
                filter: "state='active'",
                keys: vec![],
                identity_scope: vec![0],
                revision,
            })
        }
    }

    fn load_selector_record(
        &self,
        table: &str,
        agents: bool,
        revision: u64,
        seq: i64,
    ) -> StoreResult<(ProjectionRecord, u64)> {
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
        Ok((
            ProjectionRecord {
                revision: codec::revision(revision)?,
                original,
                current,
            },
            cost,
        ))
    }
}
