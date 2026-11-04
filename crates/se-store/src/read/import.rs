use super::*;
impl SqliteSnapshot {
    pub fn import_run(&self, id: RecordId) -> StoreResult<Read<ProjectionRecord>> {
        self.import_owner()?;
        self.head(
            "import_runs",
            "import_id=?",
            &[id.as_bytes()],
            Some("first_seq"),
        )
    }
    pub fn import_source(
        &self,
        id: RecordId,
        family: ImportFamily,
        source_key: &[u8],
    ) -> StoreResult<Read<ProjectionRecord>> {
        self.import_owner()?;
        let tag = serde_json::to_value(family).map_err(invalid)?;
        let tag = tag.as_str().ok_or_else(|| invalid("import family tag"))?;
        self.head(
            "import_progress",
            "import_id=? AND family=? AND source_key=?",
            &[id.as_bytes(), &tag, &source_key],
            None,
        )
    }
    pub fn import_legacy(
        &self,
        id: RecordId,
        family: ImportFamily,
        legacy_id: &str,
    ) -> StoreResult<Read<StoredEvent>> {
        self.import_owner()?;
        let tag = serde_json::to_value(family).map_err(invalid)?;
        let tag = tag.as_str().ok_or_else(|| invalid("import family tag"))?;
        let seq:Option<i64>=self.db.query_row("SELECT imported_seq FROM legacy_ids WHERE import_id=? AND family=? AND legacy_id=?",rusqlite::params![id.as_bytes().as_slice(),tag,legacy_id],|r|r.get(0)).optional().map_err(sql)?;
        match seq {
            Some(seq) => Ok(Read::Present {
                value: self.record(seq)?,
            }),
            None => Ok(self.absent("legacy source row")),
        }
    }
    fn import_owner(&self) -> StoreResult<()> {
        if !matches!(self.scope.visibility, Visibility::Owner)
            || !matches!(self.scope.admission.actor, Actor::Human(_))
            || self.scope.admission.session.is_some()
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "user-history import is owner-only",
            ));
        }
        Ok(())
    }
    pub(super) fn read_import_progress(
        &self,
        id: RecordId,
        budget: ReadBudget,
    ) -> StoreResult<Page<ImportCheckpoint>> {
        self.import_owner()?;
        let deadline = query::deadline(&budget)?;
        let binding = format!("live:import-source-key:{}", codec::encode(&id)?);
        let (h, after) = self.window(&budget, &binding, true)?;
        // The numeric cursor names the immutable checkpoint carrying its typed
        // last key. Updates of that source cannot change the continuation key,
        // and legacy source keys never need to fit inside a wire cursor.
        let previous = if after == 0 {
            None
        } else {
            let event = self.record(i64::try_from(after).map_err(invalid)?)?;
            let EventBody::ImportProgress { checkpoint, .. } = event.body else {
                return Err(fail(
                    StoreErrorCode::CursorInvalid,
                    "import cursor is not a checkpoint",
                ));
            };
            if checkpoint.import != id {
                return Err(fail(
                    StoreErrorCode::CursorInvalid,
                    "import cursor names another run",
                ));
            }
            Some(checkpoint)
        };
        let mut params = vec![rusqlite::types::Value::Blob(id.as_bytes().to_vec())];
        let mut sql =
            "SELECT revision,last_seq,last_seq FROM import_progress WHERE import_id=?".to_string();
        if let Some(previous) = previous {
            let family = serde_json::to_value(previous.family).map_err(invalid)?;
            let family = family
                .as_str()
                .ok_or_else(|| invalid("import family tag"))?;
            sql.push_str(" AND (family,source_key)>(?,?)");
            params.push(rusqlite::types::Value::Text(family.into()));
            params.push(rusqlite::types::Value::Blob(previous.source_key));
        }
        sql.push_str(" ORDER BY family,source_key LIMIT ?");
        params.push(rusqlite::types::Value::Integer(
            i64::from(budget.page.limit.get()) + 1,
        ));
        let rows = self.query_seqs_before(&sql, params, deadline)?;
        let mut items = Vec::new();
        let mut bytes = 0;
        let mut last = after;
        let mut stop = StopReason::Exhausted;
        for (revision, seq, _) in rows {
            query::check_deadline(deadline)?;
            if items.len() == budget.page.limit.get() as usize {
                stop = StopReason::ItemLimit;
                break;
            }
            let event = self.record(seq)?;
            let cost = query::event_size(&event)?;
            if bytes + cost > u64::from(budget.page.max_bytes.get()) {
                if items.is_empty() {
                    let mut error = fail(
                        StoreErrorCode::ReadBudgetTooSmall,
                        "first import checkpoint exceeds bytes",
                    );
                    error.detail = StoreDetail::Budget {
                        allowed: u64::from(budget.page.max_bytes.get()),
                        required: Some(cost),
                    };
                    return Err(error);
                }
                stop = StopReason::ByteLimit;
                break;
            }
            let EventBody::ImportProgress { mut checkpoint, .. } = event.body else {
                return Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "import checkpoint head has another kind",
                ));
            };
            if checkpoint.import != id {
                return Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "import checkpoint head has another run",
                ));
            }
            checkpoint.expected = Expected::Revision(codec::revision(revision)?);
            items.push(checkpoint);
            bytes += cost;
            last = seq as u64;
        }
        query::check_deadline(deadline)?;
        self.page(
            items,
            &budget,
            &binding,
            page::PageFacts {
                h,
                after: 0,
                last,
                bytes,
                stop,
                remaining: None,
            },
        )
    }
}
impl crate::import::ImportSnapshot for SqliteSnapshot {
    fn import_root_claim(
        &mut self,
        canonical_key: &[u8],
    ) -> StoreResult<Option<se_types::ProjectId>> {
        self.import_owner()?;
        if self.scope.admission.scope != Scope::Registry {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "source root adoption requires owner registry scope",
            ));
        }
        let project: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT project_id FROM roots WHERE canonical_key=?",
                [canonical_key],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        project
            .map(|id| {
                wire(&self.db, "project", &id, &[0])?
                    .try_into()
                    .map_err(invalid)
            })
            .transpose()
    }
    fn import_prior(
        &mut self,
        label: &str,
    ) -> StoreResult<Option<(se_types::DecisionId, Revision)>> {
        self.import_owner()?;
        let project = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let mut stmt=self.db.prepare("SELECT d.decision_id,d.revision,e.door FROM decisions d JOIN decision_data p ON p.event_seq=d.proposed_seq JOIN events e ON e.seq=d.last_seq WHERE d.project_id=? AND p.decision_key=? AND d.state='ratified' ORDER BY d.last_seq DESC LIMIT 2").map_err(sql)?;
        let rows = stmt
            .query_map(rusqlite::params![project, label], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    crate::sql_value::value::<u64>(r, 1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql)?;
        if rows.len() > 1 {
            return Err(fail(
                StoreErrorCode::ProjectionInconsistent,
                "multiple governing heads for one imported decision key",
            ));
        }
        rows.into_iter()
            .next()
            .map(|(id, revision, door)| {
                if door != "import" {
                    return Err(fail(
                        StoreErrorCode::NaturalKeyConflict,
                        "current governing user law cannot be superseded by imported history",
                    ));
                }
                Ok((
                    wire(&self.db, "decision", &id, &scope)?
                        .try_into()
                        .map_err(invalid)?,
                    crate::codec::revision(revision)?,
                ))
            })
            .transpose()
    }
}
