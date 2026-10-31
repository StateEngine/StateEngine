use super::*;
impl SqliteSnapshot {
    pub(super) fn count_messages(&self, query: MessageQuery) -> StoreResult<u64> {
        let project = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let actor_key = |actor: &Actor| {
            key(
                &self.db,
                actor.kind(),
                actor.wire(),
                if actor.kind() == "human" {
                    &[0]
                } else {
                    &scope
                },
                false,
            )
        };
        let to = query.recipient.as_ref().map(actor_key).transpose()?;
        let from = query.sender.as_ref().map(actor_key).transpose()?;
        let own = match &self.scope.visibility {
            Visibility::SelfOnly(agent) => Some(self.agent_bytes(agent)?),
            _ => None,
        };
        // The common inbox count is a maintained projection, so it remains O(1).
        // Filtered counts traverse matching index entries, never mail bodies/events.
        if query.unread_only
            && query.kind.is_none()
            && from.is_none()
            && let Some(recipient) = to.as_ref()
            && own.as_ref().is_none_or(|agent| agent == recipient)
        {
            let total: Option<Option<u64>> = self.db.query_row(
                "SELECT h.unread_count FROM principals p LEFT JOIN resume_heads h ON h.project_id=p.project_id AND h.principal_id=p.principal_id WHERE p.project_id=? AND p.principal_id=?",
                crate::sql_value::sql_params![project, recipient], |r| crate::sql_value::value(r,0)
            ).optional().map_err(|error| self.read_sql(error))?;
            return match total {
                Some(Some(total)) => Ok(total),
                None => Ok(0), // No registered recipient can own matching messages.
                Some(None) => Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "registered recipient resume head absent",
                )),
            };
        }
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        self.db
            .progress_handler(1000, Some(move || Instant::now() >= deadline))
            .map_err(|error| self.read_sql(error))?;
        let result = (|| {
            let count = |recipient: Option<&[u8]>, sender: Option<&[u8]>| {
                let h = self
                    .info
                    .head
                    .as_ref()
                    .map(StorePosition::sequence)
                    .unwrap_or(0);
                let (statement, args) =
                    message::mail_sql(&project, recipient, sender, &query, h, 0, "COUNT(*)");
                self.db
                    .query_row(&statement, rusqlite::params_from_iter(args), |r| {
                        crate::sql_value::value::<u64>(r, 0)
                    })
                    .map_err(|error| self.read_sql(error))
            };
            if let Some(own) = &own {
                let sent_visible = from.as_ref().is_none_or(|sender| sender == own);
                let received_visible = to.as_ref().is_none_or(|recipient| recipient == own);
                let sent = if sent_visible {
                    count(to.as_deref(), Some(own))?
                } else {
                    0
                };
                let received = if received_visible {
                    count(Some(own), from.as_deref())?
                } else {
                    0
                };
                let overlap = if sent_visible && received_visible {
                    count(Some(own), Some(own))?
                } else {
                    0
                };
                sent.checked_add(received)
                    .and_then(|n| n.checked_sub(overlap))
                    .ok_or_else(|| {
                        fail(
                            StoreErrorCode::ProjectionInconsistent,
                            "mail visibility count overflow/overlap",
                        )
                    })
            } else {
                count(to.as_deref(), from.as_deref())
            }
        })();
        self.db
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(|error| self.read_sql(error))?;
        result
    }
}
