use super::*;
impl crate::mail::MailSnapshot for SqliteSnapshot {
    fn mail_disposition(
        &mut self,
        event: EventId,
        recipient: AgentId,
    ) -> StoreResult<Read<StoredEvent>> {
        if !matches!((&self.scope.admission.actor, &self.scope.visibility, &self.scope.admission.scope),
            (Actor::Agent(actor), Visibility::SelfOnly(visible), Scope::Project(_))
                if *actor == recipient && *visible == recipient)
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "mail disposition requires this verified recipient's project read scope",
            ));
        }
        let Some(seq) = self.event_seq(&event)? else {
            return Ok(self.absent("mail disposition event ID"));
        };
        // Decode this exact committed fact only after project exclusion. Ordinary
        // event/history readers continue through their existing visibility checks.
        let fact = load_event(&self.db, seq, &self.info)
            .map_err(|error| context(error, &self.path, StoreIoStage::ReadSnapshot))?;
        let who = Actor::Agent(recipient);
        let message = match &fact.body {
            EventBody::MessageRead { message, recipient }
            | EventBody::MessageDismissed { message, recipient }
                if *recipient == who && fact.header.actor == who =>
            {
                message
            }
            _ => {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "event is not a committed read or dismiss for this recipient",
                ));
            }
        };
        let project = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let message_key = key(&self.db, "message", message.as_str(), &scope, false)?;
        let original: Option<i64> = self
            .db
            .query_row(
                "SELECT sent_seq FROM messages WHERE project_id=? AND message_id=?",
                rusqlite::params![project, message_key],
                |r| r.get(0),
            )
            .optional()
            .map_err(|error| self.read_sql(error))?;
        let original = load_event(
            &self.db,
            original.ok_or_else(|| {
                fail(
                    StoreErrorCode::Corrupt,
                    "committed mail disposition has no original message",
                )
            })?,
            &self.info,
        )
        .map_err(|error| context(error, &self.path, StoreIoStage::ReadSnapshot))?;
        if fact.header.scope != self.scope.admission.scope
            || original.header.scope != self.scope.admission.scope
            || !matches!(&original.body, EventBody::MessageSent {message: actual, recipient, ..} if actual == message && *recipient == who)
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "mail disposition's original message belongs to another recipient",
            ));
        }
        Ok(Read::Present { value: fact })
    }

    fn mail_cursor(&self, through: &crate::mail::MailThrough) -> StoreResult<Cursor> {
        if !matches!((&self.scope.admission.actor, &self.scope.visibility),
            (Actor::Agent(actor), Visibility::SelfOnly(recipient)) if actor == recipient)
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "mail cursor requires the verified recipient read scope; owner maintenance must hand readback to that scope",
            ));
        }
        let head = self
            .info
            .head
            .as_ref()
            .map(StorePosition::sequence)
            .unwrap_or(0);
        if through.store != self.info.id
            || through.incarnation != self.info.incarnation
            || through.sequence == 0
            || through.sequence > head
        {
            return Err(fail(
                StoreErrorCode::CursorStale,
                "mail boundary is outside this store, incarnation or snapshot",
            ));
        }
        // A checked query boundary can be the global high-water mark, even
        // when its last event belongs to another scope. No foreign event is
        // read or exposed: the cursor digest binds the recipient and purpose.
        self.cursor(
            &self.position_binding(PositionPurpose::Checked)?,
            through.sequence,
            through.sequence,
        )
    }
    fn mail_notices(
        &mut self,
        recipient: AgentId,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>> {
        match (&self.scope.admission.actor, &self.scope.visibility) {
            (Actor::Human(_), Visibility::Owner) if self.scope.admission.session.is_none() => (),
            (Actor::Agent(actor), Visibility::SelfOnly(visible))
                if *actor == recipient && *visible == recipient => {}
            _ => {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "mail reservation read requires recipient scope or owner maintenance",
                ));
            }
        }
        let p = self.project_bytes()?;
        let a = self.agent_bytes(&recipient)?;
        self.list_heads("effects INDEXED BY effects_principal_pending","requested_seq",
            "project_id=? AND principal_id=? AND state IN ('pending','offered') AND EXISTS(SELECT 1 FROM aux_data a WHERE a.event_seq=effects.requested_seq AND json_type(a.facts,'$.intent.mail_notice')='object')",
            vec![rusqlite::types::Value::Blob(p),rusqlite::types::Value::Blob(a)],budget)
    }
}
