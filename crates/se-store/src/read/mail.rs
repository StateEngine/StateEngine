use super::*;
impl crate::mail::MailSnapshot for SqliteSnapshot {
    fn mail_resolution(
        &mut self,
        message: se_types::MessageId,
        recipient: AgentId,
    ) -> StoreResult<Read<StoredEvent>> {
        let record = match self.message(message)? {
            Read::Present { value } => value,
            Read::Absent { checked } => return Ok(Read::Absent { checked }),
            Read::Unknown { what } => return Ok(Read::Unknown { what }),
            Read::Unreadable {
                source,
                reason,
                error,
            } => {
                return Ok(Read::Unreadable {
                    source,
                    reason,
                    error,
                });
            }
        };
        if record.recipient != Actor::Agent(recipient.clone()) {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "mail resolution belongs to another recipient",
            ));
        }
        let Some(position) = record.read.or(record.dismissed) else {
            return Ok(self.absent("recipient has not read or dismissed this message"));
        };
        let event = load_event(&self.db, position.sequence() as i64, &self.info)
            .map_err(|error| context(error, &self.path, StoreIoStage::ReadSnapshot))?;
        self.mail_disposition(event.header.event, recipient)
    }
    fn mail_input(
        &mut self,
        recipient: AgentId,
        session: SessionId,
        after: StorePosition,
        text_sha256: [u8; 32],
        deadline: std::time::Duration,
    ) -> StoreResult<Read<StoredEvent>> {
        if !matches!((&self.scope.admission.actor, &self.scope.visibility),
            (Actor::Agent(actor), Visibility::SelfOnly(visible)) if *actor == recipient && *visible == recipient)
            || !after.belongs(&self.info)
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "mail input requires its recipient and checked store boundary",
            ));
        }
        let project = self.project_bytes()?;
        let agent = self.agent_bytes(&recipient)?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let session_key = key(&self.db, "session", session.as_str(), &scope, false)?;
        let until = Instant::now() + deadline.min(std::time::Duration::from_secs(1));
        self.db
            .progress_handler(1000, Some(move || Instant::now() >= until))
            .map_err(|error| self.read_sql(error))?;
        // Apply the hash predicate before LIMIT. A later unrelated turn cannot
        // hide the accepted notice; payload bytes are independently checked by record().
        let result = (|| -> StoreResult<(Option<i64>, bool)> {
            let seq = self.db.query_row(
                "SELECT t.event_seq FROM turn_data t INDEXED BY turn_data_agent_seq JOIN payloads p ON p.payload_id=t.text_payload AND p.event_seq=t.event_seq AND p.field='body' WHERE t.project_id=? AND t.agent_id=? AND t.session_id=? AND t.role='user' AND t.event_seq>? AND p.sha256=? ORDER BY t.event_seq LIMIT 1",
                rusqlite::params![project,agent,session_key,after.sequence() as i64,text_sha256.as_slice()], |row|row.get(0))
                .optional().map_err(|error|self.read_sql(error))?;
            let erased = if seq.is_none() {
                self.db.query_row("SELECT EXISTS(SELECT 1 FROM turn_data INDEXED BY turn_data_agent_seq WHERE project_id=? AND agent_id=? AND session_id=? AND role='user' AND event_seq>? AND text_payload IS NULL)",
                    rusqlite::params![project,agent,session_key,after.sequence() as i64], |row|row.get::<_,bool>(0)).map_err(|error|self.read_sql(error))?
            } else {
                false
            };
            Ok((seq, erased))
        })();
        self.db
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(|error| self.read_sql(error))?;
        let (seq, erased) = result?;
        if Instant::now() >= until {
            return Err(fail(
                StoreErrorCode::ReadIncomplete,
                "mail input correlation scan exceeded its finite deadline; preserve the notice and retry its original interval",
            ));
        }
        if erased {
            return Err(fail(
                StoreErrorCode::Unreadable,
                "unmatched recipient input was erased inside the notice interval; absence of the expected input cannot be proved",
            ));
        }
        let Some(seq) = seq else {
            return Ok(self.absent("complete checked recipient/session input interval contains no matching notice hash"));
        };
        let event = self.record(seq)?;
        if !matches!(&event.body, EventBody::SessionTurn { agent, session: actual, role: Role::User, .. } if *agent == recipient && *actual == session)
        {
            return Err(fail(
                StoreErrorCode::ProjectionInconsistent,
                "mail input index differs from its captured event",
            ));
        }
        Ok(Read::Present { value: event })
    }
    fn mail_pending(
        &mut self,
        recipient: AgentId,
        budget: ReadBudget,
    ) -> StoreResult<Page<MessageRecord>> {
        if !matches!((&self.scope.admission.actor, &self.scope.visibility),
            (Actor::Agent(actor), Visibility::SelfOnly(visible)) if *actor == recipient && *visible == recipient)
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "pending mail requires the verified recipient scope",
            ));
        }
        self.read_messages_with_delivery(
            MessageQuery {
                recipient: Some(Actor::Agent(recipient)),
                sender: None,
                kind: None,
                unread_only: true,
                full_body: false,
            },
            budget,
            true,
        )
    }

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
