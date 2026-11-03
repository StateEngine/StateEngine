use super::*;
impl crate::mail::MailSnapshot for SqliteSnapshot {
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
