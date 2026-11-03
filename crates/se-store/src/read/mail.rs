use super::*;
impl crate::mail::MailSnapshot for SqliteSnapshot {
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
