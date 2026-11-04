//! Finite recipient projection reads after canonical mail visibility admission.
use super::*;
impl SqliteSnapshot {
    pub(super) fn notification_rows(
        &self,
        sent: i64,
        sender: &Actor,
        recipient: &Actor,
        work: Option<&se_types::WorkAddressing>,
        quiet: bool,
    ) -> StoreResult<Vec<NotificationRecord>> {
        let audience = work
            .map(|w| {
                w.addressees
                    .iter()
                    .cloned()
                    .map(Actor::Agent)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![recipient.clone()]);
        let visible = audience
            .into_iter()
            .filter(|who| match &self.scope.visibility {
                Visibility::SelfOnly(agent) if sender != &Actor::Agent(agent.clone()) => {
                    who == &Actor::Agent(agent.clone())
                }
                _ => true,
            })
            .collect::<Vec<_>>();
        if self.info.schema_version < 4 {
            return Ok(visible
                .into_iter()
                .map(|recipient| NotificationRecord {
                    recipient,
                    state: "unmeasured".into(),
                    event: None,
                    recorded_at_us: None,
                    code: None,
                })
                .collect());
        }
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let mut result = Vec::new();
        for recipient in visible {
            let id = key(
                &self.db,
                recipient.kind(),
                recipient.wire(),
                if recipient.kind() == "human" {
                    &[0]
                } else {
                    &scope
                },
                false,
            )?;
            let (stored_quiet,state,sequence,code):(bool,String,Option<i64>,Option<String>)=self.db.query_row("SELECT quiet,wake_state,wake_event_seq,wake_code FROM message_deliveries WHERE sent_seq=? AND recipient_id=?",rusqlite::params![sent,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(|e|self.read_sql(e))?;
            let human = matches!(recipient, Actor::Human(_));
            if stored_quiet != quiet
                || !matches!(
                    state.as_str(),
                    "quiet"
                        | "pending"
                        | "reserved"
                        | "offered"
                        | "held"
                        | "failed"
                        | "unknown"
                        | "unmeasured"
                        | "not-applicable"
                )
                || (state == "quiet" && !quiet)
                || (quiet && !human && state != "quiet")
                || (state == "not-applicable" && !human)
                || (human && !matches!(state.as_str(), "not-applicable" | "unmeasured"))
                || (sequence.is_none() != (state == "unmeasured"))
                || (matches!(state.as_str(), "quiet" | "pending" | "not-applicable")
                    && sequence != Some(sent))
                || if matches!(state.as_str(), "failed" | "unknown") {
                    !code.as_ref().is_some_and(|c| {
                        !c.is_empty()
                            && c.len() <= 64
                            && c.bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    })
                } else {
                    code.is_some()
                }
            {
                return Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "notification intent/state differs from canonical mail",
                ));
            }
            let (event, recorded_at_us) = if let Some(seq) = sequence {
                let (event, at): (Vec<u8>, i64) = self
                    .db
                    .query_row(
                        "SELECT event_id,recorded_at_us FROM events WHERE seq=? AND project_id=?",
                        rusqlite::params![seq, self.project_bytes()?],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .map_err(|e| self.read_sql(e))?;
                (
                    Some(
                        wire(&self.db, "event", &event, &scope)?
                            .try_into()
                            .map_err(invalid)?,
                    ),
                    Some(at),
                )
            } else {
                (None, None)
            };
            result.push(NotificationRecord {
                recipient,
                state,
                event,
                recorded_at_us,
                code,
            });
        }
        Ok(result)
    }
}
