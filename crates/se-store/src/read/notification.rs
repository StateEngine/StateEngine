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
        visible
            .into_iter()
            .map(|recipient| self.notification_row(sent, recipient, quiet, &scope))
            .collect()
    }

    fn notification_row(
        &self,
        sent: i64,
        recipient: Actor,
        quiet: bool,
        scope: &[u8],
    ) -> StoreResult<NotificationRecord> {
        let id = key(
            &self.db,
            recipient.kind(),
            recipient.wire(),
            if recipient.kind() == "human" {
                &[0]
            } else {
                scope
            },
            false,
        )?;
        let row: (bool, String, Option<i64>, Option<String>) = self
            .db
            .query_row(
                "SELECT quiet,wake_state,wake_event_seq,wake_code FROM message_deliveries WHERE sent_seq=? AND recipient_id=?",
                rusqlite::params![sent, id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|e| self.read_sql(e))?;
        let human = matches!(recipient, Actor::Human(_));
        validate_notification_state(sent, human, quiet, &row)?;
        let (_, state, sequence, code) = row;
        if quiet && !human && sequence != Some(sent) {
            let seq = sequence.ok_or_else(|| {
                fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "quiet continuation lacks its notice",
                )
            })?;
            let event = load_event(&self.db, seq, &self.info)
                .map_err(|error| context(error, &self.path, StoreIoStage::ReadSnapshot))?;
            if !matches!(
                &event.body,
                EventBody::EffectRequested {
                    kind: EffectKind::Bell,
                    principal: Some(owner),
                    intent: EffectIntent::MailNotice(notice),
                    ..
                } if owner == &recipient
                    && notice.through.sequence >= sent as u64
                    && Actor::Agent(notice.target_agent.clone()) == recipient
            ) {
                return Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "quiet continuation has no matching committed notice",
                ));
            }
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
                Some(typed_wire(&self.db, "event", &event, scope)?),
                Some(at),
            )
        } else {
            (None, None)
        };
        Ok(NotificationRecord {
            recipient,
            state,
            event,
            recorded_at_us,
            code,
        })
    }
}

fn validate_notification_state(
    sent: i64,
    human: bool,
    quiet: bool,
    (stored_quiet, state, sequence, code): &(bool, String, Option<i64>, Option<String>),
) -> StoreResult<()> {
    let state = state.as_str();
    let code_valid = if matches!(state, "failed" | "unknown") {
        code.as_deref().is_some_and(|c| {
            !c.is_empty()
                && c.len() <= 64
                && c.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    } else {
        code.is_none()
    };
    if *stored_quiet != quiet
        || !matches!(
            state,
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
        || (human && !matches!(state, "not-applicable" | "unmeasured"))
        || (sequence.is_none() != (state == "unmeasured"))
        || (matches!(state, "pending" | "not-applicable") && *sequence != Some(sent))
        || !code_valid
    {
        return Err(fail(
            StoreErrorCode::ProjectionInconsistent,
            "notification intent/state differs from canonical mail",
        ));
    }
    Ok(())
}
