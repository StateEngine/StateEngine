//! Grant-filtered bounded durable replay; private floor positions never become wire values here.
use super::*;
use se_types::remote::*;
use std::time::{Duration, Instant};
pub enum ChangeKind {
    Durable(RemoteDurableEvent),
    ObserveStatus,
    Unavailable { reason: String },
}
pub struct Change {
    pub position: StorePosition,
    pub kind: ChangeKind,
}
pub struct ChangeRequest<'a> {
    pub after: Option<&'a StorePosition>,
    pub limit: u16,
    pub budget: u32,
}
pub struct ChangePage {
    pub changes: Vec<Change>,
    pub through: Option<StorePosition>,
    pub more: bool,
}
impl ReadPhase {
    /// Fresh watches start at this authorized finite snapshot, not at floor zero.
    pub fn remote_watch_position(
        &self,
        grant_id: &RemoteGrantId,
        revision: Revision,
        target: &RemoteTarget,
        now: i64,
    ) -> StoreResult<Option<StorePosition>> {
        self.remote_target(grant_id, revision, RemoteVerb::Watch, target, now)?;
        Ok(self.info.head.clone())
    }

    /// The shared transport supplies an already scope-bound decoded cursor. Every
    /// page rechecks durable authority on this pin before selecting any row/count.
    pub fn remote_changes(
        &mut self,
        grant_id: &RemoteGrantId,
        revision: Revision,
        target: &RemoteTarget,
        request: ChangeRequest<'_>,
        now: i64,
    ) -> StoreResult<ChangePage> {
        self.remote_target(grant_id, revision, RemoteVerb::Watch, target, now)?;
        self.client_changes(target, request)
    }

    /// The local consumer uses the same indexed records and bounds, after its
    /// native human/project authority is checked on this very snapshot.
    pub fn local_client_changes(
        &mut self,
        admission: &crate::Admission,
        target: &RemoteTarget,
        request: ChangeRequest<'_>,
    ) -> StoreResult<ChangePage> {
        self.local_client_target(admission, target)?;
        self.client_changes(target, request)
    }

    pub fn local_client_position(
        &self,
        admission: &crate::Admission,
        target: &RemoteTarget,
    ) -> StoreResult<Option<StorePosition>> {
        self.local_client_target(admission, target)?;
        Ok(self.info.head.clone())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    fn client_changes(
        &mut self,
        target: &RemoteTarget,
        request: ChangeRequest<'_>,
    ) -> StoreResult<ChangePage> {
        let ChangeRequest {
            after,
            limit,
            budget,
        } = request;
        if !(1..=100).contains(&limit) || !(1024..=65536).contains(&budget) {
            return Err(invalid("remote replay budget"));
        }
        if after.is_some_and(|p| !p.belongs(&self.info)) {
            return Err(fail(
                StoreErrorCode::CursorStale,
                "remote replay requires the original store incarnation",
            ));
        }
        let after_seq = after.map(StorePosition::sequence).unwrap_or(0);
        let high = self
            .info
            .head
            .as_ref()
            .map(StorePosition::sequence)
            .unwrap_or(0);
        if after_seq > high {
            return Err(fail(
                StoreErrorCode::CursorStale,
                "remote replay cursor exceeds this snapshot",
            ));
        }
        let p = crate::identity::key(&self.db, "project", target.project.as_str(), &[0], false)?;
        let mut namespace = vec![1];
        namespace.extend_from_slice(&p);
        let a = crate::identity::key(&self.db, "agent", target.agent.as_str(), &namespace, false)?;
        let deadline = Instant::now() + Duration::from_millis(250);
        self.db
            .progress_handler(1000, Some(move || Instant::now() >= deadline))
            .map_err(sql)?;
        let result = (|| {
            // Each branch has a target/position index; no full-floor post-filtering.
            // Shared work marks expose only this exact recipient, never another addressee.
            let mut q=self.db.prepare("WITH selected(seq) AS (
                SELECT seq FROM events INDEXED BY events_actor_seq WHERE project_id=?1 AND actor_id=?2 AND seq>?3 AND kind IN ('session.turn','message.sent','message.delivered','message.read','message.dismissed')
                UNION SELECT event_seq FROM session_data INDEXED BY session_data_agent_seq WHERE agent_id=?2 AND event_seq>?3
                UNION SELECT event_seq FROM process_data INDEXED BY process_data_principal WHERE principal_id=?2 AND event_seq>?3
                UNION SELECT sent_seq FROM message_deliveries INDEXED BY mail_recipient_seq WHERE project_id=?1 AND recipient_id=?2 AND sent_seq>?3
                UNION SELECT sent_seq FROM message_deliveries INDEXED BY mail_sender_seq WHERE project_id=?1 AND sender_id=?2 AND sent_seq>?3
                UNION SELECT d.event_seq FROM messages m INDEXED BY messages_sender_seq JOIN mark_data d INDEXED BY mark_data_message_seq ON d.message_seq=m.sent_seq WHERE m.project_id=?1 AND m.sender_id=?2 AND d.event_seq>?3
                UNION SELECT d.event_seq FROM messages m INDEXED BY messages_recipient_seq JOIN mark_data d INDEXED BY mark_data_message_seq ON d.message_seq=m.sent_seq WHERE m.project_id=?1 AND m.recipient_id=?2 AND d.event_seq>?3
                UNION SELECT event_seq FROM work_mark_data INDEXED BY work_mark_recipient_seq WHERE recipient_id=?2 AND event_seq>?3
            ) SELECT e.seq FROM selected s JOIN events e ON e.seq=s.seq LEFT JOIN turn_data t ON t.event_seq=e.seq WHERE e.project_id=?1 AND (t.role IS NULL OR t.role!='system') ORDER BY e.seq LIMIT ?4").map_err(sql)?;
            let seqs = q
                .query_map(
                    rusqlite::params![
                        p,
                        a,
                        i64::try_from(after_seq).map_err(invalid)?,
                        i64::from(limit) + 1
                    ],
                    |r| r.get::<_, i64>(0),
                )
                .map_err(sql)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql)?;
            let mut changes = Vec::new();
            let mut cost = 0usize;
            let mut through = after.cloned();
            let mut more = seqs.len() > usize::from(limit);
            for seq in seqs.into_iter().take(usize::from(limit)) {
                if Instant::now() >= deadline {
                    return Err(fail(
                        StoreErrorCode::ReadIncomplete,
                        "remote replay deadline exhausted; retain the original cursor",
                    ));
                }
                let event = crate::read::load_event(&self.db, seq, &self.info)?;
                let kind = convert(event.body)?;
                let bytes = match &kind {
                    ChangeKind::Durable(event) => {
                        serde_json::to_vec(event).map_err(invalid)?.len() + 256
                    }
                    _ => 512,
                };
                if cost + bytes > budget as usize {
                    if changes.is_empty() {
                        let mut error = fail(
                            StoreErrorCode::ReadBudgetTooSmall,
                            format!(
                                "next authorized replay item needs {bytes} bytes; requested budget is {budget}"
                            ),
                        );
                        error.remedy.text = format!(
                            "Retry the same authorized cursor with a budget of at least {bytes} bytes (up to 65536); do not advance or discard it."
                        );
                        return Err(error);
                    }
                    more = true;
                    break;
                }
                cost += bytes;
                let position = StorePosition::new_internal(
                    self.info.id.clone(),
                    self.info.incarnation,
                    u64::try_from(seq).map_err(invalid)?,
                )?;
                through = Some(position.clone());
                changes.push(Change { position, kind });
            }
            if !more {
                through = self.info.head.clone()
            }
            Ok(ChangePage {
                changes,
                through,
                more,
            })
        })().map_err(|mut error: Box<StoreError>| {
            let sqlite_code = match &error.detail {
                StoreDetail::Sqlite { extended_code, .. } => Some(*extended_code),
                StoreDetail::Io { sqlite_extended_code, .. } => *sqlite_extended_code,
                _ => None,
            };
            if sqlite_code.is_some_and(|code| code & 0xff == rusqlite::ffi::SQLITE_INTERRUPT) {
                error.code = StoreErrorCode::ReadIncomplete;
                error.cause = "remote replay read budget exhausted; retain the original scoped cursor".into();
                error.remedy.text = "Retry the same read with its original cursor; no store repair or initialization is needed.".into();
                error.retry = se_types::Retry::AfterReread;
            }
            error
        });
        let reset = self
            .db
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(sql);
        match (result, reset) {
            (result, Ok(())) => result,
            (Ok(_), Err(error)) => Err(error),
            (Err(mut original), Err(reset)) => {
                original
                    .cause
                    .push_str(&format!("; resetting replay deadline failed: {reset}"));
                Err(original)
            }
        }
    }
}
fn convert(body: EventBody<StoredText>) -> StoreResult<ChangeKind> {
    use ChangeKind::*;
    Ok(match body {
        EventBody::MessageSent { message, .. } | EventBody::WorkMessageSent { message, .. } => {
            Durable(RemoteDurableEvent::Message {
                message,
                delivery: RemoteDeliveryState::Pending,
            })
        }
        EventBody::MessageDelivered { message, .. } => Durable(RemoteDurableEvent::Message {
            message,
            delivery: RemoteDeliveryState::Delivered,
        }),
        EventBody::MessageRead { message, .. } => Durable(RemoteDurableEvent::Message {
            message,
            delivery: RemoteDeliveryState::Read,
        }),
        EventBody::MessageDismissed { message, .. } => Durable(RemoteDurableEvent::Message {
            message,
            delivery: RemoteDeliveryState::Unknown,
        }),
        EventBody::SessionTurn {
            vendor_ref,
            role,
            text,
            ..
        } => {
            let StoredText::Present(text) = text else {
                return Ok(Unavailable {
                    reason:
                        "authorized turn text was erased; reset or reconcile the scoped history"
                            .into(),
                });
            };
            let role = match role {
                Role::User => RemoteTurnRole::User,
                Role::Assistant => RemoteTurnRole::Assistant,
                Role::Tool => RemoteTurnRole::Tool,
                _ => return Err(invalid("unsupported remote turn role")),
            };
            let mut end = text.len().min(512);
            while !text.is_char_boundary(end) {
                end -= 1
            }
            let omitted = text.len() - end;
            Durable(RemoteDurableEvent::Turn {
                item_id: vendor_ref,
                role,
                preview: RemotePreview {
                    text: text[..end].to_owned(),
                    complete: omitted == 0,
                    omitted_utf8_bytes: if omitted == 0 {
                        se_types::Omission::None
                    } else {
                        se_types::Omission::Known {
                            count: std::num::NonZeroU64::new(omitted as u64)
                                .ok_or_else(|| invalid("preview omission is zero"))?,
                            reason: se_types::OmissionReason::Budget,
                        }
                    },
                },
            })
        }
        EventBody::SessionPrepared { .. }
        | EventBody::SessionActivated { .. }
        | EventBody::SessionEnded { .. }
        | EventBody::SessionRevoked { .. }
        | EventBody::ProcessRegistered { .. }
        | EventBody::ProcessTransition { .. } => ObserveStatus,
        _ => return Err(invalid("remote replay escaped its closed event kinds")),
    })
}
