//! Finite pending native inputs. The cache advances only at a source cursor
//! returned to the writer; a failed commit rebuilds rather than losing input.
use super::*;
use se_core::ops::{
    queued_input::{Delivery, Outcome, QueuedInput},
    transcript::{Position, Record},
};
use serde_json::Value;
#[derive(Clone, Default)]
pub(in crate::runtime::capture) struct Tracker {
    pending: Vec<Prompt>,
    bytes: usize,
}
#[derive(Clone)]
struct Prompt {
    text: std::sync::Arc<str>,
    operation: Outcome,
    matched: bool,
    position: Position,
}
impl Tracker {
    pub(super) fn observe(&mut self, bytes: &[u8], position: Position) -> Result<Vec<Record>> {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|_| SeError::invalid("queue provenance", "a complete native JSON record"))?;
        let kind = value.get("type").and_then(Value::as_str);
        let mut outcomes = Vec::new();
        if kind == Some("queue-operation") {
            match value.get("operation").and_then(Value::as_str) {
                Some("enqueue") => {
                    let text = value
                        .get("content")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            SeError::invalid("queued input", "the native enqueue string")
                        })?;
                    if text.is_empty() {
                        return Err(SeError::invalid("queued input", "nonempty native input"));
                    }
                    while self.pending.len() >= 4096
                        || text.len() > (16 * 1024 * 1024usize).saturating_sub(self.bytes)
                    {
                        let completed = self.pending.iter().position(|prompt| {
                            prompt.operation != Outcome::Unresolved && prompt.matched
                        });
                        let Some(completed) = completed else {
                            return Err(SeError::invalid(
                                "pending queued input",
                                "at most 4096 unresolved inputs and 16 MiB; preserve the source cursor and resolve pending input",
                            ));
                        };
                        // Only finite correlation history is discarded. Enqueue,
                        // native outcome and user delivery are already durable.
                        let retired = self.pending.remove(completed);
                        self.bytes -= retired.text.len();
                    }
                    self.bytes += text.len();
                    self.pending.push(Prompt {
                        text: text.into(),
                        operation: Outcome::Unresolved,
                        matched: false,
                        position: position.clone(),
                    });
                    let mut record = Record::new("queue-operation", Some("enqueue"));
                    record.position = position.clone();
                    record.queued_input = Some(QueuedInput {
                        enqueue: Some(position),
                        outcome: Outcome::Unresolved,
                        reason: None,
                        delivery: Delivery::Unresolved,
                        outcome_position: None,
                        text: Some(text.into()),
                    });
                    outcomes.push(record);
                }
                Some("dequeue") => {
                    if let Some(index) = self
                        .pending
                        .iter()
                        .position(|p| p.operation == Outcome::Unresolved)
                    {
                        outcomes.push(self.resolve(index, Outcome::Dequeued, None, &position));
                    }
                }
                Some("remove") => {
                    let text = value
                        .get("content")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            SeError::invalid("native queue remove", "the native input string")
                        })?;
                    let reason = match value.get("reason") {
                        None | Some(Value::Null) => None,
                        Some(Value::String(reason))
                            if reason.len() <= 4096 && !reason.contains('\0') =>
                        {
                            Some(reason.clone())
                        }
                        _ => {
                            return Err(SeError::invalid(
                                "native queue reason",
                                "a bounded native reason string",
                            ));
                        }
                    };
                    let index = self
                        .pending
                        .iter()
                        .position(|p| p.text.as_ref() == text && p.operation == Outcome::Unresolved)
                        .or_else(|| self.pending.iter().rposition(|p| p.text.as_ref() == text));
                    if let Some(index) = index {
                        outcomes.push(self.resolve(index, Outcome::Removed, reason, &position));
                    } else {
                        // Native logs can start after enqueue or remove transformed text.
                        // Retain the operation without inventing an enqueue relationship.
                        let mut record = Record::new("queue-operation", Some("remove"));
                        record.position = position.clone();
                        let delivery = if matches!(
                            reason.as_deref(),
                            Some("absorbed_mid_turn" | "delivered_to_agent")
                        ) {
                            Delivery::NativeReason
                        } else {
                            Delivery::Unresolved
                        };
                        record.queued_input = Some(QueuedInput {
                            enqueue: None,
                            outcome: Outcome::Removed,
                            reason,
                            delivery,
                            outcome_position: Some(position.clone()),
                            text: Some(text.into()),
                        });
                        outcomes.push(record);
                    }
                }
                _ => (),
            }
        } else if kind == Some("user")
            && value.get("isSidechain").and_then(Value::as_bool) != Some(true)
        {
            let content = value.pointer("/message/content");
            let text = match content {
                Some(Value::String(text)) => text.clone(),
                Some(Value::Array(parts)) => parts
                    .iter()
                    .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                    .filter_map(|b| b.get("text").and_then(Value::as_str))
                    .collect::<String>(),
                _ => String::new(),
            };
            // A native prompt may contain several queued inputs and provider
            // wrappers. Require exact contained bytes; fuzzy matches grant no delivery.
            let mut index = 0;
            while index < self.pending.len() {
                if !self.pending[index].matched && text.contains(self.pending[index].text.as_ref())
                {
                    outcomes.push(self.resolve(index, Outcome::Delivered, None, &position));
                }
                index += 1;
            }
        }
        if outcomes.len() > 32 {
            return Err(SeError::invalid(
                "queue outcomes",
                "at most 32 exact outcomes per native record",
            ));
        }
        Ok(outcomes)
    }
    fn resolve(
        &mut self,
        index: usize,
        outcome: Outcome,
        reason: Option<String>,
        position: &Position,
    ) -> Record {
        let prompt = &mut self.pending[index];
        if outcome == Outcome::Delivered {
            prompt.matched = true;
        } else {
            prompt.operation = outcome;
        }
        let mut record = Record::new(
            "queue-operation",
            Some(match outcome {
                Outcome::Removed => "remove",
                Outcome::Dequeued => "dequeue",
                _ => "delivered",
            }),
        );
        record.position = position.clone();
        let delivery = if outcome == Outcome::Delivered {
            Delivery::UserRecord
        } else if matches!(
            reason.as_deref(),
            Some("absorbed_mid_turn" | "delivered_to_agent")
        ) {
            Delivery::NativeReason
        } else {
            Delivery::Unresolved
        };
        record.queued_input = Some(QueuedInput {
            enqueue: Some(prompt.position.clone()),
            outcome,
            reason,
            delivery,
            outcome_position: Some(position.clone()),
            text: None,
        });
        record
    }
}
pub(super) fn restore(
    source: &mut BoundTranscript,
    offset: u64,
    deadline: &Deadline,
) -> Result<Tracker> {
    if let Some((_, state)) = source.queue.iter().find(|(at, _)| *at == offset) {
        return Ok(state.clone());
    }
    let mut state = Tracker::default();
    let mut position = 0;
    let mut start = 0;
    let mut line = Vec::new();
    while position < offset {
        deadline.remaining()?;
        let chunk = source
            .pin
            .read_at(position, (offset - position).min(CHUNK as u64) as usize)
            .map_err(native_error)?;
        if chunk.bytes.is_empty() {
            return Err(SeError::invalid(
                "queue recovery",
                "the original complete captured prefix",
            ));
        }
        for byte in chunk.bytes {
            line.push(byte);
            if line.len() > LINE {
                return Err(SeError::too_large("queue recovery line", LINE, line.len()));
            }
            position += 1;
            if byte == b'\n' {
                state.observe(
                    &line,
                    Position {
                        offset: start,
                        length: position - start,
                    },
                )?;
                start = position;
                line.clear();
            }
        }
    }
    if !line.is_empty() {
        return Err(SeError::invalid(
            "queue recovery",
            "a complete native prefix",
        ));
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn queue_operations_do_not_infer_cancellation_or_replace_user_delivery()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut tracker = Tracker::default();
        let enqueue = tracker.observe(
            &serde_json::to_vec(
                &json!({"type":"queue-operation","operation":"enqueue","content":"queued text"}),
            )?,
            Position {
                offset: 0,
                length: 10,
            },
        )?;
        let saved = enqueue[0]
            .queued_input
            .as_ref()
            .ok_or("enqueue provenance absent")?;
        assert_eq!(saved.text.as_deref(), Some("queued text"));
        assert_eq!(saved.delivery, Delivery::Unresolved);
        let removed=tracker.observe(&serde_json::to_vec(&json!({"type":"queue-operation","operation":"remove","content":"queued text","reason":"absorbed_mid_turn"}))?,Position{offset:10,length:10})?;
        let operation = removed[0]
            .queued_input
            .as_ref()
            .ok_or("remove link absent")?;
        assert_eq!(operation.enqueue, saved.enqueue);
        assert_eq!(operation.outcome, Outcome::Removed);
        assert_eq!(operation.reason.as_deref(), Some("absorbed_mid_turn"));
        assert_eq!(operation.delivery, Delivery::NativeReason);
        let delivered = tracker.observe(
            &serde_json::to_vec(
                &json!({"type":"user","message":{"content":"wrapper queued text wrapper"}}),
            )?,
            Position {
                offset: 20,
                length: 10,
            },
        )?;
        let delivery = delivered[0]
            .queued_input
            .as_ref()
            .ok_or("user delivery link absent")?;
        assert_eq!(delivery.enqueue, saved.enqueue);
        assert_eq!(delivery.delivery, Delivery::UserRecord);
        assert_eq!(delivery.outcome, Outcome::Delivered);
        assert!(
            tracker
                .observe(
                    &serde_json::to_vec(
                        &json!({"type":"user","message":{"content":"quoted queued text"}})
                    )?,
                    Position {
                        offset: 30,
                        length: 10
                    }
                )?
                .is_empty()
        );
        let orphan = tracker.observe(&serde_json::to_vec(&json!({"type":"queue-operation","operation":"remove","content":"not enqueued here","reason":"absorbed_mid_turn"}))?, Position{offset:40,length:10})?;
        let orphan = orphan[0]
            .queued_input
            .as_ref()
            .ok_or("orphan remove lost")?;
        assert!(orphan.enqueue.is_none());
        assert_eq!(orphan.text.as_deref(), Some("not enqueued here"));
        orphan.validate()?;
        let repeated = tracker.observe(&serde_json::to_vec(&json!({"type":"queue-operation","operation":"remove","content":"queued text","reason":"absorbed_mid_turn"}))?, Position{offset:50,length:10})?;
        assert_eq!(repeated.len(), 1);
        Ok(())
    }
    #[test]
    fn completed_history_releases_both_entry_and_text_capacity()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        for padding in [String::new(), "x".repeat(se_types::Body::MAX_BYTES / 2)] {
            let mut tracker = Tracker::default();
            let count = if padding.is_empty() {
                4100
            } else {
                16 * 1024 * 1024 / padding.len() + 10
            };
            let mut offset = 0;
            for i in 0..count {
                let text = format!("queued-{i}:{padding}");
                for value in [
                    json!({"type":"queue-operation","operation":"enqueue","content":text}),
                    json!({"type":"queue-operation","operation":"dequeue"}),
                    json!({"type":"user","message":{"content":text}}),
                ] {
                    let rows = tracker
                        .observe(&serde_json::to_vec(&value)?, Position { offset, length: 1 })?;
                    assert_eq!(rows.len(), 1);
                    rows[0]
                        .queued_input
                        .as_ref()
                        .ok_or("provenance absent")?
                        .validate()?;
                    offset += 1;
                }
            }
            assert!(tracker.pending.len() <= 4096);
            assert!(tracker.bytes <= 16 * 1024 * 1024);
            assert!(
                tracker
                    .pending
                    .iter()
                    .all(|p| p.matched && p.operation == Outcome::Dequeued)
            );
        }
        Ok(())
    }
}
