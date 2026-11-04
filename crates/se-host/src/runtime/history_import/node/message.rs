use super::*;
mod reference;
use reference::MessageReference;
pub(super) fn decode<R: ImportSnapshot>(
    cx: &NodeContext,
    read: &mut R,
    row: &Value,
) -> StoreResult<DecodedRow> {
    let kind = str_at(row, "record_type")?;
    let id = MessageId::from_legacy(str_at(row, "msg_id")?).map_err(invalid)?;
    let ts = time::micros(str_at(row, "ts")?)?;
    if matches!(
        kind,
        "delivered" | "bell-outcome" | "delivery-retry" | "bell-output-handoff"
    ) {
        // Notification/transport bookkeeping cannot become accepted input or a
        // recipient read. Runtime retry custody stays outside user history.
        let retry = matches!(kind, "delivery-retry" | "bell-output-handoff");
        let key = format!(
            "bell:{kind}:{id}:{}:{}:{}",
            str_at(row, "seat")?,
            str_at(row, "ts")?,
            optional(row, "attempt_id").unwrap_or_default()
        );
        return Ok(DecodedRow {
            events: Vec::new(),
            family: ImportFamily::Messages,
            legacy_id: key,
            target: LegacyTarget::Message(id),
            retained: Some(if retry {
                json!({"excluded_source_kind":kind,"policy":"transport retry custody is not imported"})
            } else {
                json!({"record_type":kind,"meaning":"bell-only","seat":str_at(row,"seat")?,"ts":str_at(row,"ts")?,"bell":optional(row,"bell"),"state":optional(row,"state")})
            }),
            resume: Vec::new(),
            duplicate: false,
            dropped_by_policy: retry,
            dispositions: None,
        });
    }
    if kind == "message" {
        text_at(row, "body")?;
        let sender = str_at(row, "from_seat")?;
        let retained_sender = if sender == "floor" {
            true
        } else {
            match seat(cx, read, sender) {
                Ok(actor) => match read.principal(actor.clone())? {
                    Read::Present { .. } => false,
                    Read::Absent { .. } => {
                        matches!(actor, Actor::Human(_)) && !cx.prerequisites_pending
                    }
                    Read::Unreadable { reason, .. } => {
                        return Err(fail(StoreErrorCode::Unreadable, reason));
                    }
                    Read::Unknown { what } => return Err(fail(StoreErrorCode::Unreadable, what)),
                },
                Err(error) if error.code == StoreErrorCode::ReferenceMissing => false,
                Err(error) => return Err(error),
            }
        };
        if str_at(row, "to_seat")? == "floor" || retained_sender {
            return retained(
                row,
                id.clone(),
                format!("message:{id}"),
                "message retained with its recorded sender/audience; no native sender or recipient acceptance inferred",
            );
        }
    }
    if matches!(kind, "read-marker" | "dismiss")
        && matches!(
            reference::lookup(cx, read, &id)?,
            MessageReference::Retained(_)
        )
    {
        return retained(
            row,
            id.clone(),
            format!(
                "{kind}:{id}:{}:{}",
                str_at(row, "seat")?,
                str_at(row, "ts")?
            ),
            "source marker for retained mail; no native recipient fact inferred",
        );
    }
    let mut retained_fields = None;
    let (by, key, body) = match kind {
        "message" => {
            if row.get("from_project").is_some_and(|v|!v.is_null() && !matches!(&cx.admission.scope,Scope::Project(p) if v.as_str()==Some(p.as_str()))) {
                return Err(invalid(
                    "cross-project Node mail needs explicit source correspondence",
                ));
            }
            let by = seat(cx, read, str_at(row, "from_seat")?)?;
            let to = seat(cx, read, str_at(row, "to_seat")?)?;
            require(read.principal(by.clone())?)?;
            require(read.principal(to.clone())?)?;
            let refs = row
                .get("refs")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("Node message refs must be an array"))?
                .iter()
                .map(|value| {
                    let text = value
                        .as_str()
                        .ok_or_else(|| invalid("Node message ref must be an ID"))?;
                    if let Ok(id) = MessageId::from_legacy(text) {
                        return reference::lookup(cx, read, &id).map(|value| value.event());
                    }
                    if let Ok(id) = DecisionId::from_legacy(text) {
                        let record = require(read.decision(id)?)?;
                        return Ok(record
                            .original
                            .as_deref()
                            .unwrap_or(&record.current)
                            .header
                            .event
                            .clone());
                    }
                    Err(fail(
                        StoreErrorCode::ReferenceMissing,
                        "Node reference has no supported source correspondence yet",
                    ))
                })
                .collect::<StoreResult<Vec<_>>>()?;
            let original_kind = str_at(row, "kind")?;
            let native_kind = if matches!(
                original_kind,
                "note"
                    | "task"
                    | "question"
                    | "answer"
                    | "blocker"
                    | "done"
                    | "handoff"
                    | "finding"
            ) {
                original_kind
            } else {
                retained_fields = Some(json!({"original_kind":original_kind}));
                "note"
            };
            let reply_to = optional(row, "reply_to")
                .map(MessageId::from_legacy)
                .transpose()
                .map_err(invalid)?;
            if let Some(reply) = &reply_to
                && matches!(
                    reference::lookup(cx, read, reply)?,
                    MessageReference::Retained(_)
                )
            {
                return retained(
                    row,
                    id.clone(),
                    format!("message:{id}"),
                    "reply to retained source mail; original attribution and parent preserved without native message identities",
                );
            }
            (
                by,
                format!("message:{id}"),
                EventBody::MessageSent {
                    message: id.clone(),
                    recipient: to,
                    kind: native_kind.into(),
                    quiet: source_quiet(row)?,
                    body: InputText::Inline(text_at(row, "body")?.into()),
                    refs,
                    reply_to,
                },
            )
        }
        "read-marker" | "dismiss" => {
            let by = seat(cx, read, str_at(row, "seat")?)?;
            let key = format!(
                "{kind}:{id}:{}:{}",
                str_at(row, "seat")?,
                str_at(row, "ts")?
            );
            let body = match kind {
                "read-marker" => EventBody::MessageRead {
                    message: id.clone(),
                    recipient: by.clone(),
                },
                "dismiss" => EventBody::MessageDismissed {
                    message: id.clone(),
                    recipient: by.clone(),
                },
                _ => return Err(invalid("unsupported recipient marker")),
            };
            require(read.message(id.clone())?)?;
            (by, key, body)
        }
        _ => {
            return Err(invalid(
                "unsupported Node message record type; it is not a recipient read",
            ));
        }
    };
    let duplicate = seen(read, cx, event_id(&cx.admission.scope, &key)?)?;
    let mut events = if duplicate {
        Vec::new()
    } else {
        vec![event(cx, by.clone(), &key, ts, None, body)?]
    };
    if kind == "message"
        && !duplicate
        && let Some(values) = row.get("supersedes")
    {
        let values = values
            .as_array()
            .filter(|v| v.len() <= 32)
            .ok_or_else(|| invalid("bounded source supersedes list required"))?;
        let mut unique = std::collections::BTreeSet::new();
        for value in values {
            let old = MessageId::from_legacy(
                value
                    .as_str()
                    .ok_or_else(|| invalid("source supersedes ID must be text"))?,
            )
            .map_err(invalid)?;
            if old == id || !unique.insert(old.to_string()) {
                return Err(invalid(
                    "source replacement contains its own ID or repeated references",
                ));
            }
            let prior = match reference::lookup(cx, read, &old)? {
                MessageReference::Native(prior) => prior,
                MessageReference::Retained(_) => {
                    return retained(
                        row,
                        id.clone(),
                        format!("message:{id}"),
                        "replacement of retained source mail; original attribution and links preserved without a native replacement fact",
                    );
                }
            };
            if prior.superseded_by.as_ref() == Some(&id) {
                continue;
            }
            if prior.sender != by {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "source supersedes belongs to another sender",
                ));
            }
            events.push(event(
                cx,
                by.clone(),
                &format!("{key}:supersedes:{old}"),
                ts,
                None,
                EventBody::MessageSuperseded {
                    message: old,
                    replacement: id.clone(),
                    expected: Expected::Revision(prior.revision),
                },
            )?);
        }
    }
    Ok(DecodedRow {
        events,
        family: ImportFamily::Messages,
        legacy_id: key,
        target: LegacyTarget::Message(id),
        retained: retained_fields,
        resume: Vec::new(),
        duplicate,
        dropped_by_policy: false,
        dispositions: None,
    })
}

fn retained(row: &Value, id: MessageId, key: String, meaning: &str) -> StoreResult<DecodedRow> {
    Ok(DecodedRow {
        events: vec![],
        family: ImportFamily::Messages,
        legacy_id: key,
        target: LegacyTarget::Message(id),
        retained: Some(
            json!({"record_type":row.get("record_type"),"to_seat":row.get("to_seat"),"from_seat":row.get("from_seat"),"seat":row.get("seat"),"from_project":row.get("from_project"),"kind":row.get("kind"),"body":row.get("body"),"refs":row.get("refs"),"reply_to":row.get("reply_to"),"supersedes":row.get("supersedes"),"ts":row.get("ts"),"meaning":meaning}),
        ),
        resume: vec![],
        duplicate: false,
        dropped_by_policy: false,
        dispositions: None,
    })
}

// Node stores notification intent in work_wake, not the message body. A legacy
// message without work addressing was quiet and remains so after import.
fn source_quiet(row: &Value) -> StoreResult<bool> {
    let encoded;
    let wake = match row.get("work_wake") {
        None | Some(Value::Null) => match row.get("work_wake_json") {
            None | Some(Value::Null) => return Ok(true),
            Some(Value::String(text)) => {
                encoded = serde_json::from_str::<Value>(text).map_err(invalid)?;
                &encoded
            }
            Some(_) => return Err(invalid("Node work_wake_json must be a JSON string")),
        },
        Some(value) => value,
    };
    if !wake.is_object() {
        return Err(invalid("Node work_wake must be an object"));
    }
    match wake.get("quiet") {
        None => Ok(false),
        Some(Value::Bool(quiet)) => Ok(*quiet),
        Some(_) => Err(invalid("Node work_wake quiet must be a boolean")),
    }
}
