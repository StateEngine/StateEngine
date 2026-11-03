use super::*;
pub(super) fn decode<R: Snapshot>(
    cx: &NodeContext,
    read: &mut R,
    row: &Value,
) -> StoreResult<DecodedRow> {
    if row.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err(invalid("unsupported Node working-state version"));
    }
    let author = row
        .get("author")
        .ok_or_else(|| invalid("Node working state needs explicit author correspondence"))?;
    let actor_row = json!({"actor_type":author.get("type"),"actor_id":author.get("id")});
    let by = actor(read, &actor_row)?;
    let ts = time::micros(str_at(row, "updated_at")?)?;
    let text = text_at(row, "text")?;
    let key = format!(
        "working:{}:{}",
        str_at(author, "id")?,
        str_at(row, "updated_at")?
    );
    let duplicate = seen(read, cx, event_id(&cx.admission.scope, &key)?)?;
    let mut result = DecodedRow {
        events: Vec::new(),
        family: ImportFamily::WorkingState,
        legacy_id: key.clone(),
        target: LegacyTarget::Record(record_id("working", &key)?),
        retained: None,
        resume: Vec::new(),
        duplicate,
        dropped_by_policy: false,
        dispositions: None,
    };
    if duplicate {
        return Ok(result);
    }
    let Actor::Agent(agent) = &by else {
        result.retained =
            Some(json!({"text":text,"author":author,"updated_at":row.get("updated_at")}));
        return Ok(result);
    };
    require(read.principal(by.clone())?)?;
    let current = read.working_state(agent.clone())?;
    if let Read::Present { value } = &current
        && (value.current.header.door != Door::Import || value.current.header.occurred_at_us > ts)
    {
        result.retained = Some(
            json!({"text":text,"author":author,"updated_at":row.get("updated_at"),"disposition":"kept-newer-working-state"}),
        );
        return Ok(result);
    }
    result.events.push(event(
        cx,
        by.clone(),
        &key,
        ts,
        None,
        EventBody::WorkingStateSet {
            agent: agent.clone(),
            text: InputText::Inline(text.into()),
            expected: expected(current)?,
        },
    )?);
    result.target = LegacyTarget::Principal(by);
    Ok(result)
}
