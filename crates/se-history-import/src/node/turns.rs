//! Historical user/assistant exchanges retain their provider-native reference.
use super::*;
struct CaptureCursor {
    source: RecordId,
    old_offset: u64,
    expected: Expected,
}
struct TurnContext<'a> {
    cx: &'a NodeContext,
    by: Actor,
    session: SessionId,
    agent: AgentId,
    provider: Provider,
    native_session: &'a str,
    ts: i64,
}
fn read_present<T>(read: Read<T>) -> StoreResult<Option<T>> {
    match read {
        Read::Present { value } => Ok(Some(value)),
        Read::Absent { .. } => Ok(None),
        Read::Unreadable { reason, .. } => Err(fail(StoreErrorCode::Unreadable, reason)),
        Read::Unknown { what } => Err(fail(StoreErrorCode::Unreadable, what)),
    }
}
fn record_retained_field(
    retained: &mut Option<Value>,
    turn_id: &str,
    field: &str,
    value: Value,
) -> StoreResult<()> {
    let fields = retained
        .get_or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| invalid("retained turn metadata is not an object"))?;
    fields.insert(field.into(), value);
    fields.insert("turn_id".into(), Value::String(turn_id.into()));
    Ok(())
}
impl TurnContext<'_> {
    fn ensure_session<R: Snapshot>(
        &self,
        read: &mut R,
        reference: Option<&str>,
        events: &mut Vec<NewEvent>,
    ) -> StoreResult<()> {
        if let Some(value) = read_present(read.session(self.session.clone())?)? {
            let original = value.original.as_deref().unwrap_or(&value.current);
            if !matches!(&original.body, EventBody::SessionPrepared { agent: a, provider: p, native_ref, .. } if a == &self.agent && *p == self.provider && native_ref == reference.unwrap_or(""))
                || original.header.door != Door::Import
            {
                return Err(fail(
                    StoreErrorCode::NaturalKeyConflict,
                    "conversation identity belongs to another source/provider/agent",
                ));
            }
            return Ok(());
        }
        events.push(event(
            self.cx,
            self.by.clone(),
            &format!("conversation:{}", self.native_session),
            self.ts,
            Some(self.session.clone()),
            EventBody::SessionPrepared {
                session: self.session.clone(),
                agent: self.agent.clone(),
                provider: self.provider,
                native_ref: reference.unwrap_or_default().into(),
                surface: None,
                consent: Consent::Capture,
                generation: self.cx.admission.generation,
                expected: Expected::Absent,
            },
        )?);
        events.push(event(
            self.cx,
            self.by.clone(),
            &format!("conversation:{}:ended", self.native_session),
            self.ts,
            Some(self.session.clone()),
            EventBody::SessionEnded {
                session: self.session.clone(),
                expected: Expected::Revision(source_revision(1)?),
                reason: InputText::Inline(
                    "Imported historical conversation; no process or credential adopted".into(),
                ),
                final_turn: None,
                final_cursor: None,
            },
        )?);
        Ok(())
    }
    fn ensure_capture_source<R: Snapshot>(
        &self,
        read: &mut R,
        events: &mut Vec<NewEvent>,
    ) -> StoreResult<CaptureCursor> {
        let source = record_id(
            "capture-source",
            &format!(
                "{}:{}",
                self.native_session,
                se_types::hex_lower(&self.cx.source.incarnation)
            ),
        )?;
        let (old_offset, expected) =
            if let Some(value) = read_present(read.capture_source(source)?)? {
                let old = match value.current.body {
                    EventBody::CaptureProgress { new_offset, .. } => new_offset,
                    EventBody::CaptureSource { .. } => 0,
                    _ => return Err(invalid("capture checkpoint kind")),
                };
                (old, Expected::Revision(value.revision))
            } else {
                events.push(event(
                    self.cx,
                    self.by.clone(),
                    &format!("capture:{source:?}"),
                    self.ts,
                    Some(self.session.clone()),
                    EventBody::CaptureSource {
                        source,
                        session: self.session.clone(),
                        consent: Consent::Capture,
                        native_ref: self.native_session.into(),
                        incarnation: self.cx.source.incarnation.clone(),
                        expected: Expected::Absent,
                    },
                )?);
                (0, Expected::Revision(source_revision(1)?))
            };
        Ok(CaptureCursor {
            source,
            old_offset,
            expected,
        })
    }
    fn decode_exchange<R: Snapshot>(
        self,
        read: &mut R,
        row: &Value,
        key: &str,
        turn_id: &str,
        cursor: CaptureCursor,
        result: &mut DecodedRow,
    ) -> StoreResult<()> {
        let (mut last_turn, mut had_text) = (None, false);
        for (name, role) in [("user", Role::User), ("assistant", Role::Assistant)] {
            let part = row
                .get(name)
                .ok_or_else(|| invalid("Node exchange is missing its recorded role"))?;
            let text = part
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Node turn content is not text"))?;
            if name == "assistant"
                && let Some(reasoning) = part
                    .get("reasoning_content")
                    .filter(|v| v.as_str().is_some_and(|s| !s.is_empty()))
            {
                record_retained_field(
                    &mut result.retained,
                    turn_id,
                    "reasoning_content",
                    reasoning.clone(),
                )?;
            }
            if text.is_empty() {
                continue;
            }
            had_text = true;
            let turn_key = format!("{key}:{name}");
            if seen(
                read,
                self.cx,
                event_id(&self.cx.admission.scope, &turn_key)?,
            )? {
                continue;
            }
            let turn = record_id("turn", &turn_key)?;
            result.events.push(event(
                self.cx,
                self.by.clone(),
                &turn_key,
                self.ts,
                Some(self.session.clone()),
                EventBody::SessionTurn {
                    turn,
                    agent: self.agent.clone(),
                    session: self.session.clone(),
                    provider: self.provider,
                    vendor_ref: turn_key.clone(),
                    role,
                    text: InputText::Inline(text.into()),
                    evidence: self.cx.source.clone(),
                },
            )?);
            last_turn = Some(turn);
        }
        if let Some(last_turn) = last_turn {
            result.events.push(event(
                self.cx,
                self.by,
                &format!("{key}:progress"),
                self.ts,
                Some(self.session),
                EventBody::CaptureProgress {
                    source: cursor.source,
                    expected: cursor.expected,
                    incarnation: self.cx.source.incarnation.clone(),
                    old_offset: cursor.old_offset,
                    new_offset: self
                        .cx
                        .source
                        .offset
                        .checked_add(self.cx.source.length)
                        .ok_or_else(|| invalid("source range overflow"))?,
                    last_turn,
                    replay_evidence: None,
                },
            )?);
        } else if had_text {
            result.events.clear();
            result.duplicate = true;
        } else {
            record_retained_field(
                &mut result.retained,
                turn_id,
                "empty_exchange",
                Value::Bool(true),
            )?;
        }
        Ok(())
    }
}
pub(super) fn decode<R: Snapshot>(
    cx: &NodeContext,
    read: &mut R,
    row: &Value,
) -> StoreResult<DecodedRow> {
    if row.get("schema_version").and_then(Value::as_u64) != Some(3) {
        return Err(invalid("unsupported Node conversation version"));
    }
    let source_project =
        se_types::ProjectId::from_legacy(str_at(row, "project_id")?).map_err(invalid)?;
    if cx.admission.scope != Scope::Project(source_project) {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "Node conversation explicitly belongs to another project",
        ));
    }
    if row.get("attribution").and_then(Value::as_str) == Some("unattributed") {
        return Err(invalid(
            "unattributed source text cannot be assigned to an imported agent",
        ));
    }
    let agent = agent(read, str_at(row, "agent_id")?)?;
    require(read.principal(Actor::Agent(agent.clone()))?)?;
    let native_session = str_at(row, "session_id")?;
    let session = SessionId::from_legacy(native_session).map_err(invalid)?;
    let provider = match str_at(row, "source_cli")? {
        "claude" | "claude-code" => Provider::Claude,
        "codex" => Provider::Codex,
        _ => return Err(invalid("unsupported recorded conversation provider")),
    };
    let raw_ref = row
        .get("session")
        .and_then(|v| v.get("session_id"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let supported = raw_ref.is_some_and(|r| {
        uuid::Uuid::parse_str(r).is_ok_and(|id| {
            id.to_string() == r
                && matches!(
                    id.get_version(),
                    Some(uuid::Version::Random | uuid::Version::SortRand)
                )
        })
    });
    let unsupported = raw_ref.is_some() && !supported;
    let reference = raw_ref.filter(|_| supported).map(str::to_owned);
    let turn_id = str_at(row, "turn_id")?;
    let key = format!("turn:{native_session}:{turn_id}");
    let ts = time::micros(str_at(row, "ts")?)?;
    let mut result = registration::result(
        ImportFamily::Turns,
        key.clone(),
        LegacyTarget::Session(session.clone()),
    );
    result.retained = unsupported.then(|| json!({"native_reference_state":"unsupported","native_reference_bytes":raw_ref.map(str::len),"native_reference_sha256":raw_ref.map(|r|se_types::hex_lower(&Sha256::digest(r.as_bytes())))}));
    result.resume.push(ResumeFact {
        session: session.clone(),
        agent: agent.clone(),
        provider,
        native_reference: reference.clone(),
        unsupported,
    });
    let turn_cx = TurnContext {
        cx,
        by: Actor::Agent(agent.clone()),
        session,
        agent,
        provider,
        native_session,
        ts,
    };
    turn_cx.ensure_session(read, reference.as_deref(), &mut result.events)?;
    let cursor = turn_cx.ensure_capture_source(read, &mut result.events)?;
    turn_cx.decode_exchange(read, row, &key, turn_id, cursor, &mut result)?;
    Ok(result)
}
