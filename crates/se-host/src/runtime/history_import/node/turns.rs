//! Historical user/assistant exchanges retain their provider-native reference.
use super::*;
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
    let raw_reference = row
        .get("session")
        .and_then(|v| v.get("session_id"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let supported = raw_reference.is_some_and(|reference| {
        uuid::Uuid::parse_str(reference).is_ok_and(|id| {
            id.to_string() == reference
                && matches!(
                    id.get_version(),
                    Some(uuid::Version::Random | uuid::Version::SortRand)
                )
        })
    });
    let unsupported = raw_reference.is_some() && !supported;
    let reference = raw_reference.filter(|_| supported).map(str::to_owned);
    let key = format!("turn:{}:{}", native_session, str_at(row, "turn_id")?);
    let ts = time::micros(str_at(row, "ts")?)?;
    let mut result = DecodedRow {
        events: Vec::new(),
        family: ImportFamily::Turns,
        legacy_id: key.clone(),
        target: LegacyTarget::Session(session.clone()),
        retained: if unsupported {
            Some(
                json!({"native_reference_state":"unsupported","native_reference_bytes":raw_reference.map(str::len),"native_reference_sha256":raw_reference.map(|reference|se_types::hex_lower(&Sha256::digest(reference.as_bytes())))}),
            )
        } else {
            None
        },
        resume: vec![ResumeFact {
            session: session.clone(),
            agent: agent.clone(),
            provider,
            native_reference: reference.clone(),
            unsupported,
        }],
        duplicate: false,
        dropped_by_policy: false,
        dispositions: None,
    };
    let by = Actor::Agent(agent.clone());
    match read.session(session.clone())? {
        Read::Absent { .. } => {
            result.events.push(event(
                cx,
                by.clone(),
                &format!("conversation:{native_session}"),
                ts,
                Some(session.clone()),
                EventBody::SessionPrepared {
                    session: session.clone(),
                    agent: agent.clone(),
                    provider,
                    native_ref: reference.clone().unwrap_or_default(),
                    surface: None,
                    consent: Consent::Capture,
                    generation: cx.admission.generation,
                    expected: Expected::Absent,
                },
            )?);
            result.events.push(event(
                cx,
                by.clone(),
                &format!("conversation:{native_session}:ended"),
                ts,
                Some(session.clone()),
                EventBody::SessionEnded {
                    session: session.clone(),
                    expected: Expected::Revision(Revision {
                        value: std::num::NonZeroU64::new(1).ok_or_else(|| invalid("revision"))?,
                    }),
                    reason: InputText::Inline(
                        "Imported historical conversation; no process or credential adopted".into(),
                    ),
                    final_turn: None,
                    final_cursor: None,
                },
            )?);
        }
        Read::Present { value } => {
            let original = value.original.as_deref().unwrap_or(&value.current);
            if !matches!(&original.body,EventBody::SessionPrepared{agent:a,provider:p,native_ref,..} if a==&agent && p==&provider && native_ref==reference.as_deref().unwrap_or(""))
                || original.header.door != Door::Import
            {
                return Err(fail(
                    StoreErrorCode::NaturalKeyConflict,
                    "conversation identity belongs to another source/provider/agent",
                ));
            }
        }
        Read::Unreadable { reason, .. } => return Err(fail(StoreErrorCode::Unreadable, reason)),
        Read::Unknown { what } => return Err(fail(StoreErrorCode::Unreadable, what)),
    }
    let source = record_id(
        "capture-source",
        &format!(
            "{native_session}:{}",
            se_types::hex_lower(&cx.source.incarnation)
        ),
    )?;
    let current = read.capture_source(source)?;
    let (old, want) = match current {
        Read::Absent { .. } => {
            result.events.push(event(
                cx,
                by.clone(),
                &format!("capture:{source:?}"),
                ts,
                Some(session.clone()),
                EventBody::CaptureSource {
                    source,
                    session: session.clone(),
                    consent: Consent::Capture,
                    native_ref: native_session.into(),
                    incarnation: cx.source.incarnation.clone(),
                    expected: Expected::Absent,
                },
            )?);
            (
                0,
                Expected::Revision(Revision {
                    value: std::num::NonZeroU64::new(1).ok_or_else(|| invalid("revision"))?,
                }),
            )
        }
        Read::Present { value } => {
            let old = match value.current.body {
                EventBody::CaptureProgress { new_offset, .. } => new_offset,
                EventBody::CaptureSource { .. } => 0,
                _ => return Err(invalid("capture checkpoint kind")),
            };
            (old, Expected::Revision(value.revision))
        }
        Read::Unreadable { reason, .. } => return Err(fail(StoreErrorCode::Unreadable, reason)),
        Read::Unknown { what } => return Err(fail(StoreErrorCode::Unreadable, what)),
    };
    let mut last = None;
    let mut had_text = false;
    for (name, role) in [("user", Role::User), ("assistant", Role::Assistant)] {
        let part = row
            .get(name)
            .ok_or_else(|| invalid("Node exchange is missing its recorded role"))?;
        let text = part
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Node turn content is not text"))?;
        if name == "assistant"
            && part
                .get("reasoning_content")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
        {
            let fields = result
                .retained
                .get_or_insert_with(|| json!({}))
                .as_object_mut()
                .ok_or_else(|| invalid("retained turn metadata is not an object"))?;
            fields.insert(
                "reasoning_content".into(),
                part.get("reasoning_content")
                    .cloned()
                    .ok_or_else(|| invalid("recorded reasoning content is absent"))?,
            );
            fields.insert(
                "turn_id".into(),
                Value::String(str_at(row, "turn_id")?.into()),
            );
        }
        if text.is_empty() {
            continue;
        }
        had_text = true;
        let turn_key = format!("{key}:{name}");
        if seen(read, cx, event_id(&cx.admission.scope, &turn_key)?)? {
            continue;
        }
        let turn = record_id("turn", &turn_key)?;
        result.events.push(event(
            cx,
            by.clone(),
            &turn_key,
            ts,
            Some(session.clone()),
            EventBody::SessionTurn {
                turn,
                agent: agent.clone(),
                session: session.clone(),
                provider,
                vendor_ref: turn_key.clone(),
                role,
                text: InputText::Inline(text.into()),
                evidence: cx.source.clone(),
            },
        )?);
        last = Some(turn);
    }
    if let Some(last_turn) = last {
        result.events.push(event(
            cx,
            by,
            &format!("{key}:progress"),
            ts,
            Some(session),
            EventBody::CaptureProgress {
                source,
                expected: want,
                incarnation: cx.source.incarnation.clone(),
                old_offset: old,
                new_offset: cx
                    .source
                    .offset
                    .checked_add(cx.source.length)
                    .ok_or_else(|| invalid("source range overflow"))?,
                last_turn,

                replay_evidence: None,
            },
        )?);
    } else if had_text {
        result.events.clear();
        result.duplicate = true;
    } else {
        let fields = result
            .retained
            .get_or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| invalid("retained turn metadata is not an object"))?;
        fields.insert("empty_exchange".into(), Value::Bool(true));
        fields.insert(
            "turn_id".into(),
            Value::String(str_at(row, "turn_id")?.into()),
        );
    }
    Ok(result)
}
