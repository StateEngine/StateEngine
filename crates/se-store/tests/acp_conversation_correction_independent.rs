//! Conversation replay filters unrelated sessions and non-chat rows before paging.
use se_store::*;
use se_types::{AgentId, NativePath, SessionId};
use sha2::{Digest, Sha256};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
fn session() -> Result<SessionId, Box<dyn std::error::Error>> {
    let n = serial();
    Ok(SessionId::from_parts(1_700_000_000_000 + n, [n as u8; 10])?)
}
fn record() -> Result<RecordId, Box<dyn std::error::Error>> {
    let n = serial();
    Ok(RecordId::from_parts(1_700_000_000_000 + n, [n as u8; 10])?)
}
fn activated(id: &SessionId) -> Result<EventBody<InputText>, Box<dyn std::error::Error>> {
    Ok(EventBody::SessionActivated {
        session: id.clone(),
        expected: revision(1)?,
        incumbent: None,
        process: None,
        containment: ContainmentFact::NotLaunched,
        witnesses: vec![],
    })
}

fn start(
    f: &Fixture,
    d: &mut SqliteDirect,
    lease: &Lease,
    agent: &AgentId,
    native: &str,
) -> Result<(SessionId, RecordId), Box<dyn std::error::Error>> {
    let id = session()?;
    let source = record()?;
    d.append(
        f.batch(
            f.owner_project(),
            Some(request(&format!("session-{id}"))?),
            vec![
                EventBody::SessionPrepared {
                    session: id.clone(),
                    agent: agent.clone(),
                    provider: Provider::Acp,
                    surface: None,
                    native_ref: native.into(),
                    consent: Consent::Capture,
                    generation: 1,
                    expected: Expected::Absent,
                },
                activated(&id)?,
                EventBody::CaptureSource {
                    source,
                    session: id.clone(),
                    consent: Consent::Capture,
                    native_ref: native.into(),
                    incarnation: b"synthetic".to_vec(),
                    expected: Expected::Absent,
                },
            ],
        )?,
        lease,
    )?;
    Ok((id, source))
}
fn rows(
    f: &Fixture,
    d: &mut SqliteDirect,
    lease: &Lease,
    binding: (&AgentId, &SessionId, RecordId),
    role: Role,
    count: usize,
    label: &str,
) -> Check {
    let (agent, id, source) = binding;
    let mut at = 0u64;
    let mut revision_number = 1;
    while at < count as u64 {
        let end = (at + 63).min(count as u64);
        let mut bodies = Vec::new();
        let mut last = None;
        for n in at..end {
            let turn = record()?;
            last = Some(turn);
            bodies.push(EventBody::SessionTurn {
                turn,
                agent: agent.clone(),
                session: id.clone(),
                provider: Provider::Acp,
                vendor_ref: format!("{label}-{n}"),
                role,
                text: InputText::Inline(format!("{label}-{n}")),
                evidence: SourceEvidence {
                    path: Some(NativePath::from_local(f.home.join("synthetic.jsonl"))?),
                    incarnation: b"synthetic".to_vec(),
                    offset: n,
                    length: 1,
                    sha256: Some(Sha256::digest(b"x").into()),
                },
            });
        }
        bodies.push(EventBody::CaptureProgress {
            source,
            expected: revision(revision_number)?,
            incarnation: b"synthetic".to_vec(),
            old_offset: at,
            new_offset: end,
            last_turn: last.ok_or("missing last turn")?,
            replay_evidence: None,
        });
        let mut admission = f.admission(
            Scope::Project(f.project.clone()),
            Actor::Agent(agent.clone()),
        );
        admission.session = Some(id.clone());
        let mut batch = f.batch(admission, None, bodies)?;
        for event in &mut batch.events {
            event.header.session = Some(id.clone());
        }
        d.append(batch, lease)?;
        at = end;
        revision_number += 1;
    }
    d.append(
        f.batch(
            f.owner_project(),
            Some(request(&format!("end-{id}"))?),
            vec![EventBody::SessionEnded {
                session: id.clone(),
                expected: revision(2)?,
                reason: InputText::Inline("synthetic completion".into()),
                final_turn: None,
                final_cursor: None,
            }],
        )?,
        lease,
    )?;
    Ok(())
}
#[test]
fn selected_chat_pages_ignore_more_than_ten_thousand_unrelated_and_tool_rows() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    std::fs::write(f.home.join("synthetic.jsonl"), vec![b'x'; 20002])?;
    let (other, other_source) = start(&f, &mut d, &lease, &f.a, "other-conversation")?;
    rows(
        &f,
        &mut d,
        &lease,
        (&f.a, &other, other_source),
        Role::Assistant,
        10001,
        "unrelated",
    )?;
    let (first, first_source) = start(&f, &mut d, &lease, &f.a, "selected-conversation")?;
    rows(
        &f,
        &mut d,
        &lease,
        (&f.a, &first, first_source),
        Role::Tool,
        10001,
        "tool",
    )?;
    // A second capture source in this session is not needed: each fixture batch
    // owns its source cursor, so selected chat continues in a distinct session.
    let (second, second_source) = start(&f, &mut d, &lease, &f.a, "selected-conversation")?;
    rows(
        &f,
        &mut d,
        &lease,
        (&f.a, &second, second_source),
        Role::User,
        2,
        "selected",
    )?;
    let (third, third_source) = start(&f, &mut d, &lease, &f.a, "selected-conversation")?;
    rows(
        &f,
        &mut d,
        &lease,
        (&f.a, &third, third_source),
        Role::Assistant,
        2,
        "answer",
    )?;
    let mut snapshot = d.snapshot(f.self_scope(&f.a))?;
    let mut after = None;
    let mut text = Vec::new();
    loop {
        let page = snapshot.conversation_turns(
            f.a.clone(),
            Provider::Acp,
            "selected-conversation",
            budget(1, 65536, after)?,
        )?;
        for event in page.items() {
            let EventBody::SessionTurn {
                role,
                text: StoredText::Present(body),
                ..
            } = &event.body
            else {
                return Err("non-chat conversation row".into());
            };
            assert!(matches!(role, Role::User | Role::Assistant));
            text.push(body.clone());
        }
        after = page.next().cloned();
        if after.is_none() {
            assert!(page.window().complete());
            break;
        }
    }
    assert_eq!(text, ["selected-0", "selected-1", "answer-0", "answer-1"]);
    let denied = snapshot
        .conversation_turns(
            f.b.clone(),
            Provider::Acp,
            "selected-conversation",
            budget(1, 65536, None)?,
        )
        .err()
        .ok_or("foreign selector accepted")?;
    assert_eq!(denied.code, StoreErrorCode::ScopeMismatch);
    snapshot.close()?;
    Ok(())
}

#[test]
fn another_agents_identical_native_reference_does_not_block_a_self_read() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    std::fs::write(f.home.join("synthetic.jsonl"), b"x")?;
    let (own, own_source) = start(&f, &mut d, &lease, &f.a, "same-native-reference")?;
    rows(
        &f,
        &mut d,
        &lease,
        (&f.a, &own, own_source),
        Role::User,
        1,
        "own",
    )?;
    {
        let mut snapshot = d.snapshot(f.self_scope(&f.a))?;
        let page = snapshot.conversation_turns(
            f.a.clone(),
            Provider::Acp,
            "same-native-reference",
            budget(10, 65536, None)?,
        )?;
        assert_eq!(page.items().len(), 1);
        snapshot.close()?;
    }
    let (other, other_source) = start(&f, &mut d, &lease, &f.b, "same-native-reference")?;
    rows(
        &f,
        &mut d,
        &lease,
        (&f.b, &other, other_source),
        Role::Assistant,
        1,
        "other",
    )?;
    {
        let mut snapshot = d.snapshot(f.scoped(Visibility::Owner))?;
        let page = snapshot.conversation_turns(
            f.a.clone(),
            Provider::Acp,
            "same-native-reference",
            budget(10, 65536, None)?,
        )?;
        assert_eq!(page.items().len(), 1);
        snapshot.close()?;
    }
    let mut snapshot = d.snapshot(f.self_scope(&f.a))?;
    let page = snapshot.conversation_turns(
        f.a.clone(),
        Provider::Acp,
        "same-native-reference",
        budget(10, 65536, None)?,
    )?;
    assert_eq!(
        page.items().len(),
        1,
        "a foreign source must not prevent reading this agent's own conversation"
    );
    snapshot.close()?;
    Ok(())
}
