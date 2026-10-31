use super::*;
use se_types::{NativePath, SessionId};
use sha2::{Digest, Sha256};

pub fn record() -> Result<RecordId, Box<dyn std::error::Error>> {
    let n = serial();
    Ok(RecordId::from_parts(1_700_000_000_000 + n, [n as u8; 10])?)
}
pub fn session() -> Result<SessionId, Box<dyn std::error::Error>> {
    let n = serial();
    Ok(SessionId::from_parts(1_700_000_000_000 + n, [n as u8; 10])?)
}
pub fn prepared(_f: &Fixture, id: &SessionId, agent: &se_types::AgentId) -> EventBody<InputText> {
    EventBody::SessionPrepared {
        session: id.clone(),
        agent: agent.clone(),
        provider: Provider::Claude,
        native_ref: format!("provider-{}", agent.as_str()),
        consent: Consent::Capture,
        generation: 1,
        expected: Expected::Absent,
    }
}
pub fn activated(id: &SessionId) -> Result<EventBody<InputText>, Box<dyn std::error::Error>> {
    Ok(EventBody::SessionActivated {
        session: id.clone(),
        expected: revision(1)?,
        incumbent: None,
        process: None,
        containment: ContainmentFact::NotLaunched,
        witnesses: vec![],
    })
}
pub fn source(
    id: RecordId,
    session: &SessionId,
    incarnation: &[u8],
    expected: Expected,
) -> EventBody<InputText> {
    EventBody::CaptureSource {
        source: id,
        session: session.clone(),
        consent: Consent::Capture,
        native_ref: "transcript.jsonl".into(),
        incarnation: incarnation.into(),
        expected,
    }
}
pub fn capture(
    f: &Fixture,
    session: &SessionId,
    source_id: RecordId,
    incarnation: &[u8],
    offset: u64,
    expected: u64,
    vendor: &str,
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let turn = record()?;
    let evidence = b"ten bytes!";
    let mut admission = f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone()));
    admission.session = Some(session.clone());
    let mut batch = f.batch(
        admission,
        None,
        vec![
            EventBody::SessionTurn {
                turn,
                agent: f.a.clone(),
                session: session.clone(),
                provider: Provider::Claude,
                vendor_ref: vendor.into(),
                role: Role::Assistant,
                text: InputText::Inline(format!("captured {vendor}")),
                evidence: SourceEvidence {
                    path: NativePath::from_local(f.home.join("transcript.jsonl"))?,
                    incarnation: incarnation.into(),
                    offset,
                    length: evidence.len() as u64,
                    sha256: Some(Sha256::digest(evidence).into()),
                },
            },
            EventBody::CaptureProgress {
                source: source_id,
                expected: revision(expected)?,
                incarnation: incarnation.into(),
                old_offset: offset,
                new_offset: offset + evidence.len() as u64,
                last_turn: turn,
            },
        ],
    )?;
    for event in &mut batch.events {
        event.header.session = Some(session.clone());
    }
    Ok(batch)
}
pub fn active(
    f: &Fixture,
    d: &mut SqliteDirect,
    lease: &Lease,
    id: &SessionId,
    source_id: RecordId,
) -> Check {
    std::fs::write(f.home.join("transcript.jsonl"), b"ten bytes!ten bytes!")?;
    d.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                prepared(f, id, &f.a),
                activated(id)?,
                source(source_id, id, b"first", Expected::Absent),
            ],
        )?,
        lease,
    )?;
    Ok(())
}
