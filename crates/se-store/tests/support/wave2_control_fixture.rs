use super::*;
pub(super) fn identity(
    agent: &AgentId,
) -> Result<ProcessIdentityRecord, Box<dyn std::error::Error>> {
    let n = serial();
    Ok(ProcessIdentityRecord {
        record: LifecycleId::from_parts(1_700_000_000_000 + n, [n as u8; 10])?,
        principal: Actor::Agent(agent.clone()),
        session: None,
        root_identity: RootIdentityState::Unpublished,
        instance: RecordedIdentity::Absent {
            reason: "prepared scope has not published its root".into(),
        },
        custody: NativeCustody {
            format_version: 1,
            record: b"typed store fixture, not a native custody witness".to_vec(),
        },
        containment: ContainmentFact::NotLaunched,
    })
}
pub(super) fn registration(
    i: &ProcessIdentityRecord,
    initial: ProcessState,
) -> EventBody<InputText> {
    EventBody::ProcessRegistered {
        identity: Box::new(i.clone()),
        initial,
    }
}
pub(super) fn transition(
    i: &ProcessIdentityRecord,
    rev: u64,
    from: ProcessState,
    to: ProcessState,
    observation: se_types::EventId,
) -> Result<EventBody<InputText>, Box<dyn std::error::Error>> {
    Ok(EventBody::ProcessTransition {
        process: i.record.clone(),
        identity: Box::new(i.clone()),
        expected: revision(rev)?,
        from,
        to,
        observation,
        outcome: "independent store boundary observation".into(),
        containment: i.containment.clone(),
    })
}
pub(super) fn head(
    f: &Fixture,
    id: LifecycleId,
) -> Result<ProjectionRecord, Box<dyn std::error::Error>> {
    present(
        present(SqliteFactory::open_reader(&f.options)?)?
            .snapshot(f.scoped(Visibility::Owner))?
            .process(id)?,
    )
}
pub(super) fn grant(agent: &AgentId, active: bool, expected: Expected) -> EventBody<InputText> {
    EventBody::GrantRecorded {
        principal: Actor::Agent(agent.clone()),
        key: GrantKey::AgentCanCreate(agent.clone()),
        active,
        expected,
    }
}
pub(super) fn helper(f: &Fixture, id: &AgentId, by: Option<&AgentId>) -> EventBody<InputText> {
    EventBody::PrincipalRegistered {
        principal: Actor::Agent(id.clone()),
        kind: PrincipalKind::Agent,
        owner: f.owner.clone(),
        created_by: by.cloned().map(Actor::Agent),
        name: id.as_str().into(),
        role: "helper".into(),
        expected: Expected::Absent,
    }
}
