use super::*;
use se_types::DecisionId;
pub(super) struct Governing {
    pub(super) f: Fixture,
    direct: SqliteDirect,
    lease: Arc<Lease>,
    bound: se_types::SessionId,
}
impl Governing {
    pub(super) fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let f = Fixture::new()?;
        let (direct, lease) = f.direct()?;
        let mut h = Self {
            f,
            direct,
            lease,
            bound: capture::session()?,
        };
        h.owner(vec![
            capture::prepared(&h.f, &h.bound, &h.f.b),
            capture::activated(&h.bound)?,
        ])?;
        let a = h.propose("law.first", "visible first", None)?;
        h.ratify(&a)?;
        let b = h.propose("law.second", "visible second", None)?;
        h.ratify(&b)?;
        let old = h.propose("law.replaced", "SECRET OLD PROPOSAL", None)?;
        h.ratify(&old)?;
        let replacement = h.propose("law.replaced", "visible replacement", Some(old.clone()))?;
        h.ratify(&replacement)?;
        let approval = h.approval()?;
        let Expected::Revision(two) = revision(2)? else {
            return Err("revision helper".into());
        };
        h.owner(vec![EventBody::DecisionSuperseded {
            prior: old,
            replacement,
            prior_expected: two,
            replacement_expected: two,
            approval,
        }])?;
        h.propose("request.pending", "SECRET A PENDING RULING REQUEST", None)?;
        let rejected = h.propose("request.rejected", "SECRET REJECTED", None)?;
        h.owner(vec![EventBody::DecisionRejected {
            decision: rejected,
            expected: revision(1)?,
            reason: InputText::Inline("declined".into()),
        }])?;
        let retracted = h.propose("request.retracted", "SECRET RETRACTED", None)?;
        h.owner(vec![EventBody::DecisionRetracted {
            decision: retracted,
            expected: revision(1)?,
            reason: InputText::Inline("withdrawn".into()),
        }])?;
        h.direct.append(
            h.f.send(
                Actor::Agent(h.f.a.clone()),
                Actor::Agent(h.f.a.clone()),
                message()?,
                "SECRET A PRIVATE MAIL",
                "private-mail",
            )?,
            &*h.lease,
        )?;
        h.direct.append(
            h.f.working("SECRET A PRIVATE STATE", Expected::Absent, "private-state")?,
            &*h.lease,
        )?;
        Ok(h)
    }
    fn owner(&mut self, bodies: Vec<EventBody<InputText>>) -> Check {
        self.direct.append(
            self.f.batch(
                self.f.owner_project(),
                Some(request(&format!(
                    "fixture-wave2_continuity_fixture-73-{}",
                    serial()
                ))?),
                bodies,
            )?,
            &*self.lease,
        )?;
        Ok(())
    }
    fn approval(&mut self) -> Result<se_types::EventId, Box<dyn std::error::Error>> {
        Ok(self
            .direct
            .append(
                self.f.send(
                    Actor::Human(self.f.owner.clone()),
                    Actor::Agent(self.f.a.clone()),
                    message()?,
                    "Approve this project law",
                    &format!("approval-{}", serial()),
                )?,
                &*self.lease,
            )?
            .primary_event)
    }
    fn propose(
        &mut self,
        key: &str,
        text: &str,
        prior: Option<DecisionId>,
    ) -> Result<DecisionId, Box<dyn std::error::Error>> {
        let n = serial();
        let decision = DecisionId::from_parts(1_700_000_000_000 + n, [n as u8; 10])?;
        self.direct.append(
            self.f.batch(
                self.f.admission(
                    Scope::Project(self.f.project.clone()),
                    Actor::Agent(self.f.a.clone()),
                ),
                Some(request(&format!(
                    "fixture-wave2_continuity_fixture-102-{}",
                    serial()
                ))?),
                vec![EventBody::DecisionProposed {
                    decision: decision.clone(),
                    key: key.into(),
                    statement: InputText::Inline(text.into()),
                    rationale: None,
                    prior,
                    kind: DecisionKind::Decision,
                }],
            )?,
            &*self.lease,
        )?;
        Ok(decision)
    }
    fn ratify(&mut self, decision: &DecisionId) -> Check {
        let approval = self.approval()?;
        self.owner(vec![EventBody::DecisionRatified {
            decision: decision.clone(),
            expected: revision(1)?,
            approval,
        }])
    }
    pub(super) fn retired_ratified(&mut self) -> Result<DecisionId, Box<dyn std::error::Error>> {
        let id = self.propose("law.retired", "retired project law", None)?;
        self.ratify(&id)?;
        self.owner(vec![EventBody::DecisionRetracted {
            decision: id.clone(),
            expected: revision(2)?,
            reason: InputText::Inline("new circumstances".into()),
        }])?;
        Ok(id)
    }
    pub(super) fn reader(&self) -> Result<SqliteSnapshot, Box<dyn std::error::Error>> {
        let mut scope = self.f.self_scope(&self.f.b);
        scope.admission.session = Some(self.bound.clone());
        Ok(self.direct.snapshot(scope)?)
    }
    pub(super) fn owner_reader(&self) -> Result<SqliteSnapshot, Box<dyn std::error::Error>> {
        Ok(self.direct.snapshot(self.f.scoped(Visibility::Owner))?)
    }
    pub(super) fn finish(self) -> Check {
        self.direct.close()?;
        drop(self.lease);
        Ok(())
    }
    #[allow(dead_code, reason = "Used by the independent public MCP consumer.")]
    pub(super) fn host_parts(
        self,
    ) -> Result<(Fixture, se_types::SessionId), Box<dyn std::error::Error>> {
        self.direct.close()?;
        drop(self.lease);
        Ok((self.f, self.bound))
    }
}
pub(super) fn proposal(record: &ProjectionRecord) -> Result<String, Box<dyn std::error::Error>> {
    match record.original.as_ref().map(|e| &e.body) {
        Some(EventBody::DecisionProposed {
            statement: StoredText::Present(text),
            ..
        }) => Ok(text.clone()),
        _ => Err("governing head lacks its exact retained proposal".into()),
    }
}
