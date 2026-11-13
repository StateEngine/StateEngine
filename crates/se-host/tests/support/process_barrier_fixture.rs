use super::*;
pub struct Harness {
    pub f: Fixture,
    pub writer: SqliteWriter,
    pub client: SqliteClient,
    pub target: AgentId,
}
pub fn kernel() -> Result<Kernel, Box<dyn std::error::Error>> {
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    Ok(Kernel::new(CallFacts {
        event: event()?,
        message: message()?,
        agent: agent()?,
        profile_event: event()?,
        occurred_at_us: now,
        door: Door::Cli,
    })?)
}
impl Harness {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut f = Fixture::new()?;
        let (host, lease) = host(&f)?;
        let writer = host.start_writer(options(256)?, lease)?;
        let client = writer.client();
        // The shared fixture's initial project has no root. Register a fresh
        // rooted project through the supported public event, without SQL repair.
        f.project = se_types::ProjectId::from_parts(1_700_000_000_000 + serial(), [73; 10])?;
        f.a = agent()?;
        f.b = agent()?;
        let target = agent()?;
        let h = Self {
            f,
            writer,
            client,
            target,
        };
        h.write(vec![
            EventBody::ProjectRegistered {
                project: h.f.project.clone(),
                name: "Barriers".into(),
                roots: vec![Root {
                    path: NativePath::from_local(h.f.home.clone())?,
                    canonical_key: h.f.home.to_string_lossy().as_bytes().to_vec(),
                }],
                owner: h.f.owner.clone(),
                history_from: None,
                expected: Expected::Absent,
            },
            control::helper(&h.f, &h.f.a, None),
            control::helper(&h.f, &h.f.b, None),
            control::helper(&h.f, &h.target, Some(&h.f.a)),
            control::grant(&h.f.a, true, Expected::Absent),
            EventBody::ProfileSaved {
                agent: h.target.clone(),
                profile: Profile {
                    provider: Provider::Claude,
                    model: None,
                    permission: PermissionProfile::WorkspaceWrite,
                    harness: None,
                    named_profile: "default".into(),
                    effort: None,
                },
                expected: Expected::Absent,
            },
        ])?;
        Ok(h)
    }
    pub fn owner(&self) -> Actor {
        Actor::Human(self.f.owner.clone())
    }
    pub fn creator(&self) -> Actor {
        Actor::Agent(self.f.a.clone())
    }
    pub fn snapshot(&self, actor: &Actor) -> Result<SqliteSnapshot, Box<dyn std::error::Error>> {
        let scope = match actor {
            Actor::Human(_) => self.f.scoped(Visibility::Owner),
            Actor::Agent(agent) => self.f.self_scope(agent),
            Actor::Remote(_) => {
                return Err("remote actors use the closed grant-filtered port".into());
            }
        };
        Ok(present(SqliteFactory::open_reader(&self.f.options)?)?.snapshot(scope)?)
    }
    pub fn write(
        &self,
        bodies: Vec<EventBody<InputText>>,
    ) -> Result<CommitReceipt, Box<dyn std::error::Error>> {
        Ok(wait(self.client.submit(self.f.batch(
            self.f.owner_project(),
            Some(super::fixture::request(&format!(
                "fixture-process_barrier_fixture-88-{}",
                serial()
            ))?),
            bodies,
        )?)?)??)
    }
    pub fn commit(&self, batch: AtomicBatch) -> Result<CommitReceipt, Box<dyn std::error::Error>> {
        let result = wait(self.client.submit(batch)?)??;
        assert_eq!(result.durability, CommitDurability::Full);
        Ok(result)
    }
    pub fn plan(&self, actor: Actor) -> Result<(Kernel, LaunchPlan), Box<dyn std::error::Error>> {
        let kernel = kernel()?;
        let admission = self
            .f
            .admission(Scope::Project(self.f.project.clone()), actor.clone());
        let mut read = self.snapshot(&actor)?;
        let mut cx = Cx {
            read: &mut read,
            admission: &admission,
        };
        let plan = process_plan::launch(
            &kernel,
            AgentLaunch {
                target_agent_id: Some(self.target.clone()),
                fresh: true,
                model: None,
                task: Some("real consumer fixture".into()),
                detach: true,
                override_live: false,
                force_selection: None,
                idempotency_key: se_types::IdempotencyKey::new(format!("launch-{}", serial()))?,
                owner_agent: None,
                owner_provider: None,
            },
            &ConfigFile::default(),
            &mut cx,
        )?;
        Ok((kernel, plan))
    }
    pub fn identity(
        &self,
        plan: &LaunchPlan,
    ) -> Result<ProcessIdentityRecord, Box<dyn std::error::Error>> {
        let mut identity = control::identity(&self.target)?;
        identity.record = plan.lifecycle.clone();
        identity.session = Some(plan.session.clone());
        identity.root_identity = RootIdentityState::NoChildCreated;
        Ok(identity)
    }
    pub fn reserve(
        &self,
        kernel: &Kernel,
        plan: &LaunchPlan,
        actor: Actor,
        hashes: [[u8; 32]; 2],
    ) -> Result<se_types::Result<AtomicBatch>, Box<dyn std::error::Error>> {
        let admission = self
            .f
            .admission(Scope::Project(self.f.project.clone()), actor.clone());
        let mut read = self.snapshot(&actor)?;
        Ok(process_commit::reserve(
            kernel,
            plan,
            self.identity(plan)?,
            hashes[0],
            hashes[1],
            &mut Cx {
                read: &mut read,
                admission: &admission,
            },
        ))
    }
    pub fn release_no_child(&self, plan: &LaunchPlan, receipt: &CommitReceipt) -> Check {
        self.write(vec![control::transition(
            &self.identity(plan)?,
            1,
            ProcessState::Reserved,
            ProcessState::Exited,
            receipt.primary_event.clone(),
        )?])?;
        Ok(())
    }
    pub fn credential(
        &self,
        hash: [u8; 32],
    ) -> Result<CredentialRecord, Box<dyn std::error::Error>> {
        present(present(SqliteFactory::open_reader(&self.f.options)?)?.credential(hash)?)
    }
    pub fn finish(self) -> Check {
        wait(self.writer.drain(Duration::from_secs(2)))??;
        Ok(())
    }
}
