//! Status native facts share the finite agent-observation worker. Core status
//! rows are prepared earlier, under the request's admission/planning snapshot.
use super::*;
use crate::{BlockingClass, client::lease::Deadline};
use se_core::ops::*;
use se_store::Admission;
use se_types::{Read, Result};
mod repository;
#[path = "status/resources.rs"]
mod resources;

impl LaunchCoordinator {
    pub(super) async fn status(
        self: &Arc<Self>,
        input: ProjectStatus,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<AnyOutput> {
        let (fresh, watch_only) = (input.fresh, input.watch_only);
        let home = self.options.home.clone();
        let observed_admission = admission.clone();
        let (mut output, plans) = self
            .store
            .read(admission, deadline, move |cx| {
                let output = crate::runtime::status::prepare(input, &home, cx)?;
                let plans = crate::agent_observation::output::prepare(
                    &cx.admission.scope,
                    &output,
                    cx.read,
                )?;
                Ok((output, plans))
            })
            .await?;
        let coordinator = Arc::clone(self);
        let bound = deadline.clone();
        let home = self.options.home.clone();
        self.store
            .pool
            .run(BlockingClass::Foreground, deadline, move || {
                bound.remaining()?;
                crate::agent_observation::output::observe(&mut output, plans, bound.at(), &home)?;
                coordinator.observe_repository(&mut output, fresh, watch_only, &bound)?;
                coordinator.observe_status(&mut output, &observed_admission, &bound)?;
                bound.remaining()?;
                Ok(output)
            })
            .await
    }
    /// An agent caller in a project also sees its peers' summaries, read as
    /// the owner of that same project; the caller's own read is unchanged.
    pub(super) fn peer_request(
        &self,
        admission: &Admission,
    ) -> Option<(Admission, se_types::AgentId)> {
        let (se_store::Actor::Agent(caller), se_store::Scope::Project(_)) =
            (&admission.actor, &admission.scope)
        else {
            return None;
        };
        let owner = Admission {
            scope: admission.scope.clone(),
            actor: se_store::Actor::Human(self.capability_admission.owner.clone()),
            session: None,
            generation: admission.generation,
        };
        Some((owner, caller.clone()))
    }
    /// Peers' rows observed and settled exactly as the owner would see them,
    /// then reduced to the summary a peer row holds. The working tree is not
    /// rescanned for this. A failure is reported as unreadable, never as no peers.
    pub(super) async fn peer_summaries(
        self: &Arc<Self>,
        owner: Admission,
        caller: &se_types::AgentId,
        deadline: &Deadline,
    ) -> Read<Vec<PeerRow>> {
        let input = ProjectStatus {
            all: false,
            fresh: false,
            watch_only: true,
            include_temp: false,
        };
        // The same observation chain every host read gets (SE Code, ACP and
        // provider), so each peer's state settles from the same facts.
        let observed = match self.status(input, owner, deadline).await {
            Ok(output) => crate::CustodyExecutor::observe_output(self, output, deadline).await,
            Err(error) => Err(error),
        };
        match observed {
            Ok(output) => se_core::ops::agent_state::peer_rows(&output, caller),
            Err(error) => Read::Unreadable {
                source: "peer summaries".into(),
                reason: error.to_string(),
                error: Some(Box::new(error.body)),
            },
        }
    }
    pub(super) fn observe_status(
        &self,
        output: &mut AnyOutput,
        admission: &Admission,
        deadline: &Deadline,
    ) -> Result<()> {
        deadline.remaining()?;
        self.task_status(output, &admission.scope, &admission.actor)?;
        if let AnyOutput::ProjectStatus(status) = output
            && status.value.removal.is_none()
        {
            status.value.atlas = if !self.options.configuration.atlas.enabled {
                let mut view = se_core::ops::status::atlas_view(Ok(Read::Absent {
                    checked: "Atlas is disabled in this host configuration.".into(),
                }));
                view.state = "disabled".into();
                view
            } else if let se_store::Scope::Project(project) = &admission.scope {
                se_core::ops::status::atlas_view(self.atlas.status(project, None))
            } else {
                se_core::ops::status::atlas_view(Ok(Read::Absent {
                    checked: "Select a registered project to observe its Atlas index.".into(),
                }))
            };
        }
        let observed = se_proc::read_process(self.owner.machine.clone(), self.owner.pid)
            .map_err(|cause| error("host process observation", cause))?;
        let se_proc::ProcessRead::Present(observed) = observed else {
            return Err(error(
                "host process observation",
                "the serving host is not present",
            ));
        };
        if observed.identity != self.owner
            || !matches!(
                observed.state,
                se_proc::NativeState::Running | se_proc::NativeState::Stopped
            )
        {
            return Err(error(
                "host process observation",
                "the exact serving process instance must be live",
            ));
        }
        let AnyOutput::ProjectStatus(status) = output else {
            return Err(error("host status", "the original status family"));
        };
        status.value.runtime.state = "running".into();
        status.value.runtime.host = Some(
            match self.kind {
                crate::HostKind::Standalone => "daemon",
                crate::HostKind::EmbeddedSecode => "secode",
            }
            .into(),
        );
        status.value.runtime.process = Some(launch_util::view(&self.owner, deadline.at())?);
        status.value.runtime.generation = Some(self.store.generation.get());
        status.value.runtime.version = Some(env!("CARGO_PKG_VERSION").into());
        status.value.runtime.observed_at = Some(receipt::timestamp(
            i64::try_from(observed.observed_at_unix_ns / 1000)
                .map_err(|_| error("host observation clock", "representable Unix microseconds"))?,
        )?);
        resources::observe(&mut status.value.runtime);
        crate::adoption::status::observe(&self.options.home, &mut status.value);

        deadline.remaining()?;
        Ok(())
    }
}
