//! Status native facts share the finite agent-observation worker. Core status
//! rows are prepared earlier, under the request's admission/planning snapshot.
use super::*;
use crate::{BlockingClass, client::lease::Deadline};
use se_core::ops::*;
use se_store::Admission;
use se_types::{Read, Result};
#[path = "status/resources.rs"]
mod resources;

impl LaunchCoordinator {
    pub(super) async fn status(
        self: &Arc<Self>,
        input: ProjectStatus,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<AnyOutput> {
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
                coordinator.observe_status(&mut output, &observed_admission, &bound)?;
                bound.remaining()?;
                Ok(output)
            })
            .await
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
        // Display metadata belongs to this exact retained process instance.
        // Every reply still verifies its native identity and liveness above;
        // failures converting its birth time are never retained as a value.
        let process = match self.owner_display.get() {
            Some(value) => value,
            None => {
                let value = launch_util::view(&self.owner, deadline.at())?;
                self.owner_display.get_or_init(|| value)
            }
        };
        status.value.runtime.process = Some(process.clone());
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
