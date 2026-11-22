//! Install attribution only from the already owned native lifecycle and binding.
use super::*;

struct HarnessLivePublisher(crate::remote::publish::LiveSource);

impl se_harness::LivePublisher for HarnessLivePublisher {
    fn delta_at(
        &self,
        vendor: &str,
        role: se_harness::LiveTurnRole,
        delta: &str,
        observed_at: std::time::Instant,
    ) {
        let role = match role {
            se_harness::LiveTurnRole::User => crate::remote::RemoteTurnRole::User,
            se_harness::LiveTurnRole::Assistant => crate::remote::RemoteTurnRole::Assistant,
            se_harness::LiveTurnRole::Tool => crate::remote::RemoteTurnRole::Tool,
        };
        self.0.delta_at(vendor, role, delta, observed_at);
    }

    fn complete_at(
        &self,
        vendor: &str,
        role: se_harness::LiveTurnRole,
        text: &str,
        observed_at: std::time::Instant,
    ) {
        let role = match role {
            se_harness::LiveTurnRole::User => crate::remote::RemoteTurnRole::User,
            se_harness::LiveTurnRole::Assistant => crate::remote::RemoteTurnRole::Assistant,
            se_harness::LiveTurnRole::Tool => crate::remote::RemoteTurnRole::Tool,
        };
        self.0.complete_at(vendor, role, text, observed_at);
    }
}

impl LaunchCoordinator {
    pub(super) fn attach_remote_live(&self, work: &mut owned::Work) {
        let Some(control) = self.store.mail_waits.remote_control() else {
            return;
        };
        let Ok(Some(publisher)) = control.live() else {
            return;
        };
        let Ok(source) = publisher.register(
            crate::remote::RemoteTarget {
                project: work.meta.project.id.clone(),
                agent: work.meta.agent.id.clone(),
            },
            work.meta.session.clone(),
            work.meta.lifecycle.clone(),
            self.store.generation,
        ) else {
            return;
        };
        if let Some(binding) = work
            .binding
            .as_ref()
            .and_then(|b| b.get::<crate::codex_rpc::Binding>())
            && let Ok(mut live) = binding.live.lock()
        {
            *live = Some(Arc::new(HarnessLivePublisher(source.clone())));
        }
        work.remote_live = Some(source);
    }
}

impl LaunchCoordinator {
    pub(super) async fn refresh_remote_sources(
        &self,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<()> {
        let jobs = self
            .jobs
            .0
            .lock()
            .map_err(|_| error("remote live sources", "launch registry poisoned"))?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for job in jobs {
            let mut work = crate::runtime::pool::within(deadline, job.state.lock()).await?;
            if work.binding.is_some() {
                self.attach_remote_live(&mut work);
            }
        }
        Ok(())
    }
}
