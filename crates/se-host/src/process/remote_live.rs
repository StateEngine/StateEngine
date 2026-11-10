//! Install attribution only from the already owned native lifecycle and binding.
use super::*;
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
        if let Some(binding) = work.binding.as_ref().and_then(|b| b.codex.as_ref())
            && let Ok(mut live) = binding.live.lock()
        {
            *live = Some(source.clone());
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
