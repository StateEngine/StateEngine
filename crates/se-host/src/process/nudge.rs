//! Under a captain, nudge a crew member that sits idle on open work. The idle
//! clock is monotonic and only arms the monitor's existing timed wait; what to
//! send is decided from stored facts by se-core, so attempts survive restart.
use super::supervisor::Job;
use super::*;
use crate::{client::lease::Deadline, runtime::CustodyExecutor};
use std::{sync::atomic::Ordering, time::Duration};

impl LaunchCoordinator {
    /// Send the nudge or stuck alert that is due, if any, then return when the
    /// next one may be due: idle with no mail waiting to wake it, at least one
    /// interval after it went idle and after the engine last considered it.
    pub(super) async fn nudge(
        self: &Arc<Self>,
        state: &mut owned::Work,
        job: &Job,
        deadline: &Deadline,
    ) -> Option<tokio::time::Instant> {
        let now = tokio::time::Instant::now();
        let idle_since = state.mail.idle_since.unwrap_or(now);
        state.mail.idle_since = state.mail.idle.then_some(idle_since);
        let (interval, attempts) = self.options.configuration.runtime.captain_nudge().ok()??;
        if job.mail_pending.load(Ordering::Acquire) || state.mail.flight.is_some() {
            return None;
        }
        let due = state
            .mail
            .idle_since?
            .max(state.mail.last_nudge.unwrap_or(idle_since))
            + interval;
        if due > now {
            return Some(due);
        }
        state.mail.last_nudge = Some(now);
        let result = match deadline.stage(Duration::from_secs(10)) {
            Ok(bound) => self.send_nudge(state, attempts, &bound).await,
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            mail::diagnostic::report(state, &error);
        }
        Some(now + interval)
    }

    async fn send_nudge(
        self: &Arc<Self>,
        state: &owned::Work,
        attempts: u32,
        deadline: &Deadline,
    ) -> Result<()> {
        let admission = se_store::Admission {
            scope: state.admission.scope.clone(),
            actor: se_store::Actor::Human(self.capability_admission.owner.clone()),
            session: None,
            generation: state.admission.generation,
        };
        let agent = state.meta.agent.id.clone();
        let sent = mail::commit::step(
            &self.store,
            admission,
            deadline,
            move |kernel, cx| se_core::ops::captain_nudge::plan(kernel, &agent, attempts, cx),
            |kernel, cx, (then, to), receipt| kernel.committed(then, receipt, cx).map(|_| Some(to)),
        )
        .await?;
        let Some(agent) = sent else {
            return Ok(());
        };
        let project = state.meta.project.id.clone();
        CustodyExecutor::notify_mail(self, &[crate::runtime::MailRecipient { project, agent }])
    }
}
