//! Diagnose a missing retained transcript before any new provider preparation.
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::{AgentCommand, agent_launch::LaunchPlan};
use se_store::Admission;
use se_types::{Read, SeError};

impl LaunchCoordinator {
    pub(super) async fn check_resume_source(
        &self,
        plan: &LaunchPlan,
        admission: &Admission,
        deadline: &Deadline,
    ) -> Result<()> {
        if plan.input.fresh {
            return Ok(());
        }
        let conversation = match &plan.conversation {
            Read::Present { value } => value.as_str().to_owned(),
            Read::Absent { .. } | Read::Unknown { .. } | Read::Unreadable { .. } => return Ok(()),
        };
        let selected = plan.clone();
        let source = self
            .store
            .read(admission.clone(), deadline, move |cx| {
                crate::agent_observation::resume_source(&selected, cx.read)
            })
            .await?;
        let Some(source) = source else {
            return Ok(());
        };
        let path = source.to_local()?;
        let selected = plan.clone();
        let home = self.options.home.clone();
        self.store.pool.run_owned(deadline, move || {
            let reason = match se_proc::NativeSourcePin::open(&path) {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => format!("The saved transcript is missing at {}. No provider was launched.", path.display()),
                Err(error) => format!("The saved transcript cannot be read at {}: {error}. No provider was launched.", path.display()),
            };
            let mut error = SeError::new(se_types::Detail::ResumeReferenceUnverifiable(
                se_types::details::ResumeReferenceUnverifiable {
                    agent: selected.agent.id.clone(),
                    conversation,
                    reason,
                },
            ));
            let command = AgentCommand::launch_in_home(&selected.agent.id, &home, &selected.project.id, true)
                .map(|command| command.with_detach(selected.input.detach));
            let (text, command) = match command {
                Some(command) => (
                    format!("Restore the original transcript to resume it, or start a new conversation explicitly. Captured history is retained. {}: {}", AgentCommand::instruction("Run"), command.command),
                    Some(se_types::Cmd::Se { argv: se_types::Argv::from_op(&command)? }),
                ),
                None => (AgentCommand::HOME_UNAVAILABLE.into(), Some(se_types::Cmd::Manual)),
            };
            error.body = error.body.with_remedy(se_types::Remedy { text, command });
            Err(error)
        }).await
    }
}
