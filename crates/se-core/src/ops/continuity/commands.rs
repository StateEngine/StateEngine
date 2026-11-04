//! Typed recovery commands share one home/project prefix before packet sizing.
use super::identity::Identity;
use crate::ops::AgentCommand;
use se_types::{Result, SeError};

impl Identity {
    pub(super) fn command(&self, words: impl IntoIterator<Item = String>) -> Result<AgentCommand> {
        let mut argv = vec!["se".into()];
        if let Some(home) = &self.command_home {
            let home = AgentCommand::home_argument(home).ok_or_else(|| {
                SeError::invalid("continuity command home", AgentCommand::HOME_UNAVAILABLE)
            })?;
            argv.extend(["--home".into(), home.into()]);
        }
        argv.extend(["--project".into(), self.principal.project.id.to_string()]);
        argv.extend(words);
        AgentCommand::from_argv(argv).ok_or_else(|| {
            SeError::invalid(
                "continuity command",
                "portable arguments without line breaks",
            )
        })
    }
    pub(super) fn history(&self) -> Result<AgentCommand> {
        self.command(["history".into(), "--kind".into(), "session.turn".into()])
    }
    pub(super) fn working_state(&self) -> Result<AgentCommand> {
        self.command([
            "working-state".into(),
            "--agent".into(),
            self.principal.agent.id.to_string(),
        ])
    }
}
