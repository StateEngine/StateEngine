//! Provider turn state is joined only to the exact current native session.
use super::*;
use se_core::ops::{AgentCommand, AgentRow, AnyOutput, ProviderActivityView};
use se_types::{Page, Read, Window};
use std::sync::atomic::Ordering;

impl LaunchCoordinator {
    pub(super) fn observe_provider_output(&self, mut output: AnyOutput) -> Result<AnyOutput> {
        match &mut output {
            AnyOutput::AgentShow(value) => {
                if let Read::Present { value } = &mut value.value.agent {
                    self.observe_provider_row(value);
                }
            }
            AnyOutput::AgentList(value) => {
                value.value.page = self.observe_provider_page(&value.value.page)?
            }
            AnyOutput::ProjectStatus(value) => {
                if let Some(page) = &value.value.agents {
                    value.value.agents = Some(self.observe_provider_page(page)?);
                }
            }
            _ => (),
        }
        Ok(output)
    }
    fn observe_provider_page(&self, page: &Page<AgentRow>) -> Result<Page<AgentRow>> {
        let mut rows = page.items().to_vec();
        for row in &mut rows {
            self.observe_provider_row(row);
        }
        let mut fields = page.window().fields().cloned().ok_or_else(|| {
            error(
                "provider activity page",
                "original page accounting unavailable",
            )
        })?;
        fields.bytes = serde_json::to_vec(&rows)
            .map_err(|e| error("provider activity page", e))?
            .len() as u64;
        if fields.bytes > u64::from(fields.max_bytes.get()) {
            return Err(error(
                "provider activity page",
                "enriched rows exceed the requested byte bound; request a smaller page",
            ));
        }
        Page::new(rows, Window::new(fields)?, page.next().cloned())
    }
    fn with_provider_recovery(
        &self,
        row: &AgentRow,
        job: &supervisor::Job,
        mut value: ProviderActivityView,
    ) -> Read<ProviderActivityView> {
        if let Some(next) = &mut value.next_step {
            match (
                AgentCommand::history_in_home(&row.id, &self.options.home, &job.target.0),
                AgentCommand::stop_in_home(&row.id, &self.options.home, &job.target.0),
                AgentCommand::launch_in_home(&row.id, &self.options.home, &job.target.0, false),
            ) {
                (Some(history), Some(stop), Some(launch)) => next.push_str(&format!(
                    " {} Saved history: `{}`. After correcting the cause, stop with `{}`, then reopen with `{}`. No task is automatically resubmitted.",
                    AgentCommand::instruction("Use these commands in your own terminal."),
                    history.command, stop.command, launch.command,
                )),
                _ => next.push_str(AgentCommand::HOME_UNAVAILABLE),
            }
        }
        Read::Present { value }
    }
    fn observe_provider_row(&self, row: &mut AgentRow) {
        if !matches!(
            row.provider,
            se_types::Provider::Claude | se_types::Provider::Codex
        ) {
            return;
        }
        let read = || -> Result<Read<ProviderActivityView>> {
            let Some(session) = &row.session.session_id else {
                return Ok(Read::Absent {
                    checked: "This agent has no launched provider session".into(),
                });
            };
            let job = self
                .jobs
                .0
                .lock()
                .map_err(|_| error("provider activity", "launch registry is poisoned"))?
                .values()
                .find(|job| &job.session == session && job.target.1 == row.id)
                .cloned();
            let Some(job) = job else {
                return Ok(Read::Unknown { what: "This runtime retains no turn observation for this session. Native liveness does not establish progress; check provider sign-in and saved history before resubmitting input.".into() });
            };
            if job.settled.load(Ordering::Acquire) {
                return Ok(Read::Absent { checked: "The provider lifecycle has settled; read saved history for its final outcome".into() });
            }
            let Ok(state) = job.state.try_lock() else {
                let window = job.wake.awaiting_window.load(Ordering::Acquire);
                return Ok(Read::Unknown { what: if window {
                    "Waiting for provider setup in the existing window. Finish sign-in or workspace trust there, or explicitly stop this agent to cancel setup."
                } else {
                    "The runtime is handling provider setup or an accepted operation; turn activity cannot currently be read. Check provider sign-in and saved history; explicitly stop this agent to cancel setup rather than resubmitting uncertain input."
                }.into() });
            };
            let Some(binding) = &state.binding else {
                return Ok(Read::Unknown { what: "Waiting for a provider connection; check provider sign-in. Explicitly stop this agent to cancel setup before retrying launch.".into() });
            };
            if let Some(binding) = &binding.codex {
                return Ok(self.with_provider_recovery(row, &job, binding.activity()?));
            }
            if let Some(binding) = &binding.claude {
                if binding.attended {
                    return Ok(Read::Unknown { what: "The provider owns its terminal; turn progress is not observed on this connection. Inspect the existing window for sign-in, trust or permission prompts and read saved history before resubmitting input.".into() });
                }
                return Ok(self.with_provider_recovery(row, &job, binding.completion.activity()?));
            }
            Ok(Read::Unknown { what: "The retained lifecycle has no matching provider turn connection; check saved history and provider sign-in.".into() })
        };
        row.provider_activity = Some(match read() {
            Ok(value) => value,
            Err(error) => Read::Unreadable {
                source: "provider turn observation".into(),
                reason: error.to_string(),
                error: Some(Box::new(error.body)),
            },
        });
    }
}
