//! Provider turn state is joined only to the exact current native session.
use super::*;
use se_core::ops::{AgentCommand, AgentRow, AnyOutput, ProviderActivityView};
use se_types::{Page, Read};
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
        // Every host read ends here, so each row's state is settled from its
        // final merged observations, for the CLI and the MCP door alike.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| se_types::SeError::invalid("host clock", "after the Unix epoch"))?;
        let now = i64::try_from(now.as_micros())
            .map_err(|_| se_types::SeError::invalid("host clock", "representable microseconds"))?;
        se_core::ops::agent_state::settle(&mut output, now)?;
        Ok(output)
    }
    fn observe_provider_page(&self, page: &Page<AgentRow>) -> Result<Page<AgentRow>> {
        let mut rows = page.items().to_vec();
        for row in &mut rows {
            self.observe_provider_row(row);
        }
        let fields = page.window().fields().cloned().ok_or_else(|| {
            error(
                "provider activity page",
                "original page accounting unavailable",
            )
        })?;
        Page::fit(rows, fields, page.next().cloned(), |row| {
            row.resume_after.clone()
        })
    }
    fn with_provider_recovery(
        &self,
        row: &AgentRow,
        job: &supervisor::Job,
        mut value: ProviderActivityView,
        paced: Option<String>,
    ) -> Read<ProviderActivityView> {
        value.mail_paced_until = paced;
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
        let mut found = None;
        let mut read = || -> Result<Read<ProviderActivityView>> {
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
            let paced = self.mail_paced_until(&state, &job);
            found = state.process.clone();
            let Some(binding) = &state.binding else {
                return Ok(Read::Unknown { what: "Waiting for a provider connection; check provider sign-in. Explicitly stop this agent to cancel setup before retrying launch.".into() });
            };
            if let Some(binding) = binding.get::<crate::codex_rpc::Binding>() {
                return Ok(self.with_provider_recovery(row, &job, binding.activity()?, paced));
            }
            if let Some(binding) = binding.get::<crate::harness::ClaudeBinding>() {
                if binding.attended {
                    return Ok(Read::Unknown { what: "The provider owns its terminal; turn progress is not observed on this connection. Inspect the existing window for sign-in, trust or permission prompts and read saved history before resubmitting input.".into() });
                }
                return Ok(self.with_provider_recovery(
                    row,
                    &job,
                    binding.completion.activity()?,
                    paced,
                ));
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
        row.background = se_agent_observation::background(row.provider, &self.native, found);
        if row.provider == se_types::Provider::Codex {
            row.codex_login = Some(match &row.session.session_id {
                Some(session) => self.recorded_codex_login(session),
                None => Read::Absent {
                    checked: "This agent has no launched Codex session".into(),
                },
            });
        }
    }
}

impl LaunchCoordinator {
    /// The wall-clock time paced mail may next wake this agent, while mail waits.
    fn mail_paced_until(&self, state: &owned::Work, job: &supervisor::Job) -> Option<String> {
        if !job.mail_pending.load(Ordering::Acquire) {
            return None;
        }
        let wait = self.mail_pace(state, job)? - tokio::time::Instant::now();
        let at = std::time::SystemTime::now().checked_add(wait)?;
        let micros = at.duration_since(std::time::UNIX_EPOCH).ok()?.as_micros();
        se_core::ops::receipt::timestamp(i64::try_from(micros).ok()?).ok()
    }
    /// The login recorded for this agent at launch, and the account it is
    /// signed in to now. Only the folder and account identifier leave the file.
    fn recorded_codex_login(
        &self,
        session: &se_types::SessionId,
    ) -> Read<se_core::ops::CodexLoginView> {
        let read = || -> Result<Read<se_core::ops::CodexLoginView>> {
            let home = match self.codex.agent_login(session)? {
                Read::Present { value } => value,
                Read::Absent { checked } => return Ok(Read::Absent { checked }),
                Read::Unknown { what } => return Ok(Read::Unknown { what }),
                Read::Unreadable {
                    source,
                    reason,
                    error,
                } => {
                    return Ok(Read::Unreadable {
                        source,
                        reason,
                        error,
                    });
                }
            };
            codex_account(&home)
        };
        read().unwrap_or_else(|failure| Read::Unreadable {
            source: "Codex login".into(),
            reason: failure.to_string(),
            error: Some(Box::new(failure.body)),
        })
    }
}

fn codex_account(home: &std::path::Path) -> Result<Read<se_core::ops::CodexLoginView>> {
    let path = home.join("auth.json");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Read::Absent {
                checked: format!("Codex is not signed in at {}", home.display()),
            });
        }
        Err(e) => return Err(error("Codex login", e)),
    };
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| error("Codex login", e))?;
    let account = value
        .pointer("/tokens/account_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    Ok(Read::Present {
        value: se_core::ops::CodexLoginView {
            home: home.display().to_string(),
            account,
        },
    })
}
