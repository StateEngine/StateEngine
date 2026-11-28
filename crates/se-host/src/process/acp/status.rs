//! Join only the exact current protocol owner; stored liveness stays separate.
use super::*;
use se_core::ops::{AcpRuntimeView, AgentRow, AnyOutput};
use se_types::{Page, Read};
impl LaunchCoordinator {
    pub(in crate::process) fn observe_acp_output(
        &self,
        mut output: AnyOutput,
    ) -> Result<AnyOutput> {
        match &mut output {
            AnyOutput::AgentShow(value) => {
                if let Read::Present { value } = &mut value.value.agent {
                    self.observe_acp_row(value);
                }
            }
            AnyOutput::AgentList(value) => {
                value.value.page = self.observe_acp_page(&value.value.page)?
            }
            AnyOutput::ProjectStatus(value) => {
                if let Some(page) = &value.value.agents {
                    value.value.agents = Some(self.observe_acp_page(page)?);
                }
            }
            _ => (),
        }
        Ok(output)
    }
    fn observe_acp_page(&self, page: &Page<AgentRow>) -> Result<Page<AgentRow>> {
        let mut rows = page.items().to_vec();
        for row in &mut rows {
            self.observe_acp_row(row);
        }
        let fields =
            page.window().fields().cloned().ok_or_else(|| {
                error("ACP observed page", "original page accounting unavailable")
            })?;
        Page::fit(rows, fields, page.next().cloned(), |row| {
            row.resume_after.clone()
        })
    }
    fn observe_acp_row(&self, row: &mut AgentRow) {
        if row.provider != se_types::Provider::Acp {
            return;
        }
        let mut found = None;
        let mut context = None;
        let configured = row.provider_settings.context_window;
        let mut read = || -> Result<Read<AcpRuntimeView>> {
            let Some(session) = &row.session.session_id else {
                return Ok(Read::Absent {
                    checked: "This agent has no launched protocol session".into(),
                });
            };
            let job = self
                .jobs
                .0
                .lock()
                .map_err(|_| error("ACP status", "launch registry is poisoned"))?
                .values()
                .find(|job| &job.session == session && job.target.1 == row.id)
                .cloned();
            let Some(job) = job else {
                return Ok(Read::Absent {
                    checked: "This host retains no live protocol connection for this session"
                        .into(),
                });
            };
            if job.settled.load(std::sync::atomic::Ordering::Acquire) {
                return Ok(Read::Absent {
                    checked:
                        "The protocol lifecycle has settled; read saved history for its final outcome"
                            .into(),
                });
            }
            let state = job.state.try_lock().map_err(|_| {
                error(
                    "ACP status",
                    "the original owner is handling an accepted operation; retry status",
                )
            })?;
            found = state.process.clone();
            let Some(binding) = state
                .binding
                .as_ref()
                .and_then(|binding| binding.get::<crate::harness::acp::Binding>())
            else {
                return Ok(Read::Unknown {
                    what: "The original native lifecycle has no initialized protocol connection"
                        .into(),
                });
            };
            context = Some(binding.context(configured)?);
            Ok(Read::Present {
                value: binding.runtime_view()?,
            })
        };
        let runtime = read();
        // A connection that cannot be read has no usage either; the runtime keeps the detail.
        row.merge_context(match (&runtime, context) {
            (_, Some(context)) => context,
            (Ok(Read::Absent { .. }), None) => Read::Absent {
                checked: "No live protocol connection".into(),
            },
            (Err(error), None) => Read::Unreadable {
                source: "protocol token usage".into(),
                reason: error.to_string(),
                error: Some(Box::new(error.body.clone())),
            },
            (Ok(_), None) => Read::Unknown {
                what: "Token usage is not observed on this connection now".into(),
            },
        });
        row.acp_runtime = Some(match runtime {
            Ok(value) => value,
            Err(error) => Read::Unreadable {
                source: "ACP runtime".into(),
                reason: error.to_string(),
                error: Some(Box::new(error.body)),
            },
        });
        row.background = se_agent_observation::background(row.provider, &self.native, found);
    }
}
