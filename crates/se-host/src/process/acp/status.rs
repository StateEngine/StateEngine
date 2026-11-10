//! Join only the exact current protocol owner; stored liveness stays separate.
use super::*;
use se_core::ops::{AcpReplyPreview, AcpRuntimeView, AgentRow, AnyOutput};
use se_types::{Page, Read, Window};
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
        let mut fields =
            page.window().fields().cloned().ok_or_else(|| {
                error("ACP observed page", "original page accounting unavailable")
            })?;
        fields.bytes = serde_json::to_vec(&rows)
            .map_err(|e| error("ACP observed page", e))?
            .len() as u64;
        if fields.bytes > u64::from(fields.max_bytes.get()) {
            return Err(error(
                "ACP observed page",
                "enriched rows exceed the requested byte bound; request a smaller page",
            ));
        }
        Page::new(rows, Window::new(fields)?, page.next().cloned())
    }
    fn observe_acp_row(&self, row: &mut AgentRow) {
        if row.provider != se_types::Provider::Acp {
            return;
        }
        let read = || -> Result<Read<AcpRuntimeView>> {
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
                .find(|job| &job.session == session)
                .cloned();
            let Some(job) = job else {
                return Ok(Read::Absent {
                    checked: "This host retains no live protocol connection for this session"
                        .into(),
                });
            };
            let state = job.state.try_lock().map_err(|_| {
                error(
                    "ACP status",
                    "the original owner is handling an accepted operation; retry status",
                )
            })?;
            let Some(binding) = state
                .binding
                .as_ref()
                .and_then(|binding| binding.acp.as_ref())
            else {
                return Ok(Read::Unknown {
                    what: "The original native lifecycle has no initialized protocol connection"
                        .into(),
                });
            };
            let observed = binding.session.observe()?;
            Ok(Read::Present {
                value: AcpRuntimeView {
                    activity: if observed.failure.is_some() {
                        "failed"
                    } else if observed.cancelling {
                        "cancelling"
                    } else if observed.active_input.is_some() {
                        "working"
                    } else {
                        "idle"
                    }
                    .into(),
                    mode: observed.current_mode,
                    last_permission_refusal: observed.permission_refusal.map(|v| v.reason.into()),
                    provisional_reply: observed.provisional_text.map(|v| AcpReplyPreview {
                        text: v.text,
                        total_bytes: v.total_bytes,
                        omitted_bytes: v.omitted_bytes,
                    }),
                    failure: observed.failure,
                },
            })
        };
        row.acp_runtime = Some(match read() {
            Ok(value) => value,
            Err(error) => Read::Unreadable {
                source: "ACP runtime".into(),
                reason: error.to_string(),
                error: Some(Box::new(error.body)),
            },
        });
    }
}
