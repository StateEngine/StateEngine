//! Current authenticated provider reads, separate from retained custody. One
//! unreadable service does not conceal other rows or invent an empty execution.
use super::*;
use se_core::ops::{AgentRow, AnyOutput, SecodeRuntimeView};
use se_harness::secode_process::{Control, QualifiedControl};
use se_types::{Page, Read, Window};
use serde_json::Value;

struct ObservedRuntime {
    view: SecodeRuntimeView,
    resume_ready: bool,
    project: se_types::ProjectId,
}

struct ServiceCustodySnapshot {
    qualified: QualifiedControl,
    initial_sha256: se_types::Sha256,
    resume_proved: bool,
    project: se_types::ProjectId,
}

struct ActiveExecution {
    active: bool,
    execution_id: Read<String>,
}

impl<H: HostPort> Coordinator<'_, H> {
    pub async fn observe_secode_output(
        &self,
        mut output: AnyOutput,
        deadline: &Deadline,
    ) -> Result<AnyOutput> {
        match &mut output {
            AnyOutput::AgentShow(value) => {
                if let Read::Present { value } = &mut value.value.agent {
                    self.observe_secode_row(value, deadline).await;
                }
            }
            AnyOutput::AgentList(value) => {
                value.value.page = self
                    .observe_secode_page(&value.value.page, deadline)
                    .await?;
            }
            AnyOutput::ProjectStatus(value) => {
                if let Some(page) = &value.value.agents {
                    value.value.agents = Some(self.observe_secode_page(page, deadline).await?);
                }
            }
            _ => (),
        }
        Ok(output)
    }
    async fn observe_secode_page(
        &self,
        page: &Page<AgentRow>,
        deadline: &Deadline,
    ) -> Result<Page<AgentRow>> {
        let mut rows = page.items().to_vec();
        for row in &mut rows {
            self.observe_secode_row(row, deadline).await;
        }
        let mut fields = page.window().fields().cloned().ok_or_else(|| {
            error(
                "SE Code observed page",
                "original page accounting unavailable",
            )
        })?;
        fields.bytes = serde_json::to_vec(&rows)
            .map_err(|e| error("SE Code observed page", e))?
            .len() as u64;
        if fields.bytes > u64::from(fields.max_bytes.get()) {
            return Err(error(
                "SE Code observed page",
                "enriched rows exceed the requested byte bound; request a smaller page",
            ));
        }
        Page::new(rows, Window::new(fields)?, page.next().cloned())
    }
    async fn observe_secode_row(&self, row: &mut AgentRow, deadline: &Deadline) {
        if !matches!(&row.secode_binding, Some(Read::Present { .. })) {
            return;
        }
        let observed = self.secode_runtime(row, deadline).await;
        row.secode_runtime = Some(match observed {
            Ok(ObservedRuntime {
                view,
                resume_ready,
                project,
            }) => {
                if resume_ready {
                    let command = se_core::ops::AgentCommand::launch_in_home(
                        &row.id,
                        self.0.home(),
                        &project,
                        false,
                    );
                    row.resume.ready = command.is_some();
                    row.resume.mode = "resume".into();
                    row.resume.reason = command
                        .is_none()
                        .then(|| se_core::ops::AgentCommand::HOME_UNAVAILABLE.into());
                    row.resume.command = command.as_ref().map(|c| c.command.clone());
                    row.resume.argv = command.map(|c| c.argv);
                }
                Read::Present { value: view }
            }
            Err(error) => Read::Unreadable {
                source: "SE Code runtime".into(),
                reason: error.to_string(),
                error: Some(Box::new(error.body)),
            },
        });
    }
    async fn secode_runtime(&self, row: &AgentRow, deadline: &Deadline) -> Result<ObservedRuntime> {
        let retained = match &row.secode_binding {
            Some(Read::Present { value }) => value,
            _ => {
                return Err(error(
                    "SE Code runtime observation",
                    "original retained service binding is unavailable",
                ));
            }
        };
        let custody = self
            .snapshot_secode_custody(row, retained, deadline)
            .await?;
        let control = &custody.qualified.control;
        let session = &retained.session_id;
        let binding = custody.qualified.binding(session, deadline).await?;
        let execution = read_active_execution(control, session, deadline).await?;
        let saved = control.read(&["api", "session", session], deadline).await?;
        let provider = saved
            .pointer("/data/model/providerID")
            .and_then(Value::as_str)
            .ok_or_else(|| error("SE Code actual model", "saved provider absent"))?;
        let model = saved
            .pointer("/data/model/id")
            .and_then(Value::as_str)
            .ok_or_else(|| error("SE Code actual model", "saved model absent"))?;
        let preset = control
            .read(&["api", "session", session, "preset"], deadline)
            .await?;
        let preset = preset
            .pointer("/data/effective")
            .and_then(Value::as_str)
            .ok_or_else(|| error("SE Code actual permissions", "effective preset absent"))?
            .to_owned();
        let pending_permissions = count_pending_permissions(control, session, deadline).await?;
        let receipt = control
            .acceptance(
                &custody.qualified.service,
                session,
                &retained.initial_input_id,
                deadline,
            )
            .await?;
        let initial_input = match receipt.data {
            Some(data) => {
                data.require_initial_hash(session, &retained.initial_input_id, custody.initial_sha256)?;
                Read::Present {
                    value: "accepted; queue admission does not imply model consumption".into(),
                }
            }
            None => Read::Absent {
                checked: "Original input key is absent in this authenticated service incarnation; no replay is authorized.".into(),
            },
        };
        let after = custody.qualified.binding(session, deadline).await?;
        let resume_ready = custody.resume_proved
            && !execution.active
            && matches!(initial_input, Read::Present { .. })
            && binding.require_held().is_ok()
            && after.require_held().is_ok()
            && binding.hold_id == after.hold_id
            && binding.target_id == after.target_id
            && binding.binding == after.binding
            && row.session.state == "stopped"
            && matches!(
                row.session.recorded_state.as_deref(),
                Some("ended" | "revoked")
            )
            && matches!(&row.session.process_state, Read::Present { value } if value == "exited");
        Ok(ObservedRuntime {
            view: SecodeRuntimeView {
                service_state: "live".into(),
                active: execution.active,
                execution_id: execution.execution_id,
                model: format!("{provider}/{model}"),
                permission_preset: preset,
                pending_permissions,
                initial_input,
                output_stream: self.secode_stream(&custody.project, row)?,
            },
            resume_ready,
            project: custody.project,
        })
    }
    async fn snapshot_secode_custody(
        &self,
        row: &AgentRow,
        retained: &se_core::ops::SecodeBindingView,
        deadline: &Deadline,
    ) -> Result<ServiceCustodySnapshot> {
        let services = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline.at()),
            self.0.services().0.lock(),
        )
        .await
        .map_err(|_| error("SE Code runtime observation", "service registry is busy"))?;
        let slot = services
            .iter()
            .find(|((_, agent), _)| agent == &row.id)
            .map(|(_, slot)| slot.clone())
            .ok_or_else(|| {
                error(
                    "SE Code runtime observation",
                    "owning runtime has no matching private service custody",
                )
            })?;
        drop(services);
        let service = lock_service(&slot, deadline).await?;
        if service.journal.vendor_session != retained.session_id
            || service.journal.profile != retained.service_profile
        {
            return Err(error(
                "SE Code runtime observation",
                "retained service binding differs",
            ));
        }
        if service.journal.lost && service.restart.is_none() {
            let next = se_core::ops::AgentCommand::launch_in_home(
                &row.id,
                self.0.home(),
                &service.journal.project,
                true,
            )
            .map(|command| command.command)
            .unwrap_or_else(|| "se launch <agent> --detach".into());
            return Err(error(
                "SE Code service lost",
                format!(
                    "Original native service scope exited; final capture and uncertain input remain unproved. Preserve the original history and start a different conversation with {next}."
                ),
            ));
        }
        if let Some(failure) = service
            .failure
            .as_ref()
            .or(service.capability_failure.as_ref())
        {
            return Err(error("SE Code runtime observation", failure));
        }
        self.observe_secode_birth(&service, deadline).await?;
        Ok(ServiceCustodySnapshot {
            qualified: service.current()?,
            initial_sha256: service.journal.initial_sha256,
            resume_proved: service.journal.input_free_resume
                && service
                    .journal
                    .client_closed
                    .as_ref()
                    .is_some_and(|closed| closed.capture_complete)
                && service.journal.notice.is_none()
                && service
                    .journal
                    .resume_release
                    .as_ref()
                    .is_none_or(|release| release.completed),
            project: service.journal.project.clone(),
        })
    }
    fn secode_stream(&self, project: &se_types::ProjectId, row: &AgentRow) -> Result<Read<String>> {
        self.0.observe_client_stream(project, &row.id)
    }
}

async fn read_active_execution(
    control: &Control,
    session_id: &str,
    deadline: &Deadline,
) -> Result<ActiveExecution> {
    let active = control
        .read(&["api", "session", "active"], deadline)
        .await?;
    let active = active["data"]
        .as_object()
        .ok_or_else(|| error("SE Code active executions", "complete session map absent"))?;
    let current = active.get(session_id);
    let execution_id = match current {
        None => Read::Absent {
            checked: "Session absent from the complete authenticated active-execution map.".into(),
        },
        Some(value) => match value.get("executionID").and_then(Value::as_str) {
            Some(value) => Read::Present {
                value: value.to_owned(),
            },
            None => Read::Unknown {
                what: "Session is active but its execution ID is unavailable.".into(),
            },
        },
    };
    Ok(ActiveExecution {
        active: current.is_some(),
        execution_id,
    })
}

async fn count_pending_permissions(
    control: &Control,
    session_id: &str,
    deadline: &Deadline,
) -> Result<u64> {
    let permissions = control
        .read(&["api", "session", session_id, "permission"], deadline)
        .await?;
    if permissions["hasMore"] != false {
        return Err(error(
            "SE Code pending permissions",
            "permission inventory is incomplete",
        ));
    }
    let permissions = permissions["data"].as_array().ok_or_else(|| {
        error(
            "SE Code pending permissions",
            "complete permissions array absent",
        )
    })?;
    let mut pending_permissions = 0;
    for permission in permissions {
        match permission.get("status").and_then(Value::as_str) {
            Some("pending") => pending_permissions += 1,
            Some("suspended") => {
                return Err(error(
                    "SE Code pending permissions",
                    "a permission is suspended; its outcome remains unproved",
                ));
            }
            Some("approved" | "denied" | "rejected" | "replied") => (),
            _ => {
                return Err(error(
                    "SE Code pending permissions",
                    "permission status absent or unsupported",
                ));
            }
        }
    }
    Ok(pending_permissions)
}
