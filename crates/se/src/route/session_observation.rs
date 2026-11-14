//! Copy finite store facts under the caller's existing snapshot, then observe
//! native processes only after that snapshot has closed.
use se_core::{
    ops::{AgentRow, AnyOutput},
    scope,
};
use se_store::{Admission, Scope, Snapshot};
use se_types::{Page, Read, Result, SeError};

pub(super) struct Prepared {
    output: AnyOutput,
    plans: Vec<se_host::AgentObservationPlan>,
    selected: bool,
    deadline: std::time::Instant,
}
pub(super) fn prepare<S: Snapshot>(
    output: AnyOutput,
    read: &mut S,
    admission: &Admission,
    deadline: std::time::Instant,
) -> Result<Prepared> {
    let rows: Vec<&AgentRow> = match &output {
        AnyOutput::ProjectStatus(value) => value
            .value
            .agents
            .as_ref()
            .map(|page| page.items().iter().collect())
            .unwrap_or_default(),
        AnyOutput::AgentList(value) => value.value.page.items().iter().collect(),
        AnyOutput::AgentShow(value) => match &value.value.agent {
            Read::Present { value } => vec![value],
            _ => vec![],
        },
        _ => {
            return Ok(Prepared {
                output,
                plans: vec![],
                selected: false,
                deadline,
            });
        }
    };
    let mut plans = Vec::with_capacity(rows.len());
    if !rows.is_empty() {
        let Scope::Project(project) = &admission.scope else {
            return Err(scope::unreadable(
                "agent observation project",
                "the selected rows have no admitted project scope",
            ));
        };
        for row in rows {
            plans.push(se_host::prepare_agent_observation(project, row, read)?);
        }
    }
    Ok(Prepared {
        output,
        plans,
        selected: true,
        deadline,
    })
}
pub(super) fn deadline() -> Result<std::time::Instant> {
    std::time::Instant::now()
        .checked_add(super::execute::options().timeout)
        .ok_or_else(|| SeError::invalid("agent observation deadline", "a finite native deadline"))
}
pub(super) fn has_runtime_observation(output: &AnyOutput) -> bool {
    rows(output).iter().any(|row| match row.provider {
        se_types::Provider::Claude | se_types::Provider::Codex => {
            !matches!(&row.provider_activity, Some(Read::Absent { .. }))
        }
        se_types::Provider::Acp => !matches!(&row.acp_runtime, Some(Read::Absent { .. })),
        se_types::Provider::SeCode => {
            matches!(&row.secode_binding, Some(Read::Present { .. }))
        }
    })
}
fn rows(output: &AnyOutput) -> Vec<&AgentRow> {
    match output {
        AnyOutput::AgentShow(value) => match &value.value.agent {
            Read::Present { value } => vec![value],
            _ => vec![],
        },
        AnyOutput::AgentList(value) => value.value.page.items().iter().collect(),
        AnyOutput::ProjectStatus(value) => value
            .value
            .agents
            .as_ref()
            .map(|page| page.items().iter().collect())
            .unwrap_or_default(),
        _ => vec![],
    }
}
/// Preserve the CLI's independent native observation and join only the same
/// session's authenticated runtime facts after its store snapshot has closed.
pub(super) fn merge_runtime_observation(
    mut output: AnyOutput,
    live: Result<AnyOutput>,
) -> Result<AnyOutput> {
    let observed = live.as_ref().map(rows);
    let mut apply = |row: &mut AgentRow| -> Result<()> {
        if matches!(
            row.provider,
            se_types::Provider::Claude | se_types::Provider::Codex
        ) {
            row.provider_activity = Some(match &observed {
                Ok(rows) => rows.iter().find(|other| other.id == row.id && other.session.session_id == row.session.session_id)
                    .and_then(|other| other.provider_activity.clone()).unwrap_or_else(|| Read::Unknown {
                        what: "The owning runtime did not return turn activity for this exact session. Check provider sign-in and saved history before resubmitting input.".into(),
                    }),
                Err(error) => Read::Unreadable {
                    source: "provider turn observation".into(), reason: error.to_string(), error: Some(Box::new(error.body.clone())),
                },
            });
            return Ok(());
        }
        if row.provider == se_types::Provider::Acp {
            row.acp_runtime = Some(match &observed {
                Ok(rows) => rows.iter().find(|other| other.id == row.id && other.session.session_id == row.session.session_id)
                    .and_then(|other| other.acp_runtime.clone()).unwrap_or_else(|| Read::Unknown {
                        what: "The owning host did not return protocol facts for this exact saved session.".into(),
                    }),
                Err(error) => Read::Unreadable {
                    source: "ACP runtime observation".into(), reason: error.to_string(), error: Some(Box::new(error.body.clone())),
                },
            });
            return Ok(());
        }
        if !matches!(&row.secode_binding, Some(Read::Present { .. })) {
            return Ok(());
        }
        row.secode_runtime = Some(match &observed {
            Ok(rows) => rows
                .iter()
                .find(|other| {
                    other.id == row.id && other.session.session_id == row.session.session_id
                })
                .and_then(|other| other.secode_runtime.clone())
                .unwrap_or_else(|| Read::Unknown {
                    what:
                        "The owning host did not return service facts for this exact saved session."
                            .into(),
                }),
            Err(error) => Read::Unreadable {
                source: "SE Code runtime observation".into(),
                reason: error.to_string(),
                error: Some(Box::new(error.body.clone())),
            },
        });
        if matches!(row.secode_runtime, Some(Read::Present { .. }))
            && row.session.state == "stopped"
            && matches!(
                row.session.recorded_state.as_deref(),
                Some("ended" | "revoked")
            )
            && matches!(&row.session.process_state, Read::Present { value } if value == "exited")
            && let Ok(rows) = &observed
            && let Some(other) = rows.iter().find(|other| {
                other.id == row.id && other.session.session_id == row.session.session_id
            })
        {
            row.resume = other.resume.clone();
        }
        Ok(())
    };
    match &mut output {
        AnyOutput::AgentShow(value) => {
            if let Read::Present { value } = &mut value.value.agent {
                apply(value)?;
            }
        }
        AnyOutput::AgentList(value) => enrich_page(&mut value.value.page, &mut apply)?,
        AnyOutput::ProjectStatus(value) => {
            if let Some(page) = &mut value.value.agents {
                enrich_page(page, &mut apply)?;
            }
        }
        _ => (),
    }
    Ok(output)
}
pub(super) fn finish(prepared: Prepared, home: &std::path::Path) -> Result<AnyOutput> {
    let _phase = crate::phase_trace::Phase::new("cli_session_observation");
    let Prepared {
        mut output,
        plans,
        selected,
        deadline,
    } = prepared;
    if !selected {
        return Ok(output);
    }
    let mut observations = plans.into_iter();
    let mut pending = Vec::new();
    let status = matches!(output, AnyOutput::ProjectStatus(_));
    let mut apply = |row: &mut AgentRow| -> Result<()> {
        let plan = observations
            .next()
            .ok_or_else(|| scope::unreadable("agent observation", "prepared row is absent"))?;
        let plan = plan.with_command_home(home);
        let observation = se_host::observe_agent(
            if status {
                plan.with_status_attention()
            } else {
                plan
            },
            deadline,
        )?;
        pending.extend(observation.pending().cloned());
        observation.apply(row)
    };
    match &mut output {
        AnyOutput::ProjectStatus(value) => {
            if let Some(page) = &mut value.value.agents {
                enrich_page(page, &mut apply)?;
            }
            se_core::ops::status::pending_mail(&mut value.value);
            se_host::claude::bell::pending_status(home, &mut value.value);
            value.value.pending.extend(pending);
        }
        AnyOutput::AgentList(value) => enrich_page(&mut value.value.page, &mut apply)?,
        AnyOutput::AgentShow(value) => {
            if let Read::Present { value } = &mut value.value.agent {
                apply(value)?;
            }
        }
        _ => {
            return Err(scope::unreadable(
                "agent observation",
                "prepared output family changed",
            ));
        }
    }
    if observations.next().is_some() {
        return Err(scope::unreadable(
            "agent observation",
            "prepared rows were not all consumed",
        ));
    }
    let bytes = serde_json::to_vec(&output)
        .map_err(|error| scope::unreadable("observed agent response", &error.to_string()))?;
    if bytes.len() > se_host::client::wire::MAX_FRAME_BYTES {
        return Err(SeError::too_large(
            "complete observed agent response",
            se_host::client::wire::MAX_FRAME_BYTES,
            bytes.len(),
        ));
    }
    Ok(output)
}
fn enrich_page(
    page: &mut Page<AgentRow>,
    apply: &mut impl FnMut(&mut AgentRow) -> Result<()>,
) -> Result<()> {
    let mut rows = page.items().to_vec();
    for row in &mut rows {
        apply(row)?;
    }
    let mut fields = page.window().fields().cloned().ok_or_else(|| {
        scope::unreadable(
            "observed agent page",
            "producer response accounting is unavailable",
        )
    })?;
    let bytes = serde_json::to_vec(&rows)
        .map_err(|error| scope::unreadable("observed agent page", &error.to_string()))?
        .len();
    if bytes as u64 > u64::from(fields.max_bytes.get()) {
        return Err(SeError::too_large(
            "complete observed agent page",
            fields.max_bytes.get() as usize,
            bytes,
        ));
    }
    fields.bytes = bytes as u64;
    *page = Page::new(rows, se_types::Window::new(fields)?, page.next().cloned())?;
    Ok(())
}
