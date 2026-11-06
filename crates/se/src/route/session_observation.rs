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
pub(super) fn finish(prepared: Prepared, home: &std::path::Path) -> Result<AnyOutput> {
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
