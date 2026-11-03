//! Hosted reads share the direct consumer's two-phase observation. Rebuild page
//! accounting after enrichment without changing its keyset or omission facts.
use super::*;
use se_core::ops::AnyOutput;
use se_store::{Scope, Snapshot};
use se_types::{Page, Window};

pub(crate) fn prepare<S: Snapshot>(
    scope: &Scope,
    output: &AnyOutput,
    read: &mut S,
) -> Result<Vec<AgentObservationPlan>> {
    let Scope::Project(project) = scope else {
        return Ok(Vec::new());
    };
    let rows = match output {
        AnyOutput::ProjectStatus(value) => value.value.agents.as_ref().map_or(&[][..], Page::items),
        AnyOutput::AgentList(value) => value.value.page.items(),
        AnyOutput::AgentShow(value) => match &value.value.agent {
            Read::Present { value } => std::slice::from_ref(value),
            _ => &[],
        },
        _ => &[],
    };
    rows.iter()
        .map(|row| prepare_agent_observation(project, row, read))
        .collect()
}

pub(crate) fn observe(
    output: &mut AnyOutput,
    plans: Vec<AgentObservationPlan>,
    deadline: Instant,
) -> Result<()> {
    let mut observations = plans
        .into_iter()
        .map(|plan| observe_agent(plan, deadline))
        .collect::<Result<Vec<_>>>()?
        .into_iter();
    match output {
        AnyOutput::ProjectStatus(value) => {
            if let Some(page) = &mut value.value.agents {
                *page = enrich_page(page, &mut observations)?;
            }
        }
        AnyOutput::AgentList(value) => {
            value.value.page = enrich_page(&value.value.page, &mut observations)?;
        }
        AnyOutput::AgentShow(value) => {
            if let Read::Present { value } = &mut value.value.agent {
                apply(value, &mut observations)?;
            }
        }
        _ => {}
    }
    if observations.next().is_some() {
        return Err(invalid("one observation per original output row"));
    }
    Ok(())
}

fn apply(
    row: &mut AgentRow,
    observations: &mut impl Iterator<Item = AgentObservation>,
) -> Result<()> {
    observations
        .next()
        .ok_or_else(|| invalid("an observation for each original output row"))?
        .apply(row)
}

fn enrich_page(
    page: &Page<AgentRow>,
    observations: &mut impl Iterator<Item = AgentObservation>,
) -> Result<Page<AgentRow>> {
    let mut rows = page.items().to_vec();
    for row in &mut rows {
        apply(row, observations)?;
    }
    let mut fields = page
        .window()
        .fields()
        .cloned()
        .ok_or_else(|| invalid("original store page accounting"))?;
    fields.bytes = serde_json::to_vec(&rows)
        .map_err(|error| invalid(&format!("encodable observed rows: {error}")))?
        .len() as u64;
    if fields.bytes > u64::from(fields.max_bytes.get()) {
        return Err(invalid(
            "observed rows within the original page byte budget; request a smaller page",
        ));
    }
    Page::new(rows, Window::new(fields)?, page.next().cloned())
}
