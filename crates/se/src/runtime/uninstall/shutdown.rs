//! Installation removal reuses public down and keeps its verified stop facts.
use crate::{bootstrap::Bootstrap, route};
use se_core::{ops::*, scope};
use se_types::{Detail, IdempotencyKey, Result, SeError, details};
use std::io;

pub(super) fn execute(
    cx: &Bootstrap,
    key: &IdempotencyKey,
    diagnostic: &mut dyn FnMut(&str) -> io::Result<()>,
) -> Result<Vec<StopFact>> {
    if matches!(
        route::setup::inspect(&cx.home, super::clock())?,
        route::setup::Setup::Absent(_)
    ) {
        diagnostic("Uninstall: no initialized runtime store; no runtime shutdown required.\n")
            .map_err(|e| scope::unreadable("uninstall shutdown diagnostic", &e.to_string()))?;
        return Ok(Vec::new());
    }
    diagnostic("Uninstall: stop this home's runtime with ordinary se down; installation removal waits for verified shutdown.\n")
        .map_err(|e| scope::unreadable("uninstall shutdown diagnostic", &e.to_string()))?;
    let stopped = route::execute::dispatch(
        cx,
        AnyOp::RuntimeDown(RuntimeDown {
            idempotency_key: key.clone(),
        }),
        diagnostic,
    )
    .map_err(|error| {
        refusal(format!("Ordinary runtime shutdown failed: {error}")).with_cause(error)
    })?;
    let AnyOutput::RuntimeDown(report) = &stopped else {
        return Err(refusal(
            "Ordinary down returned an unexpected result".into(),
        ));
    };
    let mut rendered = Vec::new();
    crate::render::output(&stopped, false, false, &mut rendered)
        .map_err(|e| scope::unreadable("uninstall shutdown result", &e.to_string()))?;
    let rendered = String::from_utf8(rendered)
        .map_err(|e| scope::unreadable("uninstall shutdown result", &e.to_string()))?;
    diagnostic(&rendered)
        .map_err(|e| scope::unreadable("uninstall shutdown diagnostic", &e.to_string()))?;
    if !report.value.complete
        || report.value.witness.state != WitnessState::Witnessed
        || report
            .value
            .stops
            .iter()
            .any(|stop| !stop.complete || stop.witness.state != WitnessState::Witnessed)
    {
        return Err(refusal(format!(
            "Ordinary runtime shutdown remains unverified: {rendered}"
        )));
    }
    Ok(report.value.stops.clone())
}

fn refusal(reason: String) -> SeError {
    SeError::new(Detail::StateConflict(details::StateConflict {
        subject: "uninstall runtime shutdown".into(),
        reason,
        next_step: "Installation files, its record and PATH were retained. Resolve the named shutdown failure with se status or se stop using this same --home, then retry se uninstall; retained history, conversations and credentials remain available.".into(),
    }))
}
