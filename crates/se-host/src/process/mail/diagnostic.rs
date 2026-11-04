//! A mail-specific host-log record, separate from native cleanup state.
//! Durable notice/message rows remain pending; this diagnostic claims no delivery.
use super::*;

pub(in crate::process) fn report(work: &owned::Work, failure: &se_types::SeError) {
    let flight = work.mail.flight.as_ref();
    eprintln!(
        "{}",
        serde_json::json!({
            "diagnostic":"mail.delivery-pending",
            "project":work.meta.project.id,
            "agent":work.meta.agent.id,
            "session":work.meta.session,
            "notice":flight.map(|value|&value.reservation.notice_id),
            "effect":flight.map(|value|value.reservation.effect_id),
            "transport_outcome":if flight.is_some_and(|value|value.evidence.is_none()) {"uncertain"} else {"no delivery confirmed"},
            "error":failure.body,
            "next_step":if flight.is_some_and(|value|value.evidence.is_none()) {"Stop/relaunch the binding before another transport attempt."} else {"Pending mail may retry on the next recipient event; inspect this failure before retrying."},
        })
    );
}
