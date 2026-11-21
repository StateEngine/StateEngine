//! Reviewer judge: each status row's state follows the observed facts in the
//! documented precedence, and settling twice gives the same answer.
use se_core::ops::{AnyOutput, agent_state::settle};
use se_types::{AgentId, MessageId};
use serde_json::{Value, json};

type Check = Result<(), Box<dyn std::error::Error>>;

const ASKED: &str = "2026-11-21T09:06:00.000000Z";
const ASKED_US: i64 = 1_795_251_960_000_000;

fn row(
    session: &str,
    activity: Option<Value>,
    question: bool,
) -> Result<Value, Box<dyn std::error::Error>> {
    let waiting = question.then(|| {
        json!({
            "message_id": MessageId::from_parts(1, [2; 10]).map(|m| m.to_string()).unwrap_or_default(),
            "to": "Lead",
            "asked_at": ASKED,
        })
    });
    let mut row = json!({
        "id": AgentId::from_parts(1, [1; 10])?.to_string(),
        "name": "Worker",
        "role": null,
        "provider": "codex",
        "model": null,
        "profile": "default",
        "session": {
            "state": session,
            "recorded_state": null,
            "session_id": null,
            "launch_id": null,
            "surface": null,
            "process": null,
            "since": null,
            "observed_at": null,
            "containment": null,
            "containment_cause": null,
        },
        "conversation": {"id": null, "state": "none"},
        "resume": {"ready": false, "mode": "none", "reason": null, "command": null, "argv": null},
        "unread": 0,
        "last_activity_at": null,
        "state": {"state": "unknown", "since": null, "elapsed_seconds": null, "waiting_on": waiting},
    });
    let transcript = serde_json::to_value(se_core::ops::transcript::View::default())?;
    if let (Some(session), Some(fields)) = (row["session"].as_object_mut(), transcript.as_object())
    {
        session.extend(fields.clone());
    }
    if let Some(activity) = activity {
        row["provider_activity"] = activity;
    }
    Ok(row)
}

fn activity(kind: &str) -> Value {
    serde_json::to_value(se_types::Read::Present {
        value: json!({
            "activity": kind,
            "detail": "observed",
            "quiet_seconds": null,
            "phase_started_at": "2026-11-21T09:00:00.000000Z",
            "phase_seconds": 42,
            "next_step": null,
        }),
    })
    .unwrap_or(Value::Null)
}

/// Settle one row as `agent.show` output and return its state object.
fn settled(row: Value, now_us: i64) -> Result<Value, Box<dyn std::error::Error>> {
    let row: se_core::ops::AgentRow = serde_json::from_value(row)?;
    let agent = serde_json::to_value(se_types::Read::Present { value: row })?;
    let envelope = serde_json::from_value(json!({"schema": "se.agent-status.v1", "agent": agent}))?;
    let mut output = AnyOutput::AgentShow(envelope);
    settle(&mut output, now_us)?;
    let once = serde_json::to_value(&output)?;
    settle(&mut output, now_us)?;
    assert_eq!(
        serde_json::to_value(&output)?,
        once,
        "settling twice changes nothing"
    );
    let AnyOutput::AgentShow(envelope) = output else {
        return Err("output changed kind".into());
    };
    let se_types::Read::Present { value } = envelope.value.agent else {
        return Err("agent row vanished".into());
    };
    Ok(serde_json::to_value(
        value.state.ok_or("state not settled")?,
    )?)
}

#[test]
fn state_follows_observed_facts_in_precedence() -> Check {
    let now = ASKED_US + 90 * 1_000_000;
    let cases = [
        ("never-launched", None, false, "stopped"),
        (
            "stopped",
            Some(activity("awaiting-provider")),
            true,
            "stopped",
        ),
        ("starting", None, false, "starting"),
        (
            "stopping",
            Some(activity("turn-completed")),
            false,
            "stopping",
        ),
        ("lost", None, false, "unreachable"),
        (
            "unknown",
            Some(activity("awaiting-provider")),
            true,
            "unreachable",
        ),
        (
            "running",
            Some(activity("awaiting-provider")),
            true,
            "working",
        ),
        ("running", Some(activity("failed")), true, "attention"),
        (
            "running",
            Some(activity("authentication-required")),
            false,
            "attention",
        ),
        ("running", Some(activity("turn-completed")), true, "blocked"),
        ("running", None, true, "blocked"),
        ("running", Some(activity("turn-completed")), false, "idle"),
        ("running", None, false, "running"),
    ];
    for (session, observed, question, expected) in cases {
        let state = settled(row(session, observed.clone(), question)?, now)?;
        assert_eq!(
            state["state"], expected,
            "session {session}, activity {observed:?}, open question {question}"
        );
    }
    Ok(())
}

#[test]
fn since_and_elapsed_come_from_the_fact_that_set_the_state() -> Check {
    let now = ASKED_US + 90 * 1_000_000;
    let working = settled(
        row("running", Some(activity("awaiting-provider")), false)?,
        now,
    )?;
    assert_eq!(working["since"], "2026-11-21T09:00:00.000000Z");
    assert_eq!(working["elapsed_seconds"], 42);
    let blocked = settled(row("running", None, true)?, now)?;
    assert_eq!(blocked["since"], ASKED);
    assert_eq!(
        blocked["elapsed_seconds"], 90,
        "elapsed counts from when the question was asked"
    );
    assert_eq!(blocked["waiting_on"]["to"], "Lead");
    let running = settled(row("running", None, false)?, now)?;
    assert!(
        running["since"].is_null() && running["elapsed_seconds"].is_null(),
        "no fact, no time: {running}"
    );
    Ok(())
}
