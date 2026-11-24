//! Reviewer judge: an ACP row's state follows its protocol observation in the
//! same precedence as provider turn activity, and an unobserved ACP session
//! is never claimed idle or working.
use se_core::ops::{AnyOutput, agent_state::settle};
use se_types::{AgentId, MessageId, Read};
use serde_json::{Value, json};

type Check = Result<(), Box<dyn std::error::Error>>;
type Built<T> = Result<T, Box<dyn std::error::Error>>;

const PHASE: &str = "2026-11-21T09:00:00.000000Z";
const ASKED: &str = "2026-11-21T09:06:00.000000Z";
const ASKED_US: i64 = 1_795_251_960_000_000;
const NOW_US: i64 = ASKED_US + 90 * 1_000_000;

struct Facts {
    session: &'static str,
    provider: &'static str,
    acp: Option<Value>,
    question: bool,
    background: bool,
}
impl Facts {
    fn acp(session: &'static str, acp: Option<Value>) -> Self {
        Self {
            session,
            provider: "acp",
            acp,
            question: false,
            background: false,
        }
    }
}

fn row(facts: &Facts) -> Built<Value> {
    let waiting = facts.question.then(|| {
        json!({
            "message_id": MessageId::from_parts(1, [2; 10]).map(|m| m.to_string()).unwrap_or_default(),
            "to": "Lead",
            "asked_at": ASKED,
            "asked_at_us": ASKED_US,
        })
    });
    let mut row = json!({
        "id": AgentId::from_parts(1, [1; 10])?.to_string(),
        "name": "Worker",
        "role": null,
        "provider": facts.provider,
        "model": null,
        "profile": "default",
        "session": {
            "state": facts.session,
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
    if let Some(acp) = &facts.acp {
        row["acp_runtime"] = acp.clone();
    }
    if facts.background {
        row["background"] = serde_json::to_value(Read::Present {
            value: json!({
                "processes": 1,
                "oldest": {
                    "command": "synthetic-build",
                    "started_at": "2026-11-21T09:05:00.000000Z",
                    "started_at_us": ASKED_US - 60 * 1_000_000,
                },
            }),
        })?;
    }
    Ok(row)
}

/// A present protocol observation, optionally with the time its phase began.
fn observed(activity: &str, phase: bool) -> Value {
    let mut value = json!({
        "activity": activity,
        "mode": null,
        "last_permission_refusal": null,
        "provisional_reply": null,
        "failure": null,
    });
    if phase {
        value["phase_started_at"] = json!(PHASE);
        value["phase_seconds"] = json!(42);
    }
    serde_json::to_value(Read::Present { value }).unwrap_or(Value::Null)
}

fn absent() -> Value {
    serde_json::to_value(Read::<Value>::Absent {
        checked: "The protocol lifecycle has settled".into(),
    })
    .unwrap_or(Value::Null)
}

fn unknown() -> Value {
    serde_json::to_value(Read::<Value>::Unknown {
        what: "The owning host did not return protocol facts".into(),
    })
    .unwrap_or(Value::Null)
}

fn unreadable() -> Value {
    serde_json::to_value(Read::<Value>::Unreadable {
        source: "ACP runtime observation".into(),
        reason: "synthetic unreadable observation".into(),
        error: None,
    })
    .unwrap_or(Value::Null)
}

/// Settle one row as `agent.show` output and return its state object.
fn settled(facts: &Facts) -> Built<Value> {
    settled_row(row(facts)?)
}

fn settled_row(row: Value) -> Built<Value> {
    let row: se_core::ops::AgentRow = serde_json::from_value(row)?;
    let agent = serde_json::to_value(Read::Present { value: row })?;
    let envelope = serde_json::from_value(json!({"schema": "se.agent-status.v1", "agent": agent}))?;
    let mut output = AnyOutput::AgentShow(envelope);
    settle(&mut output, NOW_US)?;
    let once = serde_json::to_value(&output)?;
    settle(&mut output, NOW_US)?;
    assert_eq!(
        serde_json::to_value(&output)?,
        once,
        "settling twice changes nothing"
    );
    let AnyOutput::AgentShow(envelope) = output else {
        return Err("output changed kind".into());
    };
    let Read::Present { value } = envelope.value.agent else {
        return Err("agent row vanished".into());
    };
    Ok(serde_json::to_value(
        value.state.ok_or("state not settled")?,
    )?)
}

/// Each observed protocol activity maps to the state an operator acts on, and
/// a turn's time comes from the protocol phase that set it.
#[test]
fn observed_protocol_activity_sets_the_row_state_and_its_time() -> Check {
    for (activity, expected) in [
        ("working", "working"),
        ("cancelling", "working"),
        ("idle", "idle"),
        ("failed", "attention"),
    ] {
        let state = settled(&Facts::acp("running", Some(observed(activity, true))))?;
        assert_eq!(state["state"], expected, "ACP activity {activity}");
        assert_eq!(state["since"], PHASE, "ACP activity {activity}");
        assert_eq!(state["elapsed_seconds"], 42, "ACP activity {activity}");
    }
    // A fresh connection has observed no turn yet: idle, with no invented time.
    let fresh = settled(&Facts::acp("running", Some(observed("idle", false))))?;
    assert_eq!(fresh["state"], "idle");
    assert!(
        fresh["since"].is_null() && fresh["elapsed_seconds"].is_null(),
        "no phase, no time: {fresh}"
    );
    Ok(())
}

/// No protocol observation, a settled lifecycle and an unreturned one are all
/// unobserved: alive, but never claimed idle or working.
#[test]
fn an_unobserved_protocol_session_is_not_claimed_idle_or_working() -> Check {
    for (label, acp) in [
        ("none", None),
        ("absent", Some(absent())),
        ("unknown", Some(unknown())),
    ] {
        let state = settled(&Facts::acp("running", acp))?;
        assert_eq!(state["state"], "running", "unobserved ({label})");
        assert!(
            state["since"].is_null() && state["elapsed_seconds"].is_null(),
            "unobserved ({label}) invented a time: {state}"
        );
    }
    // An observation that could not be read is not an absent one.
    let unreadable = settled(&Facts::acp("running", Some(unreadable())))?;
    assert_eq!(unreadable["state"], "turn-unreadable");
    Ok(())
}

/// The protocol observation slots into the existing precedence: lifecycle
/// first, then turn attention, an open question, background work, then idle.
#[test]
fn protocol_activity_keeps_the_documented_precedence() -> Check {
    for session in ["stopped", "starting", "stopping"] {
        let state = settled(&Facts::acp(session, Some(observed("working", true))))?;
        assert_eq!(state["state"], session, "{session}");
    }
    let mut asked = Facts::acp("running", Some(observed("idle", true)));
    asked.question = true;
    let blocked = settled(&asked)?;
    assert_eq!(blocked["state"], "blocked");
    assert_eq!(blocked["since"], ASKED);
    // A turn that needs attention outranks the open question it may have caused.
    asked.acp = Some(observed("failed", true));
    assert_eq!(settled(&asked)?["state"], "attention");
    // A working turn outranks the open question too.
    asked.acp = Some(observed("working", true));
    assert_eq!(settled(&asked)?["state"], "working");

    let mut busy = Facts::acp("running", Some(observed("idle", true)));
    busy.background = true;
    let background = settled(&busy)?;
    assert_eq!(background["state"], "background");
    assert_eq!(background["since"], "2026-11-21T09:05:00.000000Z");
    assert_eq!(background["elapsed_seconds"], 150);
    // Background processes never make an unobserved session look idle.
    busy.acp = None;
    assert_eq!(settled(&busy)?["state"], "running");
    Ok(())
}

/// A Claude or Codex row keeps reading its own turn activity first: a protocol
/// fact on the same row cannot change that row's state.
#[test]
fn provider_turn_activity_keeps_precedence_over_protocol_facts() -> Check {
    let mut codex = Facts::acp("running", Some(observed("working", true)));
    codex.provider = "codex";
    let mut built = row(&codex)?;
    built["provider_activity"] = serde_json::to_value(Read::Present {
        value: json!({
            "activity": "turn-completed",
            "detail": "observed",
            "quiet_seconds": null,
            "phase_started_at": "2026-11-21T09:07:00.000000Z",
            "phase_seconds": 7,
            "next_step": null,
        }),
    })?;
    let state = settled_row(built)?;
    assert_eq!(state["state"], "idle");
    assert_eq!(state["since"], "2026-11-21T09:07:00.000000Z");
    assert_eq!(state["elapsed_seconds"], 7);
    Ok(())
}
