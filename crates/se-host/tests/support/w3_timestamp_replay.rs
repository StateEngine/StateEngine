//! Bug: retrying one native turn with a later observation timestamp must not
//! create another capture source, turn or cursor, even across a millisecond.
use super::*;

fn captured(role: api::TurnRole, occurred_at: u64, key: &str) -> api::CapturedTurn {
    let text = "timestamp replay: café π";
    api::CapturedTurn {
        conversation: api::ProviderSessionId("conv-timestamp-replay".into()),
        vendor_turn: "native-timestamp-turn".into(),
        vendor_event: Some("evt-native-timestamp-turn".into()),
        machine_id: None,
        source_ref: Some("secode-event:native-timestamp-turn".into()),
        source_cli: "secode".into(),
        nesting: None,
        role,
        occurred_at: api::UnixMicros(occurred_at),
        content: api::BoundedText {
            text: text.into(),
            utf8_bytes: text.len() as u64,
            complete: true,
            omitted_bytes: Some(0),
        },
        source_sha256: api::Sha256(Sha256::digest(text.as_bytes()).into()),
        idempotency_key: api::IdempotencyKey(key.into()),
    }
}

fn check(role: api::TurnRole, offset: u64) {
    let mut judge = Judge::new("timestamp-replay").required();
    judge.retain = true;
    let opened = judge.open().required();
    let generation = judge.activate(&opened).required();
    let host = opened.host.clone();
    let issued = judge
        .bind(&host, generation, "conv-timestamp-replay", "timestamp-bind")
        .required();
    let timestamp = 1_700_000_001_000_000;
    let first = judge
        .capture_with(
            &host,
            &issued.session,
            generation,
            captured(role, timestamp, "timestamp-original"),
        )
        .required();
    let (first_commit, first_event) = committed_value(first, "first timestamp capture").required();
    let head_before = witness(&judge, generation.0, |snapshot| {
        Ok::<_, String>(snapshot.info().head)
    })
    .required();
    let replay = judge.capture_with(
        &host,
        &issued.session,
        generation,
        captured(role, timestamp + offset, "timestamp-retry-new-key"),
    );
    let head_after = witness(&judge, generation.0, |snapshot| {
        Ok::<_, String>(snapshot.info().head)
    })
    .required();
    let rows = turn_rows(&judge, generation.0).required();
    // Release the actual host and lease before asserting the counterexample.
    // A failing assertion retains the fixture for outside readback.
    judge.drain_close(&host, generation).required();
    drop(host);
    drop(opened);

    let replay_event = match &replay {
        Ok(api::Receipt::Committed { commit }) => Some(commit.value.id.0.clone()),
        Ok(api::Receipt::Replayed { original }) => Some(original.value.id.0.clone()),
        _ => None,
    };
    std::fs::write(
        judge.root.join("timestamp-observation.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "project": judge.project, "agent": judge.agent, "offset_us": offset,
            "first_event": first_event.id.0, "replay_event": replay_event,
            "turn_count": rows.len(), "text": "timestamp replay: café π",
            "head_before": format!("{head_before:?}"),
            "head_after": format!("{head_after:?}")
        }))
        .required(),
    )
    .required();

    eprintln!(
        "timestamp replay offset={offset}us turns={} head_before={head_before:?} head_after={head_after:?} receipt={replay:?}",
        rows.len()
    );

    assert_eq!(
        head_after, head_before,
        "same native turn at offset {offset}us must append zero events (including source and cursor)"
    );
    let (commit, event) =
        replayed_value(replay.required(), "timestamp-independent natural replay").required();
    assert_eq!(event, first_event, "replay preserves the original turn ID");
    assert_eq!(
        commit.event, first_commit.event,
        "replay preserves the original event position"
    );
    assert_eq!(rows.len(), 1, "exactly one native turn remains");
    assert_eq!(rows[0].header.event.to_string(), first_event.id.0);
}

/// Protects: native capture retries deduplicate independently of sub-millisecond observation jitter.
#[test]
fn same_millisecond_user_replay_preserves_original_receipt_and_head() {
    check(api::TurnRole::User, 1);
}

/// Protects: native capture retries do not create another source when observation crosses a millisecond.
#[test]
fn later_millisecond_user_replay_preserves_original_receipt_and_head() {
    check(api::TurnRole::User, 1_000);
}

/// Protects: the assistant capture mirror preserves the original natural turn across later timestamps.
#[test]
fn later_second_assistant_replay_preserves_original_receipt_and_head() {
    check(api::TurnRole::Assistant, 1_000_000);
}
