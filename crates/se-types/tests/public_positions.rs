use se_types::{
    Checked, Cursor, Omission, OmissionReason, Page, Read, Receipt, Revision, Sequence, Source,
    StopReason, UnixMicros, Window, WindowFields,
};
use serde_json::{Value, json};
use std::{error::Error, num::NonZeroU32};
type Check = Result<(), Box<dyn Error>>;

fn receipt() -> Value {
    json!({"state":"committed", "event_id":"ev_0192f3b5-0000-7000-8000-000000000120",
        "position":"z.commit", "idempotency_key":"probe-key", "value":{"body":"kept"},
        "effects":{"state":"witnessed", "witness":{
            "id":"ev_0192f3b5-0000-7000-8000-000000000121", "position":"a.witness"}}})
}
fn window() -> Result<Window, Box<dyn Error>> {
    Ok(Window::new(WindowFields {
        source: Source::Configuration {
            location: "review fixture".into(),
        },
        from: Sequence::new(4182)?,
        to: Sequence::new(4190)?,
        start_cursor: Some(Cursor::new("c.start")?),
        end_cursor: Some(Cursor::new("c.end")?),
        returned: 1,
        limit: NonZeroU32::MIN,
        bytes: 7,
        max_bytes: NonZeroU32::new(128).ok_or("bytes")?,
        omitted_before: Omission::None,
        omitted_after: Omission::Known {
            count: 1.try_into()?,
            reason: OmissionReason::Limit,
        },
        unreadable: 0,
        stop_reason: StopReason::ItemLimit,
    })?)
}

#[test]
fn receipt_roundtrip_has_opaque_positions_on_commit_and_witness() -> Check {
    for state in ["committed", "replayed"] {
        let mut value = receipt();
        value["state"] = json!(state);
        let parsed: Receipt<Value> = serde_json::from_value(value.clone())?;
        assert_eq!(serde_json::to_value(parsed)?, value);
        assert!(value.get("sequence").is_none());
        assert!(value["effects"]["witness"].get("sequence").is_none());
    }
    let mut numeric = receipt();
    numeric.as_object_mut().ok_or("object")?.remove("position");
    numeric["sequence"] = json!(4182);
    assert!(serde_json::from_value::<Receipt<Value>>(numeric).is_err());
    let schema = serde_json::to_string(&schemars::schema_for!(Receipt<Value>))?;
    assert!(!schema.contains("sequence"));
    Ok(())
}

#[test]
fn witness_cannot_be_its_commit_and_cursor_spelling_is_not_order() -> Check {
    let good: Receipt<Value> = serde_json::from_value(receipt())?;
    good.validate()?; // z.commit precedes a.witness only in store order, not lexical order.
    let mut same_event = receipt();
    same_event["effects"]["witness"]["id"] = same_event["event_id"].clone();
    assert!(serde_json::from_value::<Receipt<Value>>(same_event).is_err());
    let mut same_position = receipt();
    same_position["effects"]["witness"]["position"] = json!("z.commit");
    assert!(serde_json::from_value::<Receipt<Value>>(same_position).is_err());
    Ok(())
}

#[test]
fn real_window_encoder_omits_internal_numeric_accounting() -> Check {
    let original = window()?;
    assert!(original.fields().is_some());
    let value = serde_json::to_value(original)?;
    assert!(value.get("snapshot").is_none());
    assert_eq!(value["from"], "c.start");
    assert_eq!(value["to"], "c.end");
    let bytes = serde_json::to_string(&value)?;
    assert!(!bytes.contains("4182") && !bytes.contains("4190"));
    let schema = serde_json::to_string(&schemars::schema_for!(Window))?;
    assert!(!schema.contains("snapshot") && !schema.contains("Sequence"));
    let decoded: Window = serde_json::from_value(value)?;
    assert!(decoded.fields().is_none());
    assert_eq!(decoded.exit_code(true), 2);
    Ok(())
}

#[test]
fn page_roundtrip_keeps_omission_and_requires_progressing_continuation() -> Check {
    let page = Page::new(vec!["row"], window()?, Some(Cursor::new("c.end")?))?;
    let value = serde_json::to_value(page)?;
    assert_eq!(value["window"]["complete"], false);
    assert_eq!(value["window"]["omitted"]["count"], 1);
    let round: Page<String> = serde_json::from_value(value.clone())?;
    assert_eq!(serde_json::to_value(round)?, value);
    let mut absent_next = value.clone();
    absent_next["next"] = Value::Null;
    assert!(serde_json::from_value::<Page<String>>(absent_next).is_err());
    let mut stalled_next = value.clone();
    stalled_next["next"] = json!("c.start");
    assert!(serde_json::from_value::<Page<String>>(stalled_next).is_err());
    let mut false_complete = value;
    false_complete["window"]["complete"] = json!(true);
    assert!(serde_json::from_value::<Page<String>>(false_complete).is_err());
    Ok(())
}

#[test]
fn checked_and_absent_read_never_render_numeric_store_position() -> Check {
    let checked = Checked {
        source: Source::Configuration {
            location: "review fixture".into(),
        },
        snapshot_to: Some(Cursor::new("c.bound")?),
        observed_at: UnixMicros::new(1)?,
    };
    let mut value = serde_json::to_value(&checked)?;
    assert_eq!(value["snapshot_to"], "c.bound");
    value["snapshot_to"] = json!(4182);
    assert!(serde_json::from_value::<Checked>(value).is_err());
    let output = serde_json::to_string(&Read::<()>::absent(checked))?;
    assert!(output.contains("snapshot c.bound"));
    assert!(!output.contains("4182"));
    Ok(())
}

#[test]
fn revision_runtime_and_generated_schema_agree_at_both_edges() -> Check {
    for value in [json!(0), json!(-1), json!(i64::MAX as u64 + 1)] {
        assert!(serde_json::from_value::<Revision>(value).is_err());
    }
    for value in [1, i64::MAX as u64] {
        let revision: Revision = serde_json::from_value(json!(value))?;
        assert_eq!(revision.get(), value);
        assert_eq!(serde_json::to_value(revision)?, json!(value));
    }
    let schema = serde_json::to_value(schemars::schema_for!(Revision))?;
    assert_eq!(schema["minimum"], 1);
    assert_eq!(schema["maximum"], i64::MAX);
    Ok(())
}
