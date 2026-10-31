use se_types::{
    Checked, Cursor, EventId, Omission, OmissionReason, Page, Read, Receipt, Revision, Sequence,
    Source, StopReason, UnixMicros, Window, WindowFields,
};
use serde_json::json;
use std::{error::Error, num::NonZeroU32};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn page_wire_keeps_cursors_and_omissions_without_internal_snapshot() -> TestResult {
    let window = Window::new(WindowFields {
        source: Source::Configuration {
            location: "config.toml".into(),
        },
        from: Sequence::new(100)?,
        to: Sequence::new(200)?,
        start_cursor: Some(Cursor::new("c1.start")?),
        end_cursor: Some(Cursor::new("c1.end")?),
        returned: 1,
        limit: NonZeroU32::MIN,
        bytes: 32,
        max_bytes: NonZeroU32::new(128).ok_or("invalid test byte limit")?,
        omitted_before: Omission::None,
        omitted_after: Omission::Known {
            count: 1.try_into()?,
            reason: OmissionReason::Limit,
        },
        unreadable: 0,
        stop_reason: StopReason::ItemLimit,
    })?;
    assert!(window.fields().is_some());
    let page = Page::new(vec!["row"], window, Some(Cursor::new("c1.end")?))?;
    let value = serde_json::to_value(page)?;
    assert_eq!(
        value,
        json!({"items":["row"],"window":{"from":"c1.start","to":"c1.end",
            "limit":1,"complete":false,"omitted":{"count":1,"reason":"limit"}},
            "next":"c1.end"})
    );
    let decoded: Page<String> = serde_json::from_value(value.clone())?;
    assert!(decoded.window().fields().is_none());
    assert_eq!(decoded.window().exit_code(true), 2);
    assert_eq!(serde_json::to_value(decoded)?, value);
    let mut missing_continuation = value.clone();
    missing_continuation["next"] = json!(null);
    assert!(serde_json::from_value::<Page<String>>(missing_continuation).is_err());
    let mut false_complete = value;
    false_complete["window"]["complete"] = json!(true);
    assert!(serde_json::from_value::<Page<String>>(false_complete).is_err());
    let schema = serde_json::to_value(schemars::schema_for!(Window))?;
    assert!(schema["properties"].get("snapshot").is_none());
    assert!(schema.to_string().find("Sequence").is_none());
    Ok(())
}

#[test]
fn checked_read_uses_an_opaque_cursor() -> TestResult {
    let checked = Checked {
        source: Source::Configuration {
            location: "config.toml".into(),
        },
        snapshot_to: Some(Cursor::new("s1.bound")?),
        observed_at: UnixMicros::new(0)?,
    };
    let value = serde_json::to_value(&checked)?;
    assert_eq!(value["snapshot_to"], "s1.bound");
    let mut numeric = value;
    numeric["snapshot_to"] = json!(200);
    assert!(serde_json::from_value::<Checked>(numeric).is_err());
    let absent = serde_json::to_value(Read::<()>::absent(checked))?;
    assert!(
        absent["checked"]
            .as_str()
            .ok_or("missing checked text")?
            .contains("snapshot s1.bound")
    );
    Ok(())
}

#[test]
fn receipt_positions_are_opaque_and_replay_keeps_the_original() -> TestResult {
    let event = EventId::from_parts(1, [0; 10])?;
    let witness = EventId::from_parts(2, [0; 10])?;
    let value = json!({"state":"replayed","event_id":event,"position":"z.commit",
        "idempotency_key":"request-1","value":"original",
        "effects":{"state":"witnessed","witness":{"id":witness,"position":"a.witness"}}});
    let receipt: Receipt<String> = serde_json::from_value(value.clone())?;
    assert_eq!(
        receipt.committed_value().map(String::as_str),
        Some("original")
    );
    assert_eq!(serde_json::to_value(receipt)?, value);
    let mut self_witness = value.clone();
    self_witness["effects"]["witness"]["id"] = json!(event);
    assert!(serde_json::from_value::<Receipt<String>>(self_witness).is_err());
    let mut same_position = value.clone();
    same_position["effects"]["witness"]["position"] = json!("z.commit");
    assert!(serde_json::from_value::<Receipt<String>>(same_position).is_err());
    let mut old_sequence = value;
    old_sequence
        .as_object_mut()
        .ok_or("receipt must be an object")?
        .remove("position");
    old_sequence["sequence"] = json!(1);
    assert!(serde_json::from_value::<Receipt<String>>(old_sequence).is_err());
    let schema = serde_json::to_value(schemars::schema_for!(Receipt<String>))?;
    assert!(!schema.to_string().contains("sequence"));
    Ok(())
}

#[test]
fn entity_revision_is_positive_and_fits_the_store_counter() -> TestResult {
    assert!(Revision::new(0).is_err());
    assert!(serde_json::from_value::<Revision>(json!(0)).is_err());
    assert!(Revision::new(i64::MAX as u64 + 1).is_err());
    let first: Revision = serde_json::from_value(json!(1))?;
    assert_eq!(first.get(), 1);
    assert_eq!(serde_json::to_value(first)?, json!(1));
    assert_eq!(Revision::new(i64::MAX as u64)?.get(), i64::MAX as u64);
    let schema = serde_json::to_value(schemars::schema_for!(Revision))?;
    assert_eq!(schema["minimum"], 1);
    assert_eq!(schema["maximum"], i64::MAX);
    Ok(())
}
