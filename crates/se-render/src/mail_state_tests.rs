use super::output;
use se_core::ops::{AnyOp, AnyOutput, MetaSchema, metadata_output};
use serde_json::{Value, json};

type Check = Result<(), Box<dyn std::error::Error>>;
const MESSAGE: &str = "msg_0192f3b0-0000-7000-8000-000000000101";
const EVENT: &str = "ev_0192f3b0-0000-7000-8000-000000000102";

fn actor() -> Value {
    json!({"kind":"agent","id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"Reader"})
}
fn row(delivery: &str, disposition: &str) -> Value {
    json!({"id":MESSAGE,"event_id":EVENT,"from":actor(),"to":actor(),
        "kind":"handoff","sent_at":"2026-01-01T00:00:00Z","reply_to":null,"refs":[],
        "delivery":{"state":delivery,"at":null},"disposition":{"state":disposition,"at":null},
        "notification":{"intent":"direct","recipients":[]},
        "body":{"text":"A reply is separate mail.","complete":true,"bytes":25,"command":null,"argv":null},"unreadable":null})
}
fn read(
    delivery: &str,
    disposition: &str,
    inspection: bool,
) -> Result<AnyOutput, serde_json::Error> {
    serde_json::from_value(
        json!({"schema":"se.message-read/v1","message":row(delivery,disposition),
        "marked_read":!inspection,"inspection":inspection}),
    )
}
fn page(delivery: &str, disposition: &str) -> Result<AnyOutput, serde_json::Error> {
    serde_json::from_value(
        json!({"schema":"se.message-page/v1","consistency":"live-keyset",
        "view":{"op":"list","recipient":actor(),"disposition":"all","box":"inbox",
            "filter":{"to":null,"from":null,"kind":null},"inspection":true,"full":true,"scope":"project"},
        "items":[row(delivery,disposition)],"window":{"from":null,"to":null,"limit":1,"complete":true,
            "omitted":{"count":0,"reason":null}},"next":null,"unread_total":u64::from(disposition == "unread")}),
    )
}
fn send(delivery: &str, state: &str) -> Result<AnyOutput, serde_json::Error> {
    serde_json::from_value(
        json!({"schema":"se.message-receipt/v1","state":state,"message_id":MESSAGE,"event_id":EVENT,
        "recorded_at":"2026-01-01T00:00:00Z","project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"Fixture"},
        "from":actor(),"to":actor(),"kind":"handoff","reply_to":null,"refs":[],"idempotency_key":"fixture-request",
        "body":{"bytes":25,"sha256":"0".repeat(64)},"delivery":{"state":delivery,"at":null},"writer":{"mode":"direct"},
        "notification":{"intent":"direct","recipients":[]}}),
    )
}
fn plain(value: &AnyOutput) -> Result<String, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    output(value, false, false, &mut bytes)?;
    Ok(String::from_utf8(bytes)?)
}

#[test]
fn pending_notification_and_recipient_read_are_independent_on_list_and_read() -> Check {
    for disposition in ["unread", "read", "dismissed"] {
        for value in [
            page("pending", disposition)?,
            read("pending", disposition, true)?,
        ] {
            let before = serde_json::to_value(&value)?;
            let text = plain(&value)?;
            assert!(
                text.contains(&format!("Recipient state: {disposition}\n")),
                "{text}"
            );
            assert!(
                text.contains(
                    "Notification delivery: not observed (not a read or completion receipt)"
                ),
                "{text}"
            );
            assert_eq!(
                serde_json::to_value(&value)?,
                before,
                "inspection must preserve the stored facts"
            );
        }
    }
    Ok(())
}

#[test]
fn accepted_notification_does_not_fabricate_a_read_mark_and_unknown_states_remain_visible() -> Check
{
    for (stored, label) in [
        ("delivered", "accepted by provider"),
        ("offered", "offered"),
        ("not-running", "not-running"),
        ("not-applicable", "not applicable"),
        ("future-provider-state", "future-provider-state"),
    ] {
        for value in [page(stored, "unread")?, read(stored, "unread", true)?] {
            let text = plain(&value)?;
            assert!(text.contains("Recipient state: unread\n"), "{text}");
            assert!(
                text.contains(&format!(
                    "Notification delivery: {label} (not a read or completion receipt)"
                )),
                "{text}"
            );
        }
    }
    Ok(())
}

#[test]
fn committed_and_replayed_send_receipts_report_notification_only() -> Check {
    for state in ["committed", "replayed"] {
        for (stored, label) in [
            ("pending", "not observed"),
            ("delivered", "accepted by provider"),
            ("not-applicable", "not applicable"),
        ] {
            let value = send(stored, state)?;
            let text = plain(&value)?;
            assert!(
                text.contains(&format!(
                    "Notification delivery: {label} (not a read or completion receipt)"
                )),
                "{text}"
            );
            assert!(
                !text.contains("Recipient state:"),
                "send cannot invent a recipient disposition: {text}"
            );
        }
    }
    Ok(())
}

#[test]
fn json_fields_are_preserved_on_send_list_and_read_and_quiet_success_stays_quiet() -> Check {
    for value in [
        send("pending", "replayed")?,
        page("pending", "read")?,
        read("pending", "read", true)?,
    ] {
        let expected = serde_json::to_value(&value)?;
        let mut bytes = Vec::new();
        output(&value, true, false, &mut bytes)?;
        assert_eq!(serde_json::from_slice::<Value>(&bytes)?, expected);
        assert!(!String::from_utf8(bytes)?.contains("Notification delivery:"));
        let mut quiet = Vec::new();
        assert_eq!(output(&value, false, true, &mut quiet)?, 0);
        assert!(quiet.is_empty());
    }
    Ok(())
}

#[test]
fn read_marker_and_owner_inspection_remain_explicit_alongside_independent_states() -> Check {
    assert!(plain(&read("pending", "read", false)?)?.contains("Marked read."));
    assert!(
        plain(&read("pending", "read", true)?)?
            .contains("Inspection; recipient read mark unchanged.")
    );
    Ok(())
}

fn descriptions(value: &Value, field: &str, found: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            if let Some(text) = object
                .get(field)
                .and_then(|entry| entry.get("description"))
                .and_then(Value::as_str)
            {
                found.push(text.to_owned());
            }
            for value in object.values() {
                descriptions(value, field, found);
            }
        }
        Value::Array(array) => {
            for value in array {
                descriptions(value, field, found);
            }
        }
        _ => {}
    }
}
#[test]
fn public_generated_schemas_explain_notification_and_recipient_markers_independently() -> Check {
    for op in ["message.send", "message.list", "message.read"] {
        let output = metadata_output(&AnyOp::MetaSchema(MetaSchema {
            op: Some(op.into()),
        }))?
        .ok_or("schema absent")?;
        let value = serde_json::to_value(output)?;
        let mut delivery = Vec::new();
        descriptions(&value, "delivery", &mut delivery);
        assert!(
            delivery
                .iter()
                .any(|text| text.contains("notification") && text.contains("read")),
            "{op}: {delivery:?}"
        );
        if op != "message.send" {
            let mut disposition = Vec::new();
            descriptions(&value, "disposition", &mut disposition);
            assert!(
                disposition
                    .iter()
                    .any(|text| text.contains("authenticated") && text.contains("completed work")),
                "{op}: {disposition:?}"
            );
        }
    }
    Ok(())
}
