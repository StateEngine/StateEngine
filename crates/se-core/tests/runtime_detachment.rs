use se_core::ops::{HostDetachment, RuntimeView, status};
use serde_json::{Value, json};
type Check = Result<(), Box<dyn std::error::Error>>;

/// Protects: status honesty — absent runtime evidence and older payloads never infer detachment from the platform, a missing endpoint or an unknown runtime state.
#[test]
fn unobserved_detachment_stays_absent_on_construction_and_decode() -> Check {
    let output = status::missing(
        "/uninitialized-home".into(),
        "2026-10-31T00:00:00Z".into(),
        "checked absent".into(),
    );
    let mut value = serde_json::to_value(output.runtime)?;
    assert_eq!(value["state"], "unknown");
    assert!(value.get("detachment").is_none());
    let legacy: RuntimeView = serde_json::from_value(value.clone())?;
    assert!(legacy.detachment.is_none());
    value["state"] = json!("running");
    value["endpoint"] = json!("observed endpoint");
    let running: RuntimeView = serde_json::from_value(value)?;
    assert!(running.detachment.is_none());
    assert!(serde_json::to_value(running)?.get("detachment").is_none());
    Ok(())
}

/// Protects: runtime detachment DTO — observed session, user-manager and Windows modes retain distinct closed wire facts rather than being collapsed into a platform assumption.
#[test]
fn observed_detachment_modes_roundtrip_without_guessing() -> Check {
    for (mode, name) in [
        (HostDetachment::SessionOnly, "session-only"),
        (HostDetachment::UserManagerUnit, "user-manager-unit"),
        (HostDetachment::WindowsBreakaway, "windows-breakaway"),
    ] {
        let mut view = status::missing("home".into(), "now".into(), "absent".into()).runtime;
        view.state = "running".into();
        view.detachment = Some(mode);
        let value = serde_json::to_value(view)?;
        assert_eq!(value["detachment"], name);
        let decoded: RuntimeView = serde_json::from_value(value.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, value);
    }
    for unknown in [
        json!("unknown"),
        json!("session_only"),
        json!(true),
        Value::Null,
    ] {
        if unknown.is_null() {
            continue;
        }
        assert!(serde_json::from_value::<HostDetachment>(unknown).is_err());
    }
    Ok(())
}
