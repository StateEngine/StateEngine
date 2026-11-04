//! Protects: G4 — the public resource DTO distinguishes unavailable splits from measured zero.
use se_core::ops::ResourceSample;

/// Protects: G4 — either context-switch split can be unavailable without inventing zero.
#[test]
fn both_public_context_switch_splits_represent_absence_and_zero() -> Result<(), serde_json::Error> {
    let mut sample = ResourceSample {
        self_voluntary_switches: None,
        self_involuntary_switches: None,
        cpu_user_us: 0,
        cpu_system_us: 0,
        rss_bytes: 1,
        sampled_at: "2026-11-04T00:00:00Z".into(),
        method: "public optional-counter representation".into(),
    };
    let absent = serde_json::to_value(&sample)?;
    assert!(absent["self_voluntary_switches"].is_null());
    assert!(absent["self_involuntary_switches"].is_null());
    sample.self_voluntary_switches = Some(0);
    sample.self_involuntary_switches = Some(0);
    let zero = serde_json::to_value(&sample)?;
    assert_eq!(zero["self_voluntary_switches"], 0);
    assert_eq!(zero["self_involuntary_switches"], 0);
    Ok(())
}
