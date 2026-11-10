//! Terminal timing remains explicitly unqualified when clocks cannot bound drift.
use se_core::ops::RemoteWatchOutput;
use serde_json::{Value, json};
use std::{error::Error, time::Instant};
#[path = "../src/remote/measure.rs"]
mod measure;
type Check<T = ()> = Result<T, Box<dyn Error>>;
fn page(age: Option<u64>, released: Option<u64>) -> Check<RemoteWatchOutput> {
    Ok(serde_json::from_value(json!({
        "observation_clock":released.map(|time|json!({"epoch":vec![1;16],"sampled_at_us":123,"source_bracket_us":2,"source_released_at_us":time})),
        "records":[{"type":"provisional","target":{"project":se_types::ProjectId::from_parts(1_700_000_000_000,[1;10])?,"agent":se_types::AgentId::from_parts(1_700_000_000_000,[2;10])?},"cursor":"synthetic-clock-cursor","item":{"item_id":"synthetic-item","role":"assistant","preview":{"text":"synthetic observation","complete":true,"omitted_utf8_bytes":{"kind":"none"}}},"observation":{"at_us":100,"age_estimate_us":age}}],
        "cursors":[],"complete":true,"omitted_records":{"kind":"none"},"reset_required":false
    }))?)
}
fn rendered(page: &RemoteWatchOutput) -> Check<Vec<Value>> {
    let mut bytes = Vec::new();
    measure::flushed(page, Instant::now(), &mut bytes)?;
    std::str::from_utf8(&bytes)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}
/// Protects: an available age is still an estimate, never a qualified cross-machine bound.
#[test]
fn available_terminal_age_is_explicitly_an_unqualified_estimate() -> Check {
    let now = se_proc::monotonic_micros()?;
    let rows = rendered(&page(Some(1234), Some(now))?)?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["boundary"], "stdout_flushed");
    let item = &rows[1];
    assert_eq!(item["boundary"], "provisional_flushed");
    assert_eq!(item["qualification"], "unqualified");
    assert_eq!(item["clock_model"], "unsynchronized_monotonic_estimate");
    assert_eq!(item["clock_estimate_available"], true);
    assert!(
        item["producer_to_flush_estimate_us"]
            .as_u64()
            .ok_or("estimate absent")?
            >= 1234
    );
    assert!(item.get("producer_to_flush_upper_bound_us").is_none());
    assert!(item.get("clock_bound_available").is_none());
    Ok(())
}
/// Protects: absent and inconsistent timing never become a zero-latency observation.
#[test]
fn unavailable_terminal_age_stays_absent_and_future_release_refuses() -> Check {
    let rows = rendered(&page(None, None)?)?;
    assert_eq!(rows[1]["producer_to_flush_estimate_us"], Value::Null);
    assert_eq!(rows[1]["clock_estimate_available"], false);
    assert_eq!(rows[1]["qualification"], "unqualified");
    assert!(rendered(&page(Some(1), Some(u64::MAX))?).is_err());
    Ok(())
}
