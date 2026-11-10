//! Bug: 45cfd6f5 — a larger transport frame silently enlarged request output budgets.
use se_types::remote::{RemoteList, RemoteWatch};

/// Protects: design47 §5 list/watch output remains1024..65536 bytes independently of framing.
#[test]
fn list_and_watch_keep_their_public_output_budget() -> Result<(), Box<dyn std::error::Error>> {
    let mut failures = Vec::new();
    for budget in [1023, 1024, 65536, 65537, 262144] {
        let list: RemoteList = serde_json::from_value(serde_json::json!({
            "targets":[], "limit":20, "budget":budget
        }))?;
        let watch: RemoteWatch = serde_json::from_value(serde_json::json!({
            "targets":[], "cursors":[], "budget":budget
        }))?;
        for (kind, admitted) in [
            ("list", list.validate().is_ok()),
            ("watch", watch.validate().is_ok()),
        ] {
            if admitted != (1024..=65536).contains(&budget) {
                failures.push(format!("{kind} budget{budget}: admitted={admitted}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
    Ok(())
}
