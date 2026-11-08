//! Bug: c2d3b788 — adding remote ID kinds must preserve existing legacy project JSON.
use se_types::ProjectId;

/// Protects: C1 — historical project JSON remains readable after adding remote identity kinds.
#[test]
fn remote_prefix_additions_keep_legacy_project_json_readable()
-> Result<(), Box<dyn std::error::Error>> {
    let mut failures = Vec::new();
    for id in ["rgr_archive", "rinv_archive", "rdev_archive", "rpr_archive"] {
        let text = serde_json::to_string(id)?;
        match serde_json::from_str::<ProjectId>(&text) {
            Ok(value) => assert_eq!(value.as_str(), id),
            Err(error) => failures.push(format!("{id}: {error}")),
        }
    }
    assert!(
        failures.is_empty(),
        "historical project IDs stopped reading: {}",
        failures.join("; ")
    );
    Ok(())
}
