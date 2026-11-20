#![allow(
    dead_code,
    reason = "The shared real native fixture supports several public API consumers."
)]
use se_store::*;
use std::process::{Command, Output};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn search(
    f: &Fixture,
    args: &[&str],
) -> Result<(Output, serde_json::Value), Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
    command
        .arg("--json")
        .arg("--home")
        .arg(&f.options.state_directory)
        .args(["--project", f.project.as_str(), "search"])
        .args(args);
    for name in [
        "SE_HOME",
        "SE_PROJECT",
        "SE_CONFIG",
        "SE_LOG",
        "SE_SESSION",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        command.env_remove(name);
    }
    let output = command.output()?;
    let value = serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
    Ok((output, value))
}

fn hit_ids(value: &serde_json::Value) -> Vec<String> {
    value["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["event_id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Protects: the public search command finds committed history text case-insensitively, reports measured zero for absent text, and refuses an empty query.
#[test]
fn search_finds_committed_text_and_reports_honest_misses() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let wanted = store.append(
        f.working(
            "the Needle sits in this note 🦀",
            Expected::Absent,
            "wanted",
        )?,
        &*lease,
    )?;
    store.append(
        f.working("nothing to find here", revision(1)?, "other")?,
        &*lease,
    )?;
    store.close()?;
    drop(lease);

    let (output, value) = search(&f, &["needle"])?;
    assert!(
        output.status.success(),
        "search refused: {value}; {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ids = hit_ids(&value);
    assert_eq!(
        ids,
        vec![wanted.primary_event.as_str().to_owned()],
        "actual search page: {value}"
    );
    let snippet = value["items"][0]["snippet"].as_str().unwrap_or_default();
    assert!(
        snippet.contains("Needle"),
        "snippet lost the match: {value}"
    );

    let (output, value) = search(&f, &["absent-term-xyz"])?;
    assert!(output.status.success(), "absent search refused: {value}");
    assert!(
        value["items"].as_array().is_some_and(Vec::is_empty),
        "absent text produced hits: {value}"
    );

    let (output, _) = search(&f, &[""])?;
    assert!(!output.status.success(), "an empty query was accepted");
    Ok(())
}
