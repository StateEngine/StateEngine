//! Plain output is a human summary; JSON retains the exact public receipt.
#![allow(
    dead_code,
    reason = "Imports the production renderer and shared native fixture."
)]
#[path = "../../se-store/tests/support/capture_fixture.rs"]
mod capture;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "../src/render/mod.rs"]
mod render;
use fixture::*;
use se_store::*;
use serde_json::{Value, json};
use std::process::Command;

fn stop_row(
    f: &Fixture,
) -> Result<se_core::ops::agent_stop::AgentStopResult, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(json!({
        "target": {"project":{"id":f.project,"name":"Repo"}, "agent":{"id":f.a,"name":"Alpha"},
            "session_id":null,"launch_id":null,"provider":"claude","process":null},
        "result":"stopped", "event_id":null,"method":"native-stop",
        "witness":{"state":"witnessed","method":"start-identity-exit+pgid-empty",
            "observed_at":"2026-11-04T23:00:00Z", "detail":"scope=ProcessIdentity { boot_id: [1, 2, 3] }"},
        "population":"empty", "population_reason":null,"ownership_release":null,
        "remaining":[],"enumeration":"complete", "capture":{"flushed":true,"last_event_id":null},
        "resume":{"state":"ready","reason":null,"conversation_id":"native-conversation", "provider":"claude",
            "model":null,"command":"se --home '/selected home' --project repo launch alpha --detach", "argv":[]}
    }))?)
}

fn stop_output(
    row: se_core::ops::agent_stop::AgentStopResult,
    all: bool,
) -> Result<se_core::ops::AnyOutput, Box<dyn std::error::Error>> {
    use se_core::ops::StopResult;
    let mut value = StopResult {
        idempotency_key: se_types::IdempotencyKey::new("plain-stop")?,
        receipt: "seat-stop/v1".into(),
        scope: if all { "all" } else { "agent" }.into(),
        result: row.result.clone(),
        complete: row.result == "stopped",
        event_id: None,
        target: None,
        method: None,
        witness: None,
        population: None,
        population_reason: None,
        ownership_release: None,
        remaining: None,
        enumeration: None,
        capture: None,
        resume: None,
        stops: None,
    };
    if all {
        value.stops = Some(vec![row]);
    } else {
        value.target = Some(row.target);
        value.witness = Some(row.witness);
        value.population = Some(row.population);
        value.population_reason = row.population_reason;
        value.ownership_release = row.ownership_release;
        value.remaining = Some(row.remaining);
        value.enumeration = Some(row.enumeration);
        value.capture = Some(row.capture);
        value.resume = Some(row.resume);
    }
    Ok(value.into())
}

#[test]
fn single_and_all_stop_summarize_native_witness_but_json_keeps_it() -> Check {
    let f = Fixture::new()?;
    for all in [false, true] {
        let output = stop_output(stop_row(&f)?, all)?;
        let mut plain = Vec::new();
        assert_eq!(render::output(&output, false, false, &mut plain)?, 0);
        let plain = String::from_utf8(plain)?;
        for fact in [
            "Alpha",
            "Repo",
            "Exit check complete.",
            "No processes remain in the checked scope.",
            "The process list is complete.",
            "Saved conversation: up to date.",
            "Resume: se --home '/selected home'",
            "Use --json",
        ] {
            assert!(plain.contains(fact), "missing {fact}: {plain}");
        }
        for raw in [
            "ProcessIdentity",
            "boot_id",
            "[1, 2, 3]",
            "Request key:",
            "native-conversation",
            "; enumeration:",
        ] {
            assert!(!plain.contains(raw), "diagnostic leaked: {plain}");
        }
        let mut full = Vec::new();
        render::output(&output, true, false, &mut full)?;
        let full: Value = serde_json::from_slice(&full)?;
        let receipt = if all { &full["stops"][0] } else { &full };
        assert_eq!(
            receipt["witness"]["detail"],
            "scope=ProcessIdentity { boot_id: [1, 2, 3] }"
        );
        assert_eq!(receipt["resume"]["conversation_id"], "native-conversation");
    }
    Ok(())
}

#[test]
fn incomplete_stop_never_claims_an_empty_diagnostic_list_proves_exit() -> Check {
    let f = Fixture::new()?;
    for all in [false, true] {
        let mut row = stop_row(&f)?;
        row.result = "unwitnessed".into();
        row.witness.state = "unwitnessed".into();
        row.population = "unknown".into();
        row.population_reason = Some("Native closure is incomplete.".into());
        row.enumeration = "unavailable".into();
        row.capture.flushed = false;
        row.resume.state = "unavailable".into();
        row.resume.reason = Some("No original conversation has been proven.".into());
        row.resume.command.clear();
        let output = stop_output(row, all)?;
        let mut plain = Vec::new();
        assert_ne!(render::output(&output, false, false, &mut plain)?, 0);
        let plain = String::from_utf8(plain)?;
        for fact in [
            "Stop incomplete.",
            "Process exit was not observed.",
            "Remaining processes could not be determined.",
            "The process list is incomplete or unavailable.",
            "Saved conversation: may be incomplete.",
            "Native closure is incomplete.",
            "No original conversation has been proven.",
            "Stop remains incomplete",
        ] {
            assert!(plain.contains(fact), "missing obligation {fact}: {plain}");
        }
    }
    Ok(())
}

fn history(
    f: &Fixture,
    json: bool,
    extra: &[&str],
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_se"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").ok_or("PATH")?)
        .arg("--home")
        .arg(&f.options.state_directory)
        .args(["--project", f.project.as_str()]);
    if json {
        cmd.arg("--json");
    }
    Ok(cmd
        .arg("history")
        .args(extra)
        .current_dir(&f.home)
        .output()?)
}

#[test]
fn public_history_page_and_exact_event_show_chat_text_without_payload_envelope() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let session = capture::session()?;
    let source = capture::record()?;
    capture::active(&f, &mut store, &lease, &session, source)?;
    for n in 0..2 {
        let mut batch = capture::capture(
            &f,
            &session,
            source,
            b"first",
            n * 10,
            n + 1,
            &format!("plain-turn-{n}"),
        )?;
        for event in &mut batch.events {
            event.header.door = Door::Hook;
            if let EventBody::SessionTurn { text, .. } = &mut event.body {
                *text = InputText::Inline("Complete answer 🦀\nsecond line".into());
            }
        }
        store.append(batch, &*lease)?;
    }
    let head = store.info()?.head;
    let args = [
        "--agent",
        f.a.as_str(),
        "--kind",
        "session.turn",
        "--limit",
        "1",
    ];
    let full = history(&f, true, &args)?;
    assert!(
        full.status.success(),
        "{}",
        String::from_utf8_lossy(&full.stdout)
    );
    let full: Value = serde_json::from_slice(&full.stdout)?;
    let event = full["items"][0]["event_id"].as_str().ok_or("event")?;
    let cursor = full["next"].as_str().ok_or("continuation")?;
    for args in [args.to_vec(), vec!["--event", event]] {
        let plain = history(&f, false, &args)?;
        assert!(plain.status.success());
        let plain = String::from_utf8(plain.stdout)?;
        assert!(
            plain.contains("Complete answer 🦀\n    second line"),
            "{plain}"
        );
        assert!(plain.contains("Role: assistant"), "{plain}");
        assert!(plain.contains("By: Alpha"), "{plain}");
        assert!(plain.contains("Use --json"), "{plain}");
        for raw in [
            "Payload:",
            "sha256:",
            "bytes:",
            "Committed by",
            "provider session:",
            "turn id:",
        ] {
            assert!(!plain.contains(raw), "raw envelope: {plain}");
        }
    }
    let first = history(&f, false, &args)?;
    assert!(String::from_utf8(first.stdout)?.contains(cursor));
    assert!(
        history(
            &f,
            false,
            &[
                "--agent",
                f.a.as_str(),
                "--kind",
                "session.turn",
                "--limit",
                "1",
                "--cursor",
                cursor
            ]
        )?
        .status
        .success()
    );
    let payload = &full["items"][0]["payload"];
    assert_eq!(payload["body"]["text"], "Complete answer 🦀\nsecond line");
    assert_eq!(payload["body"]["complete"], true);
    assert!(payload["body"]["sha256"].is_string());
    assert!(payload["provider_session"].is_string());
    assert!(full["items"][0]["writer"].is_object());
    assert_eq!(store.info()?.head, head);
    store.close()?;
    drop(lease);
    Ok(())
}
