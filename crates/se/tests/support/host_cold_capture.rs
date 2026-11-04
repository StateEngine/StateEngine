use crate::*;

pub struct Capture<'a> {
    pub machine_key: &'a Secret,
    pub session_key: &'a Secret,
    pub conversation: &'a ProviderSessionId,
    pub transcript: &'a std::path::Path,
    pub first_line: &'a [u8],
    pub source: RecordId,
}

/// Protects: cold native capture — a new authenticated host reopens the prior trusted pin, preserves every multi-record commit timing and confirmed partial key, and refuses changes to the last cursor-anchored raw range without blocking unrelated writes.
pub fn check(f: &Fixture, case: Capture<'_>) -> Check {
    let machine =
        route::identity::require_machine(&route::files::Files::open(&f.options.state_directory)?)?;
    let ready = host::start(
        &f.options.state_directory,
        &f.options.state_directory.join("config.toml"),
        machine,
        &bound()?,
    )
    .map_err(|error| format!("cold native startup {error:?}"))?;
    let _cleanup = ChildCleanup {
        endpoint: &ready.endpoint,
        identity: &ready.ready.identity,
        credential: case.machine_key,
    };
    let outcome = (|| -> Check {
        let credential =
            || -> Result<se_host::client::lease::ClientCredential, Box<dyn std::error::Error>> {
                Ok(se_host::client::lease::ClientCredential::Session(
                    copy_secret(case.session_key)?,
                ))
            };
        let hook = || -> Result<se_host::ClaudeHookInput, Box<dyn std::error::Error>> {
            Ok(se_host::ClaudeHookInput {
                kind: se_host::ClaudeHookKind::Stop,
                conversation: case.conversation.clone(),
                claimed_transcript: NativePath::from_local(case.transcript.to_path_buf())?,
                payload: serde_json::Value::Null,
            })
        };
        let replay = ipc::forward_hook(&ready.endpoint, credential()?, hook()?, &options())?;
        assert!(
            matches!(replay,se_core::ops::AnyOutput::HookClaude(ref value) if value.value.receipt.as_ref().is_some_and(|receipt|matches!(receipt.result,se_core::ops::hook::CaptureResult::Duplicate)))
        );
        let mut next: serde_json::Value = serde_json::from_slice(case.first_line)?;
        next["uuid"] = serde_json::json!("otto-record-2");
        let second = serde_json::to_vec(&next)?;
        let mut append = std::fs::OpenOptions::new()
            .append(true)
            .open(case.transcript)?;
        append.write_all(&second)?;
        append.write_all(b"\n")?;
        next["uuid"] = serde_json::json!("otto-record-3");
        let third = serde_json::to_vec(&next)?;
        append.write_all(&third)?;
        append.write_all(b"\n")?;
        append.sync_all()?;
        let before = turn_events(f)?;
        let captured = ipc::forward_hook(&ready.endpoint, credential()?, hook()?, &options())?;
        let se_core::ops::AnyOutput::HookClaude(output) = captured else {
            return Err("multi-record capture returned another family".into());
        };
        assert!(
            output.value.stdout.is_empty(),
            "native provider stdout changed"
        );
        let diagnostics = output
            .diagnostics
            .as_ref()
            .ok_or("multi-record capture omitted diagnostics")?;
        assert_eq!(
            diagnostics.capture_commits.len(),
            2,
            "capture lost an earlier record's measured timing"
        );
        let measured = diagnostics
            .capture_commits
            .iter()
            .map(|value| {
                value.write_timings.validate()?;
                Ok(value.event_id.to_string())
            })
            .collect::<se_types::Result<std::collections::BTreeSet<_>>>()?;
        let after = turn_events(f)?;
        assert_eq!(measured, after.difference(&before).cloned().collect());
        let committed = (case.first_line.len() + second.len() + third.len() + 3) as u64;
        verify_capture(f, case.source, 3, committed)?;
        // An ordinary native read/write handle supplies FILE_WRITE_DATA on
        // Windows; append-only access cannot demonstrate arbitrary rewrites.
        let mut writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(case.transcript)?;
        let start = third
            .windows(b"outside provider text".len())
            .position(|bytes| bytes == b"outside provider text")
            .ok_or("provider text fixture drifted")?;
        std::io::Seek::seek(
            &mut writer,
            std::io::SeekFrom::Start((case.first_line.len() + second.len() + 2 + start) as u64),
        )?;
        writer.write_all(b"X")?;
        writer.sync_all()?;
        drop(writer);
        next["uuid"] = serde_json::json!("otto-record-4");
        let fourth = serde_json::to_vec(&next)?;
        append.write_all(&fourth)?;
        append.write_all(b"\n")?;
        append.sync_all()?;
        let error = ipc::forward_hook(&ready.endpoint, credential()?, hook()?, &options())
            .err()
            .ok_or("changed committed source range advanced capture")?;
        assert!(
            matches!(error.body.detail(), se_types::Detail::SourceUnreadable(_)),
            "wrong source-change refusal: {error}"
        );
        verify_capture(f, case.source, 3, committed)?;
        // Restore exactly this fixture's changed byte. The next complete turn
        // then commits before a following malformed provider line is refused.
        let mut restore = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(case.transcript)?;
        std::io::Seek::seek(
            &mut restore,
            std::io::SeekFrom::Start((case.first_line.len() + second.len() + 2 + start) as u64),
        )?;
        restore.write_all(&third[start..start + 1])?;
        restore.sync_all()?;
        drop(restore);
        append.write_all(b"{malformed-provider-record}\n")?;
        append.sync_all()?;
        let before_partial = turn_events(f)?;
        let partial = ipc::forward_hook(&ready.endpoint, credential()?, hook()?, &options())
            .err()
            .ok_or("malformed trailing provider record returned success")?;
        let wire = serde_json::to_value(partial.body.detail())?;
        assert_eq!(
            wire["code"], "capture-incomplete",
            "partial capture lost confirmed work: {partial}"
        );
        let confirmed = wire["detail"]["committed_events"]
            .as_array()
            .ok_or("confirmed capture events")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or("confirmed event string")
            })
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        let after_partial = turn_events(f)?;
        assert_eq!(
            confirmed,
            after_partial.difference(&before_partial).cloned().collect()
        );
        assert_eq!(confirmed.len(), 1);
        let keys = wire["detail"]["natural_keys"]
            .as_array()
            .ok_or("confirmed capture natural keys")?;
        assert_eq!(keys.len(), 1);
        let natural = keys[0].as_str().ok_or("confirmed natural key string")?;
        assert!(natural.contains(case.conversation.as_str()) && natural.contains("otto-record-4"));
        verify_capture(f, case.source, 4, committed + fourth.len() as u64 + 1)?;
        let independent = ipc::forward(
            &ready.endpoint,
            credential()?,
            se_core::ops::AnyOp::MessageSend(se_core::ops::MessageSend {
                to: f.b.as_str().into(),
                body: "capture refusal leaves message available".into(),
                kind: Default::default(),
                refs: vec![],
                reply_to: None,
                work: None,
                idempotency_key: key("cold-independent")?,
            }),
            &Default::default(),
            None,
            &options(),
        )?;
        assert_eq!(serde_json::to_value(independent)?["state"], "committed");
        Ok(())
    })();
    stop_native(&ready.endpoint, case.machine_key, "cold-stop")?;
    wait_native_exit(&ready.ready.identity)?;
    outcome?;
    println!(
        "PASS cold_capture: trusted prior pin, native restart, replay/append, every committed timing, exact durable cursor, keyed partial capture, changed-range refusal and independent message"
    );
    Ok(())
}

fn turn_events(
    f: &Fixture,
) -> Result<std::collections::BTreeSet<String>, Box<dyn std::error::Error>> {
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
    let turns = snapshot.turns(f.a.clone(), budget(10, 65536, None)?)?;
    let events = turns
        .items()
        .iter()
        .map(|value| value.header.event.to_string())
        .collect();
    snapshot.close()?;
    Ok(events)
}
