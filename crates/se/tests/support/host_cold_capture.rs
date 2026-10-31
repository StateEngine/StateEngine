use crate::*;

pub struct Capture<'a> {
    pub machine_key: &'a Secret,
    pub session_key: &'a Secret,
    pub conversation: &'a ProviderSessionId,
    pub transcript: &'a std::path::Path,
    pub first_line: &'a [u8],
    pub source: RecordId,
}

/// Protects: cold native capture — a new authenticated host reopens only the prior trusted pin, captures appended bytes, replays its immutable receipt and refuses a changed committed range without stopping unrelated session writes.
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
        append.sync_all()?;
        ipc::forward_hook(&ready.endpoint, credential()?, hook()?, &options())?;
        let committed = (case.first_line.len() + second.len() + 2) as u64;
        verify_capture(f, case.source, 2, committed)?;
        // An ordinary native read/write handle supplies FILE_WRITE_DATA on
        // Windows; append-only access cannot demonstrate arbitrary rewrites.
        let mut writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(case.transcript)?;
        let start = second
            .windows(b"outside provider text".len())
            .position(|bytes| bytes == b"outside provider text")
            .ok_or("provider text fixture drifted")?;
        std::io::Seek::seek(
            &mut writer,
            std::io::SeekFrom::Start((case.first_line.len() + 1 + start) as u64),
        )?;
        writer.write_all(b"X")?;
        writer.sync_all()?;
        drop(writer);
        next["uuid"] = serde_json::json!("otto-record-3");
        append.write_all(&serde_json::to_vec(&next)?)?;
        append.write_all(b"\n")?;
        append.sync_all()?;
        let error = ipc::forward_hook(&ready.endpoint, credential()?, hook()?, &options())
            .err()
            .ok_or("changed committed source range advanced capture")?;
        assert!(
            matches!(error.body.detail(), se_types::Detail::SourceUnreadable(_)),
            "wrong source-change refusal: {error}"
        );
        verify_capture(f, case.source, 2, committed)?;
        let independent = ipc::forward(
            &ready.endpoint,
            credential()?,
            se_core::ops::AnyOp::MessageSend(se_core::ops::MessageSend {
                to: f.b.as_str().into(),
                body: "capture refusal leaves message available".into(),
                kind: Default::default(),
                refs: vec![],
                reply_to: None,
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
        "PASS cold_capture: trusted prior pin, native restart, replay/append, exact durable cursor, changed-range refusal and independent message"
    );
    Ok(())
}
