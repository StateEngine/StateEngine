//! Native capture through the real host writer, then public plain/JSON history.
#![cfg(target_os = "linux")]
#[path = "../../se-host/tests/support/wave2_host_fixture.rs"]
mod support;
use se_core::ops::transcript::{Record, tool::Target};
use se_host::*;
use se_store::*;
use se_types::{NativePath, ProviderSessionId, Sha256};
use serde_json::{Value, json};
use std::process::Command;
use support::*;

#[test]
fn fresh_claude_and_codex_commands_reach_history_page_and_exact_event() -> Check {
    for provider in [Provider::Claude, Provider::Codex] {
        capture_and_read(provider)?;
    }
    Ok(())
}
fn capture_and_read(provider: Provider) -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let session = session::session()?;
    let conversation = ProviderSessionId::new(format!("shell-{}", f.a.as_str()))?;
    let command = "printf SHELL_HISTORY_NATIVE > not-an-edit-witness.rs";
    let rows = if provider == Provider::Claude {
        vec![
            json!({"type":"assistant","uuid":"shell-called","sessionId":conversation.as_str(),
                "message":{"role":"assistant","content":[{"type":"tool_use","id":"native-shell","name":"Bash","input":{"command":command}}]}}),
            json!({"type":"user","uuid":"shell-result","sessionId":conversation.as_str(),
                "message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"native-shell","is_error":false,"content":"PRIVATE_OUTPUT"}]}}),
        ]
    } else {
        vec![
            json!({"type":"session_meta","payload":{"id":conversation.as_str()}}),
            json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":conversation.as_str(),"turn_id":"native-turn",
                "item":{"type":"CommandExecution","id":"native-shell","command":["/bin/bash","-lc",command],"status":"completed","exit_code":0,"aggregated_output":"PRIVATE_OUTPUT"}}}),
        ]
    };
    let mut bytes = Vec::new();
    for row in rows {
        bytes.extend(serde_json::to_vec(&row)?);
        bytes.push(b'\n');
    }
    let path = f.home.join("native-shell.jsonl");
    std::fs::write(&path, &bytes)?;
    let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("source absent")?;
    let native_path = NativePath::from_local(path)?;
    let source = session::record()?;
    let (mut store, lease) = direct(&f)?;
    let mut prepared = session::prepared(&f, &session, &f.a);
    if let EventBody::SessionPrepared {
        provider: actual,
        native_ref,
        ..
    } = &mut prepared
    {
        *actual = provider;
        *native_ref = conversation.as_str().into();
    }
    store.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("native-shell-setup")?),
            vec![
                prepared,
                session::activated(&session)?,
                session::source(source, &session, &pin.identity(), Expected::Absent),
            ],
        )?,
        &*lease,
    )?;
    store.close()?;
    drop(lease);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        configure_private_listener(&mut host)?;
        let capture = host.capture_handle();
        capture
            .bind(
                TranscriptPin {
                    identity: SessionIdentity {
                        project: f.project.clone(),
                        agent: f.a.clone(),
                        session: session.clone(),
                    },
                    conversation: conversation.clone(),
                    path: native_path.clone(),
                    file_identity: Sha256::from_bytes(pin.identity()),
                },
                source,
                pin,
                &bound()?,
            )
            .await?;
        let mut admitted = f.self_scope(&f.a).admission;
        admitted.session = Some(session.clone());
        let stop = host.local_stop();
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let capture_bound = bound()?;
        let consumer = async {
            let result = capture
                .catch_up(admitted, conversation, native_path, &capture_bound)
                .await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), consumer).await;
        drop(capture);
        let report = exit.finish(&bound()?).await;
        require(
            report.transport_closed && report.endpoint_retired,
            "native command host did not close",
        )?;
        require(
            !result?.capture_commits.is_empty(),
            "native command did not commit",
        )?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let history =
        |json: bool, args: &[&str]| -> Result<std::process::Output, Box<dyn std::error::Error>> {
            let mut cli = Command::new(env!("CARGO_BIN_EXE_se"));
            cli.env_clear()
                .env("PATH", std::env::var_os("PATH").ok_or("PATH absent")?)
                .arg("--home")
                .arg(&f.options.state_directory)
                .args(["--project", f.project.as_str()]);
            if json {
                cli.arg("--json");
            }
            Ok(cli
                .arg("history")
                .args(args)
                .current_dir(&f.home)
                .output()?)
        };
    let args = [
        "--agent",
        f.a.as_str(),
        "--kind",
        "transcript.event",
        "--limit",
        "100",
    ];
    let machine = history(true, &args)?;
    require(
        machine.status.success(),
        String::from_utf8_lossy(&machine.stderr).as_ref(),
    )?;
    let full: Value = serde_json::from_slice(&machine.stdout)?;
    let event = full["items"]
        .as_array()
        .ok_or("history items absent")?
        .iter()
        .find(|item| {
            item.pointer("/payload/metadata/captured_tool/outcome") == Some(&json!("Succeeded"))
        })
        .ok_or("native shell completion absent from public history")?;
    let target = event
        .pointer("/payload/metadata/captured_tool/target/Command")
        .and_then(Value::as_str)
        .ok_or("native command text not retained")?;
    require(target.contains(command), "actual command text differs")?;
    for args in [
        args.to_vec(),
        vec![
            "--event",
            event["event_id"].as_str().ok_or("event id absent")?,
        ],
    ] {
        let plain = history(false, &args)?;
        require(
            plain.status.success(),
            String::from_utf8_lossy(&plain.stderr).as_ref(),
        )?;
        let text = String::from_utf8(plain.stdout)?;
        require(
            text.contains("ran: ") && text.contains(command),
            "public history lost the fresh command",
        )?;
        require(
            !text.contains("edited:") && !text.contains("PRIVATE_OUTPUT"),
            "shell text fabricated an edit or exposed output",
        )?;
        require(
            !text.contains("arguments not captured"),
            "fresh known arguments became legacy unknown",
        )?;
    }
    let (reader, lease) = direct(&f)?;
    let mut snapshot = reader.snapshot(f.self_scope(&f.a))?;
    let turns = snapshot.turns(f.a.clone(), budget(10, 100_000, None)?)?;
    for event in turns.items() {
        if let EventBody::SessionTurn {
            text: StoredText::Present(text),
            ..
        } = &event.body
        {
            let tool = Record::decode(text)?
                .captured_tool
                .ok_or("trusted metadata absent")?;
            require(
                matches!(tool.target, Target::Command(_)),
                "shell spelling inferred a path target",
            )?;
        }
    }
    snapshot.close()?;
    reader.close()?;
    drop(lease);
    Ok(())
}
