#![allow(
    dead_code,
    reason = "Shared native fixture supports several public consumers."
)]
use se_store::*;
use se_types::EventId;
use std::{
    path::Path,
    process::{Command, Output},
    sync::Arc,
};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn clean(command: &mut Command) {
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
}
fn command(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
    command.arg("--json").arg("--home").arg(home);
    clean(&mut command);
    command
}
fn json(output: &Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "CLI JSON: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })?)
}
fn success(output: Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    assert!(
        output.status.success(),
        "CLI refused: {}; {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    json(&output)
}
fn setup() -> Result<(Fixture, SqliteDirect, Arc<Lease>), Box<dyn std::error::Error>> {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    store.append(
        f.batch(
            f.owner_project(),
            None,
            vec![EventBody::PrincipalRegistered {
                principal: Actor::Human(f.owner.clone()),
                kind: PrincipalKind::Human,
                owner: f.owner.clone(),
                created_by: None,
                name: "Owner".into(),
                role: "owner".into(),
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    Ok((f, store, lease))
}
fn send(
    f: &Fixture,
    store: &mut SqliteDirect,
    lease: &Lease,
    sender: Actor,
    kind: &str,
    text: &str,
) -> Result<EventId, Box<dyn std::error::Error>> {
    Ok(store
        .append(
            f.batch(
                f.admission(Scope::Project(f.project.clone()), sender),
                None,
                vec![EventBody::MessageSent {
                    message: message()?,
                    recipient: Actor::Human(f.owner.clone()),
                    kind: kind.into(),
                    body: InputText::Inline(text.into()),
                    refs: vec![],
                    reply_to: None,
                }],
            )?,
            lease,
        )?
        .primary_event)
}

/// Protects: a clipped message's executable full-body argv preserves the original project, sender, recipient, kind and all/unread filters and returns its exact retained body through the real CLI.
#[test]
fn message_preview_hint_reaches_the_full_retained_body() -> Check {
    let (f, mut store, lease) = setup()?;
    let body = "a real retained message with UTF8 🦀 and spaces\n".repeat(30);
    let event = send(
        &f,
        &mut store,
        &lease,
        Actor::Agent(f.a.clone()),
        "note",
        &body,
    )?;
    send(
        &f,
        &mut store,
        &lease,
        Actor::Agent(f.b.clone()),
        "note",
        "unrelated sender",
    )?;
    send(
        &f,
        &mut store,
        &lease,
        Actor::Agent(f.a.clone()),
        "finding",
        "unrelated kind",
    )?;
    let human_event = send(
        &f,
        &mut store,
        &lease,
        Actor::Human(f.owner.clone()),
        "note",
        &body,
    )?;
    check_preview(&f, f.a.as_str(), &event, &body)?;
    check_preview(&f, "owner", &human_event, &body)?;
    store.close()?;
    Ok(())
}
fn check_preview(f: &Fixture, from: &str, event: &EventId, body: &str) -> Check {
    let page = success(
        command(&f.options.state_directory)
            .args([
                "--project",
                f.project.as_str(),
                "msg",
                "list",
                "--all",
                "--from",
                from,
                "--to",
                "owner",
                "--kind",
                "note",
                "--limit",
                "1",
                "--preview-chars",
                "16",
            ])
            .output()?,
    )?;
    assert_eq!(page["items"].as_array().ok_or("message rows")?.len(), 1);
    let row = &page["items"][0];
    assert_eq!(row["event_id"], event.as_str());
    assert_eq!(row["body"]["complete"], false);
    let argv = row["body"]["argv"]
        .as_array()
        .ok_or("full-body argv")?
        .iter()
        .map(|value| value.as_str().ok_or("argv string"))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(argv.first().copied(), Some("se"));
    assert!(
        !row["body"]["command"]
            .as_str()
            .ok_or("full-body command")?
            .contains("msg read")
    );
    let output = command(&f.options.state_directory)
        .args(&argv[1..])
        .output()?;
    assert!(
        output.status.success(),
        "printed full-body argv {argv:?} refused: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let full = json(&output)?;
    assert_eq!(
        full["items"].as_array().ok_or("full message rows")?.len(),
        1
    );
    assert_eq!(full["items"][0]["event_id"], event.as_str());
    assert_eq!(full["items"][0]["body"]["text"], body);
    assert_eq!(full["items"][0]["body"]["complete"], true);
    Ok(())
}

/// Protects: the public inbox DTO and actual native store reader cannot report a complete exit while unread messages remain beyond a finite page; a complete inbox and an empty sent box stay successful.
#[test]
fn real_inbox_page_exit_distinguishes_hidden_unread_mail() -> Check {
    let (f, mut store, lease) = setup()?;
    for n in 0..3 {
        send(
            &f,
            &mut store,
            &lease,
            Actor::Agent(f.a.clone()),
            "note",
            &format!("actual unread {n}"),
        )?;
    }
    let admission = f.owner_project();
    for (input, expected, count) in [
        (serde_json::json!({"limit":1}), 2, 1),
        (serde_json::json!({"limit":10}), 0, 3),
        (serde_json::json!({"box":"sent","limit":1}), 0, 0),
    ] {
        let input = serde_json::from_value::<se_core::ops::MessageList>(input)?;
        let mut snapshot = store.snapshot(f.scoped(Visibility::Owner))?;
        let page = se_core::ops::message::list(
            input,
            &mut se_core::commit::Cx {
                read: &mut snapshot,
                admission: &admission,
            },
        )?;
        snapshot.close()?;
        assert_eq!(page.page.items().len(), count);
        let output: se_core::ops::AnyOutput = page.into();
        assert_eq!(output.exit_code(), expected);
    }
    store.close()?;
    Ok(())
}

/// Protects: an existing caller key belonging to another real operation refuses config mutation with idempotency-key-reused and the original retained event, without advancing history.
#[cfg(target_os = "linux")]
#[test]
fn config_reused_message_key_names_the_original_event() -> Check {
    let (f, store, _lease) = setup()?;
    let first = success(
        command(&f.options.state_directory)
            .args([
                "--project",
                f.project.as_str(),
                "--key",
                "message-before-config",
                "msg",
                "send",
                f.a.as_str(),
                "key belongs to this message",
            ])
            .output()?,
    )?;
    let head = store.info()?.head;
    let key = format!("agent.{}.model", f.a);
    let mut configured = command(&f.options.state_directory);
    configured.args([
        "--project",
        f.project.as_str(),
        "--key",
        "message-before-config",
        "config",
        "set",
        &key,
        "another-model",
    ]);
    let output = terminal(&configured)?;
    assert!(!output.status.success());
    let printed = String::from_utf8_lossy(&output.stdout);
    let error: serde_json::Value = printed
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line).ok())
        .ok_or("actual terminal config JSON")?;
    assert_eq!(
        error["code"], "idempotency-key-reused",
        "wrong config conflict: {error}"
    );
    assert_eq!(error["detail"]["key"], "message-before-config");
    assert_eq!(error["detail"]["original_event"], first["event_id"]);
    assert_eq!(store.info()?.head, head);
    store.close()?;
    Ok(())
}

/// Protects: missing selection reports the actual two registered project choices in structured and plain output; init's suggested argv executes a supported operation in the saved home.
#[test]
fn project_choices_and_init_next_step_are_real_and_executable() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let mut ids = Vec::new();
    for name in ["first-choice", "second-choice"] {
        let repo = f.home.join(name);
        std::fs::create_dir(&repo)?;
        let initialized = success(
            command(&f.options.state_directory)
                .arg("init")
                .arg("--repo")
                .arg(&repo)
                .args(["--name", name])
                .output()?,
        )?;
        ids.push(initialized["project"]["id"].clone());
        let argv = initialized["next"]["argv"]
            .as_array()
            .ok_or("init next argv")?
            .iter()
            .map(|value| value.as_str().ok_or("argv string"))
            .collect::<Result<Vec<_>, _>>()?;
        let mut next = Command::new(env!("CARGO_BIN_EXE_se"));
        clean(&mut next);
        next.arg("--json").args(&argv[1..]);
        success(next.output()?)?;
    }
    let output = command(&f.options.state_directory)
        .current_dir(&f.home)
        .arg("working-state")
        .output()?;
    let error = json(&output)?;
    assert_eq!(error["code"], "project-required");
    let choices = error["detail"]["choices"]
        .as_array()
        .ok_or("registered choices")?;
    assert_eq!(choices.len(), 2);
    for id in ids {
        assert!(choices.iter().any(|value| value["id"] == id));
    }
    assert!(
        !error["message"]
            .as_str()
            .ok_or("choice message")?
            .contains("none registered")
    );
    let mut human = Command::new(env!("CARGO_BIN_EXE_se"));
    clean(&mut human);
    let human = human
        .arg("--home")
        .arg(&f.options.state_directory)
        .arg("working-state")
        .current_dir(&f.home)
        .output()?;
    let diagnostic = String::from_utf8_lossy(&human.stderr);
    assert!(
        diagnostic.contains("first-choice") && diagnostic.contains("second-choice"),
        "registered choices missing from actual plain refusal: {diagnostic}"
    );
    assert!(!diagnostic.contains("none registered"));
    Ok(())
}

/// Protects: unknown workflows use current help instead of handing users another nonexistent command; setup status never advertises an unavailable launch.
#[test]
fn compatibility_refusals_and_missing_status_use_supported_hints() -> Check {
    let f = Fixture::new()?;
    for args in [
        vec!["seat", "launch", "example"],
        vec!["agents"],
        vec!["pending"],
        vec!["rawlog-search", "text"],
        vec!["plugin"],
        vec!["backup"],
        vec!["msg", "read", "example"],
        vec!["msg", "complete", "example"],
        vec!["process", "list"],
    ] {
        let output = command(&f.options.state_directory).args(&args).output()?;
        assert!(!output.status.success());
        let error = json(&output)?;
        let hint = error["remedy"]["text"]
            .as_str()
            .ok_or("compatibility remedy")?;
        for old in [
            "se launch",
            "se stop",
            "se wake",
            "se doctor",
            "se restore",
            "se msg read",
            "se config list",
            "se agent list",
            "se decision list",
        ] {
            assert!(!hint.contains(old), "retired hint {args:?}: {hint}");
        }
    }
    let mut status = Command::new(env!("CARGO_BIN_EXE_se"));
    clean(&mut status);
    let status = status
        .arg("--home")
        .arg(&f.options.state_directory)
        .arg("status")
        .output()?;
    assert!(status.status.success());
    assert!(!String::from_utf8_lossy(&status.stdout).contains("se launch"));
    Ok(())
}

/// Protects: obsolete operator commands use the generated unknown-command refusal without opening state.
#[test]
fn obsolete_commands_use_the_live_grammar_without_opening_state() -> Check {
    let f = Fixture::new()?;
    let home = f.home.join("uncreated-state");
    for args in [
        vec!["seat", "launch", "example"],
        vec!["seat", "create", "example"],
        vec!["seat-continuity-write", "text"],
        vec!["wake", "example"],
        vec!["agents"],
        vec!["process", "start", "anything"],
        vec!["process-start", "anything"],
        vec!["stateengine_process_stop", "anything"],
        vec!["campaign"],
        vec!["merge-land"],
        vec!["floor-serve"],
        vec!["brick-build"],
        vec!["msg", "retry-delivery", "example"],
        vec!["mail-tunnel"],
        vec!["rawlog-search", "text"],
        vec!["backup"],
    ] {
        let output = command(&home).args(&args).output()?;
        assert_eq!(output.status.code(), Some(64), "{args:?}");
        let error = json(&output)?;
        assert_eq!(error["code"], "usage-unknown-command", "{args:?}: {error}");
        assert_eq!(error["remedy"]["text"], "Use `se help`", "{args:?}");
        assert!(!home.exists(), "unknown command created state: {args:?}");
    }
    Ok(())
}

/// Protects: genuine renames retain literal, supported replacement templates and stay inert.
#[test]
fn renamed_commands_keep_supported_replacements_without_opening_state() -> Check {
    let f = Fixture::new()?;
    let home = f.home.join("uncreated-state");
    for (old, replacement, help) in [
        (
            vec!["projects"],
            "se status --all",
            vec!["status", "--all", "--help"],
        ),
        (vec!["stop"], "se down", vec!["down", "--help"]),
        (
            vec!["init", "--status"],
            "se status",
            vec!["status", "--help"],
        ),
        (
            vec!["ratify", "id"],
            "se decision ratify ID",
            vec!["decision", "ratify", "--help"],
        ),
        (
            vec!["reject", "id"],
            "se decision reject ID",
            vec!["decision", "reject", "--help"],
        ),
        (
            vec!["retract", "id"],
            "se decision retract ID",
            vec!["decision", "retract", "--help"],
        ),
        (
            vec!["reverse", "id"],
            "se decision supersede ID WITH_ID",
            vec!["decision", "supersede", "--help"],
        ),
        (
            vec!["floor-event", "id"],
            "se history --event ID",
            vec!["history", "--help"],
        ),
        (
            vec!["capture-status"],
            "se status",
            vec!["status", "--help"],
        ),
        (vec!["context"], "se status", vec!["status", "--help"]),
        (
            vec!["working-state-show"],
            "se working-state",
            vec!["working-state", "--help"],
        ),
        (
            vec!["working-state-set", "text"],
            "se working-state set TEXT --expect REV",
            vec!["working-state", "set", "--help"],
        ),
    ] {
        let output = command(&home).args(&old).output()?;
        assert_eq!(output.status.code(), Some(64), "{old:?}");
        let error = json(&output)?;
        assert_eq!(error["code"], "renamed", "{old:?}: {error}");
        assert!(
            error["remedy"]["text"]
                .as_str()
                .ok_or("rename remedy")?
                .contains(replacement),
            "{error}"
        );
        let mut help_command = Command::new(env!("CARGO_BIN_EXE_se"));
        clean(&mut help_command);
        let output = help_command
            .arg("--json")
            .args(help)
            .current_dir(&f.home)
            .output()?;
        assert!(
            output.status.success(),
            "replacement help failed: {replacement}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(!home.exists(), "rename or help created state: {old:?}");
    }
    for old in ["ratifyall", "ratify"] {
        let mut args = vec![old];
        if old == "ratify" {
            args.push("all");
        }
        let error = json(&command(&home).args(args).output()?)?;
        assert_eq!(error["code"], "renamed");
        assert!(
            error["remedy"]["text"]
                .as_str()
                .ok_or("bulk remedy")?
                .contains("once per decision; no bulk approval")
        );
        assert!(!home.exists());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn terminal(command: &Command) -> Result<Output, Box<dyn std::error::Error>> {
    let argv = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|arg| arg.to_str().ok_or("UTF8 native fixture argv"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut driver = Command::new("python3");
    clean(&mut driver);
    Ok(driver.arg("-c").arg(r#"
import json,os,pty,select,signal,subprocess,sys,time
args=json.loads(sys.argv[1]);master,slave=pty.openpty()
child=subprocess.Popen(args,stdin=slave,stdout=slave,stderr=slave,start_new_session=True)
os.close(slave);deadline=time.monotonic()+20;data=bytearray()
while time.monotonic()<deadline:
    if select.select([master],[],[],.1)[0]:
        try:part=os.read(master,4096)
        except OSError:break
        if not part:break
        data.extend(part)
        if len(data)>262144:raise RuntimeError('native config output exceeded fixture budget')
    if child.poll() is not None:break
else:
    actual=open('/proc/'+str(child.pid)+'/cmdline','rb').read().split(b'\0')[:-1]
    if actual!=[os.fsencode(value) for value in args]:raise RuntimeError('owned config child identity changed; refusing signal')
    os.kill(child.pid,signal.SIGKILL);child.wait();raise RuntimeError('owned config child exceeded deadline')
os.close(master);sys.stdout.buffer.write(data);sys.exit(child.wait(timeout=3))
"#).arg(serde_json::to_string(&argv)?).output()?)
}
