#![allow(
    dead_code,
    reason = "Shared native fixture supports several public consumers."
)]
use se_store::*;
use se_types::EventId;
#[cfg(unix)]
use std::time::{Duration, Instant};
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
            Some(fixture::request(&format!(
                "fixture-cli_followups-59-{}",
                serial()
            ))?),
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
                Some(fixture::request(&format!(
                    "fixture-cli_followups-86-{}",
                    serial()
                ))?),
                vec![EventBody::MessageSent {
                    quiet: false,
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
            .output_executable()?,
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
        .output_executable()?;
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
            .output_executable()?,
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

/// Protects: missing selection reports both registered project choices; the first-launch hint has executable grammar and exact saved scope without spending a provider account.
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
                .output_executable()?,
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
        assert_eq!(argv.first(), Some(&"se"));
        assert!(argv.contains(&"launch") && argv.contains(&"--detach"));
        let saved_home = f.options.state_directory.to_str().ok_or("fixture UTF-8")?;
        let saved_project = initialized["project"]["id"].as_str().ok_or("project ID")?;
        assert!(argv.windows(2).any(|pair| pair == ["--home", saved_home]));
        assert!(
            argv.windows(2)
                .any(|pair| pair == ["--project", saved_project])
        );
        assert!(argv.contains(&initialized["agent"]["id"].as_str().ok_or("agent ID")?));
        next.args(&argv[1..]).arg("--help");
        let help = next.output_executable()?;
        assert!(
            help.status.success(),
            "printed launch argv refused: {}",
            String::from_utf8_lossy(&help.stderr)
        );
        assert!(String::from_utf8_lossy(&help.stdout).contains("Usage:"));
    }
    let output = command(&f.options.state_directory)
        .current_dir(&f.home)
        .arg("working-state")
        .output_executable()?;
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
        .output_executable()?;
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
        let output = command(&f.options.state_directory)
            .args(&args)
            .output_executable()?;
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
        .output_executable()?;
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
        let output = command(&home).args(&args).output_executable()?;
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
        (vec!["stop"], "se stop --all", vec!["stop", "--help"]),
        (
            vec!["init", "--status"],
            "se status",
            vec!["status", "--help"],
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
        let output = command(&home).args(&old).output_executable()?;
        assert_eq!(output.status.code(), Some(64), "{old:?}");
        let error = json(&output)?;
        if old == ["stop"] {
            assert_eq!(error["code"], "usage-missing-argument", "{error}");
            assert!(
                error["remedy"]["text"]
                    .as_str()
                    .ok_or("stop remedy")?
                    .contains("se stop AGENT")
            );
        } else {
            assert_eq!(error["code"], "renamed", "{old:?}: {error}");
        }
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
            .output_executable()?;
        assert!(
            output.status.success(),
            "replacement help failed: {replacement}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(!home.exists(), "rename or help created state: {old:?}");
    }

    Ok(())
}

/// Protects: the plain project row of status --all labels the recipient scope of its
/// unread count, and an agent's unread mail appears on the agent's own row, under both
/// the runtime-down/direct and the runtime-up/hosted read.
#[cfg(unix)]
#[test]
fn plain_status_labels_the_owner_unread_scope() -> Check {
    use std::os::unix::fs::PermissionsExt;
    let (f, mut store, lease) = setup()?;
    // Both saved agents need their saved profile for the status agent rows.
    for agent in [&f.a, &f.b] {
        store.append(
            f.batch(
                f.owner_project(),
                Some(fixture::request(&format!(
                    "fixture-cli_followups-status-agent-{}",
                    serial()
                ))?),
                vec![EventBody::ProfileSaved {
                    agent: agent.clone(),
                    profile: Profile {
                        provider: Provider::Codex,
                        model: None,
                        permission: PermissionProfile::WorkspaceWrite,
                        harness: None,
                        named_profile: "default".into(),
                        effort: None,
                    },
                    expected: Expected::Absent,
                }],
            )?,
            &*lease,
        )?;
    }
    // One unread message addressed to the saved agent; zero to the owner.
    send_to(
        &f,
        &mut store,
        &lease,
        Actor::Human(f.owner.clone()),
        Actor::Agent(f.a.clone()),
        "note",
        "agent mail",
    )?;
    let home = &f.options.state_directory;
    // The fixture store makes this home a present installation, so the installer's
    // create-once protected files must already be in place for init and up.
    let machine = format!(
        "{{\"schema\":\"stateengine-machine/v1\",\"machine_id\":\"{}\"}}",
        uuid::Uuid::new_v4()
    );
    let machine_path = home.join("machine.json");
    std::fs::write(&machine_path, machine)?;
    std::fs::set_permissions(&machine_path, std::fs::Permissions::from_mode(0o600))?;
    let credential = se_proc::random_secret()?;
    let exposed = credential.expose();
    let credential_bytes: [u8; 32] = exposed
        .get(..32)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("native entropy short")?;
    let credential_path = home.join("credential");
    std::fs::write(&credential_path, credential_bytes)?;
    std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o600))?;
    assert_plain_status_labels(home)?;
    // Release the fixture's shared lease so the independent `se init` can
    // acquire the home lease; the fixture writer has no further appends.
    store.close()?;
    drop(lease);
    // Repeat the identical reads while the runtime is up: the host keeps its writer
    // custody and status takes its short shared read.
    let repository = f.home.join("repository");
    std::fs::create_dir(&repository)?;
    let mut init = Command::new(env!("CARGO_BIN_EXE_se"));
    clean(&mut init);
    let init = init
        .arg("--home")
        .arg(home)
        .arg("init")
        .arg("--repo")
        .arg(&repository)
        .output_executable()?;
    assert!(
        init.status.success(),
        "se init refused: {} {}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    let image = f.home.join("status-se");
    std::fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    let host = StatusHost::start(&image, home)?;
    assert_plain_status_labels(home)?;
    host.stop()?;
    Ok(())
}

fn assert_plain_status_labels(home: &Path) -> Check {
    let mut status = Command::new(env!("CARGO_BIN_EXE_se"));
    clean(&mut status);
    let status = status
        .arg("--home")
        .arg(home)
        .arg("--project")
        .arg("Project")
        .arg("status")
        .output_executable()?;
    let text = String::from_utf8_lossy(&status.stdout).into_owned();
    assert!(
        status.status.success(),
        "plain status refused: {text} {}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(
        text.lines().any(|line| {
            line.trim_start().starts_with("Agent Sable: ") && line.ends_with(" — unread messages 1")
        }),
        "the agent's unread mail is missing from the plain project status:\n{text}"
    );
    assert!(
        text.contains("Owner unread messages: 0"),
        "the owner's own unread count changed: {text}"
    );
    let mut all = Command::new(env!("CARGO_BIN_EXE_se"));
    clean(&mut all);
    let all = all
        .arg("--home")
        .arg(home)
        .arg("--project")
        .arg("Project")
        .arg("status")
        .arg("--all")
        .output_executable()?;
    let text = String::from_utf8_lossy(&all.stdout).into_owned();
    assert!(
        all.status.success(),
        "plain status --all refused: {text} {}",
        String::from_utf8_lossy(&all.stderr)
    );
    let project_line = text
        .lines()
        .find(|line| line.starts_with("  Project:"))
        .ok_or("the Project row is missing from status --all")?;
    assert!(
        project_line.contains("0 unread for owner"),
        "the project row does not name the owner scope: {project_line}"
    );
    Ok(())
}

fn send_to(
    f: &Fixture,
    store: &mut SqliteDirect,
    lease: &Lease,
    sender: Actor,
    recipient: Actor,
    kind: &str,
    text: &str,
) -> Result<EventId, Box<dyn std::error::Error>> {
    Ok(store
        .append(
            f.batch(
                f.admission(Scope::Project(f.project.clone()), sender),
                Some(fixture::request(&format!(
                    "fixture-cli_followups-send-to-{}",
                    serial()
                ))?),
                vec![EventBody::MessageSent {
                    message: message()?,
                    recipient,
                    kind: kind.into(),
                    body: InputText::Inline(text.into()),
                    refs: vec![],
                    reply_to: None,
                    quiet: false,
                }],
            )?,
            lease,
        )?
        .primary_event)
}

/// Holds the exact observed native instance; PID reuse never proves its exit.
#[cfg(unix)]
struct StatusHost {
    endpoint: se_host::EndpointRecord,
    key: se_types::Secret,
    identity: se_proc::ProcessIdentity,
}
#[cfg(unix)]
impl StatusHost {
    fn start(image: &Path, home: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut up = Command::new(image);
        clean(&mut up);
        let up = up
            .arg("--json")
            .arg("--home")
            .arg(home)
            .arg("up")
            .output_executable()?;
        assert!(
            up.status.success(),
            "se up refused: {} {}",
            String::from_utf8_lossy(&up.stdout),
            String::from_utf8_lossy(&up.stderr)
        );
        let endpoint = se_host::client::endpoint::decode_endpoint(&std::fs::read(
            home.join("endpoint.json"),
        )?)?;
        let expected = endpoint.epoch.owner.fields();
        let observed = se_proc::NativeProcessRuntime::read_process_until(
            expected.machine.clone(),
            se_proc::ProcessId(expected.pid.get()),
            Instant::now() + Duration::from_secs(10),
        )
        .map_err(|error| format!("outside native host observation during start: {error:?}"))?;
        let se_proc::ProcessRead::Present(observed) = observed else {
            return Err(format!("fixture host is not live: {observed:?}").into());
        };
        assert_eq!(
            std::fs::canonicalize(&observed.identity.image)?,
            std::fs::canonicalize(image)?,
            "published host is not this fixture's copied image"
        );
        Ok(Self {
            endpoint,
            key: se_types::Secret::new(std::fs::read(home.join("credential"))?)?,
            identity: observed.identity,
        })
    }
    fn live_until(
        &self,
        deadline: Instant,
        phase: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match se_proc::NativeProcessRuntime::read_process_until(
            self.identity.machine.clone(),
            self.identity.pid,
            deadline,
        ) {
            Ok(read) => self.classify(read, phase),
            Err(error) if Self::exit_race(&error) => self.settle_exit_race(error),
            Err(error) => {
                Err(format!("outside native host observation during {phase}: {error:?}").into())
            }
        }
    }

    /// The kernel can drop /proc/PID/exe while the exiting instance's state
    /// has not reached zombie yet, and that window can outlast one re-read.
    /// Poll the bounded observation until it settles: absence or our exact
    /// zombie proves the exit, a live exact instance means the refusal was
    /// transient, and anything else keeps the original error.
    fn settle_exit_race(
        &self,
        original: se_proc::ProcError,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match se_proc::NativeProcessRuntime::read_process_until(
                self.identity.machine.clone(),
                self.identity.pid,
                Instant::now() + Duration::from_millis(100),
            ) {
                Ok(read) => return self.classify(read, "exit-race confirmation"),
                Err(again) if Self::exit_race(&again) => {
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "exit-race confirmation unsettled: original {original:?}, last {again:?}"
                        )
                        .into());
                    }
                    std::thread::park_timeout(Duration::from_millis(10));
                }
                Err(again) => {
                    return Err(format!(
                        "exit-race confirmation failed: original {original:?}, confirmation {again:?}"
                    )
                    .into());
                }
            }
        }
    }

    /// The exact read_process signature of that exit race: the executable read
    /// failed with a not-found native code while a same-born instance still
    /// existed. Classified through std so the test needs no native dependency.
    fn exit_race(error: &se_proc::ProcError) -> bool {
        let Some(native) = error.native.as_ref() else {
            return false;
        };
        error.code == se_proc::ProcErrorCode::IdentityUnreadable
            && native.api == "read proc executable"
            && native.code.is_some_and(|code| {
                let Ok(code) = i32::try_from(code) else {
                    return false;
                };
                std::io::Error::from_raw_os_error(code).kind() == std::io::ErrorKind::NotFound
            })
    }

    fn classify(
        &self,
        read: se_proc::ProcessRead,
        phase: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match read {
            se_proc::ProcessRead::Present(observed) if observed.identity == self.identity => {
                Ok(!matches!(
                    observed.state,
                    se_proc::NativeState::Exited | se_proc::NativeState::ExitedAwaitingReap
                ))
            }
            se_proc::ProcessRead::Absent { .. } => Ok(false),
            se_proc::ProcessRead::ExitedRecord {
                pid, boot, start, ..
            } if pid == self.identity.pid
                && boot == self.identity.boot
                && start == self.identity.start =>
            {
                Ok(false)
            }
            other => Err(format!(
                "host identity changed during {phase}; refusing to act on another instance: {other:?}"
            )
            .into()),
        }
    }
    fn live(&self) -> Result<bool, Box<dyn std::error::Error>> {
        self.live_until(Instant::now() + Duration::from_secs(10), "live")
    }
    fn stop(&self) -> Check {
        if !self
            .live()
            .map_err(|error| format!("stop preflight: {error}"))?
        {
            return Ok(());
        }
        let until = se_types::UnixMicros::new(
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_micros()
                + 5_000_000) as u64,
        )?;
        se_host::client::BlockingIpcClient::stop(
            &self.endpoint,
            &self.key,
            se_types::IdempotencyKey::new("plain-status-fixture-cleanup")?,
            until,
            &se_host::client::ClientOptions {
                expected_generation: Some(self.endpoint.generation),
                timeout: Duration::from_secs(5),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
        )?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.live_until(deadline, "stop exit")? {
            if Instant::now() >= deadline {
                return Err("exact fixture host did not exit after graceful stop".into());
            }
            std::thread::park_timeout(Duration::from_millis(10));
        }
        Ok(())
    }
}
#[cfg(unix)]
impl Drop for StatusHost {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!(
                "retaining exact runtime fixture host {}: {error}",
                self.identity.pid.0
            );
        }
    }
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
"#).arg(serde_json::to_string(&argv)?).output_executable()?)
}

#[path = "../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
