//! Execute resume's recovery argv verbatim with a different ambient data home.
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
use se_store::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
mod capture;
use serde_json::Value;
use std::{collections::BTreeSet, fs, process::Command};

fn run(f: &Fixture, args: &[String]) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_se"))
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").ok_or("PATH absent")?)
        .env("HOME", f.home.join("unrelated default"))
        .env("USERPROFILE", f.home.join("unrelated default"))
        .current_dir(&f.home)
        .output()?)
}
fn commands(value: &Value, out: &mut Vec<(Vec<String>, String)>) -> Check {
    match value {
        Value::Object(map) => {
            if map
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(|v| v.starts_with("se "))
            {
                assert!(
                    map.get("argv")
                        .and_then(Value::as_array)
                        .is_some_and(|v| !v.is_empty()),
                    "printed recovery command lost its runnable argv: {value}"
                );
            }
            if let Some(Value::Array(words)) = map.get("argv")
                && !words.is_empty()
            {
                let argv = words
                    .iter()
                    .map(|v| v.as_str().map(str::to_owned).ok_or("non-string argv"))
                    .collect::<Result<Vec<_>, _>>()?;
                if argv.first().is_some_and(|v| v == "se") {
                    out.push((
                        argv,
                        map.get("command")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .into(),
                    ));
                }
            }
            for child in map.values() {
                commands(child, out)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                commands(child, out)?;
            }
        }
        _ => (),
    }
    Ok(())
}
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn preview_succeeds_when_only_turns_are_omitted_for_packet_budget() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let session = capture::session()?;
    let source = capture::record()?;
    capture::active(&f, &mut store, &lease, &session, source)?;
    store.append(
        f.batch(
            f.owner_project(),
            Some(request("preview-budget-profile")?),
            vec![EventBody::ProfileSaved {
                agent: f.a.clone(),
                profile: Profile {
                    provider: Provider::Claude,
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
    for n in 0..6 {
        let mut captured = capture::capture(
            &f,
            &session,
            source,
            b"first",
            n * 10,
            n + 1,
            &format!("preview budget turn {n}: {}", "context ".repeat(60)),
        )?;
        for event in &mut captured.events {
            event.header.door = Door::Hook;
        }
        store.append(captured, &*lease)?;
    }
    store.append(
        f.send(
            Actor::Agent(f.b.clone()),
            Actor::Agent(f.a.clone()),
            message()?,
            "A fully visible unread message remains unacknowledged.",
            "preview-visible-unread",
        )?,
        &*lease,
    )?;
    let head = store.info()?.head;
    // The same budget omission still blocks an actual bound agent resume.
    let mut scope = f.self_scope(&f.a);
    scope.admission.session = Some(session);
    let admission = scope.admission.clone();
    let mut read = store.snapshot(scope)?;
    let bound = se_core::ops::continuity::resume(
        se_core::ops::continuity::Resume {
            limit: 20,
            since: None,
            byte_budget: 4096,
            preview_agent: None,
        },
        se_types::UnixMicros::new(1_800_000_000_000_000)?,
        &mut se_core::commit::Cx {
            read: &mut read,
            admission: &admission,
        },
    )?;
    assert!(!bound.complete && !bound.omissions.is_empty());
    assert_eq!(se_core::ops::AnyOutput::from(bound).exit_code(), 2);
    read.close()?;
    store.close()?;
    drop(lease);
    let args = [
        "--home",
        f.options.state_directory.to_str().ok_or("home")?,
        "--project",
        f.project.as_str(),
        "resume",
        "--preview",
        f.a.as_str(),
    ];
    for mode in ["--json", "--no-color", "--quiet"] {
        let mut words = args.map(str::to_owned).to_vec();
        words.push(mode.into());
        let output = run(&f, &words)?;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{mode}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if mode == "--json" {
            let value: Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(value["complete"], false);
            assert_eq!(value["resume_status"], "needs_read");
            assert_eq!(value["required_reads"].as_array().ok_or("reads")?.len(), 1);
            let omissions = value["omissions"].as_array().ok_or("omissions")?;
            assert!(!omissions.is_empty());
            assert!(
                omissions
                    .iter()
                    .all(|item| item["section"] == "recent_turns"
                        && item["reason"] == "packet byte budget")
            );
            assert!(serde_json::to_vec(&value)?.len() <= 4096);
        } else if mode == "--no-color" {
            let text = String::from_utf8(output.stdout)?;
            assert!(text.contains("Omitted recent_turns") && text.contains("packet byte budget"));
            assert!(text.contains("complete: false"));
        }
    }
    // A source-page limit is distinct from intentionally fitting the packet.
    let mut limited = args.map(str::to_owned).to_vec();
    limited.extend(["--limit", "1", "--budget", "32768", "--json"].map(str::to_owned));
    let output = run(&f, &limited)?;
    assert_eq!(output.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&output.stdout)?;
    assert!(
        value["omissions"]
            .as_array()
            .ok_or("limit omissions")?
            .iter()
            .any(|item| item["reason"] != "packet byte budget")
    );
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    assert_eq!(reader.info()?.head, head, "preview wrote state");
    Ok(())
}
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
#[cfg_attr(
    not(windows),
    expect(
        clippy::cognitive_complexity,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )
)]
fn every_resume_recovery_argv_reaches_the_selected_home_without_writing() -> Check {
    let mut f = Fixture::new()?;
    let renamed = f.home.with_extension("selected home ' 日本語");
    fs::rename(&f.home, &renamed)?;
    f.home = renamed;
    f.options.state_directory = f.home.join("state");
    fs::create_dir(f.home.join("unrelated default"))?;
    let (mut store, lease) = f.direct()?;
    let session = capture::session()?;
    let source = capture::record()?;
    capture::active(&f, &mut store, &lease, &session, source)?;
    for n in 0..3 {
        let mut captured = capture::capture(
            &f,
            &session,
            source,
            b"first",
            n * 10,
            n + 1,
            &format!("scope turn {n} {}", "long captured content ".repeat(100)),
        )?;
        // Public history requires the capture producer's real provenance door.
        for event in &mut captured.events {
            event.header.door = Door::Hook;
        }
        store.append(captured, &*lease)?;
    }
    store.append(
        f.batch(
            f.owner_project(),
            Some(request("scope-profile")?),
            vec![EventBody::ProfileSaved {
                agent: f.a.clone(),
                profile: Profile {
                    provider: Provider::Claude,
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
    store.append(
        f.working(
            &"saved working note 🦊 ".repeat(600),
            Expected::Absent,
            "scope-working",
        )?,
        &*lease,
    )?;
    store.append(
        f.send(
            Actor::Agent(f.b.clone()),
            Actor::Agent(f.a.clone()),
            message()?,
            &"scope unread body ".repeat(80),
            "scope-unread",
        )?,
        &*lease,
    )?;
    let head = store.info()?.head;
    store.close()?;
    drop(lease);
    let home = f.options.state_directory.to_str().ok_or("home encoding")?;
    let mut seen = BTreeSet::new();
    let mut executed = 0;
    for budget in [4096, 8192, 32768] {
        let args = [
            "--json",
            "--home",
            home,
            "--project",
            f.project.as_str(),
            "resume",
            "--preview",
            f.a.as_str(),
            "--limit",
            "1",
            "--budget",
            &budget.to_string(),
        ]
        .map(str::to_owned);
        let output = run(&f, &args)?;
        assert!(
            output.status.code() == Some(2),
            "resume failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout)?;
        assert!(serde_json::to_vec(&value)?.len() <= budget);
        assert_eq!(
            value["budget"]["used_bytes"],
            serde_json::to_vec(&value)?.len()
        );
        let mut printed = Vec::new();
        commands(&value, &mut printed)?;
        assert!(!printed.is_empty(), "fixture produced no recovery commands");
        for (argv, command) in printed {
            assert_eq!(
                &argv[..5],
                ["se", "--home", home, "--project", f.project.as_str()]
            );
            seen.insert(argv[5].clone());
            let rendered = se_core::ops::AgentCommand::from_argv(argv.clone())
                .ok_or("unrenderable command")?;
            assert_eq!(command, rendered.command);
            let recovered = run(&f, &argv[1..])?;
            executed += 1;
            assert!(
                matches!(recovered.status.code(), Some(0 | 2)),
                "literal argv {argv:?} failed: {} {}",
                String::from_utf8_lossy(&recovered.stdout),
                String::from_utf8_lossy(&recovered.stderr)
            );
            let text = String::from_utf8(recovered.stdout)?;
            let marker = match argv[5].as_str() {
                "history" => "scope turn",
                "msg" => "scope unread body",
                "working-state" => "saved working note",
                "resume" => "Sable",
                _ => return Err("unexpected recovery operation".into()),
            };
            assert!(
                text.contains(marker),
                "recovery missed selected content: {text}"
            );
        }
        #[cfg(unix)]
        {
            let plain_args = args[1..].to_vec();
            let plain = run(&f, &plain_args)?;
            assert_eq!(plain.status.code(), Some(2));
            let plain = String::from_utf8(plain.stdout)?;
            for line in plain.lines() {
                let command = line
                    .split_once(": ")
                    .map(|(_, text)| text)
                    .filter(|v| v.starts_with("se "));
                if let Some(command) = command {
                    // The shell only decodes the emitted quoting into literal words.
                    let decoded = Command::new("sh")
                        .args(["-c", &format!("set -- {command}; printf '%s\\0' \"$@\"")])
                        .output()?;
                    assert!(decoded.status.success());
                    let words = decoded
                        .stdout
                        .split(|v| *v == 0)
                        .filter(|v| !v.is_empty())
                        .map(|v| String::from_utf8(v.to_vec()))
                        .collect::<Result<Vec<_>, _>>()?;
                    assert_eq!(
                        &words[..5],
                        ["se", "--home", home, "--project", f.project.as_str()]
                    );
                    let recovered = run(&f, &words[1..])?;
                    executed += 1;
                    assert!(
                        matches!(recovered.status.code(), Some(0 | 2)),
                        "plain command failed: {command}"
                    );
                }
            }
        }
    }
    assert!(
        seen.contains("history") && seen.contains("msg") && seen.contains("working-state"),
        "unexercised recovery paths: {seen:?}"
    );
    let refusal = run(
        &f,
        &[
            "--json",
            "--home",
            home,
            "--project",
            f.project.as_str(),
            "resume",
            "--preview",
            f.a.as_str(),
            "--budget",
            "1024",
        ]
        .map(str::to_owned),
    )?;
    let refusal: Value = serde_json::from_slice(&refusal.stdout)?;
    let retry = refusal["remedy"]["command"]["argv"]
        .as_array()
        .ok_or("small-budget refusal lost its literal recovery")?
        .iter()
        .map(|word| word.as_str().map(str::to_owned).ok_or("non-string retry"))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        &retry[..5],
        ["se", "--home", home, "--project", f.project.as_str()]
    );
    let recovered = run(&f, &retry[1..])?;
    assert!(
        matches!(recovered.status.code(), Some(0 | 2)),
        "budget retry failed: {}",
        String::from_utf8_lossy(&recovered.stdout)
    );
    let recovered: Value = serde_json::from_slice(
        &run(&f, &[vec!["--json".into()], retry[1..].to_vec()].concat())?.stdout,
    )?;
    assert_eq!(recovered["schema"], "se.resume/v1");
    assert_eq!(
        recovered["budget"]["used_bytes"],
        serde_json::to_vec(&recovered)?.len()
    );
    executed += 2;
    assert!(
        recovered["budget"]["used_bytes"]
            .as_u64()
            .ok_or("missing size")?
            <= recovered["budget"]["limit_bytes"]
                .as_u64()
                .ok_or("missing limit")?
    );
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    assert_eq!(reader.info()?.head, head, "context or recovery wrote state");
    println!("literal recovery commands executed: {executed}; store writes: 0");
    Ok(())
}

#[test]
fn bound_resume_and_session_context_share_scoped_commands_and_exact_budgets() -> Check {
    use se_core::{
        admission::HumanTerminal,
        commit::{Cx, OpStep},
        dispatch::Kernel,
        ops::{
            AnyOp,
            continuity::{Resume, SessionContextRequest},
        },
    };
    use se_types::UnixMicros;
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let session = capture::session()?;
    let source = capture::record()?;
    capture::active(&f, &mut store, &lease, &session, source)?;
    store.append(
        capture::capture(&f, &session, source, b"first", 0, 1, "bound scope marker")?,
        &*lease,
    )?;
    let mut scope = f.self_scope(&f.a);
    scope.admission.session = Some(session);
    let admission = scope.admission.clone();
    let mut read = store.snapshot(scope)?;
    let home = f.options.state_directory.to_str().ok_or("home encoding")?;
    let kernel = Kernel::read_only_at(UnixMicros::new(1_800_000_000_000_000)?)
        .with_command_home(&f.options.state_directory);
    for op in [
        AnyOp::Resume(Resume {
            limit: 20,
            since: None,
            byte_budget: 32768,
            preview_agent: None,
        }),
        AnyOp::SessionContext(SessionContextRequest {
            limit: 20,
            since: None,
            byte_budget: 32768,
        }),
    ] {
        let output = kernel.plan(
            op,
            &mut Cx {
                read: &mut read,
                admission: &admission,
            },
            &HumanTerminal::Refused {
                reason: "bound agent read".into(),
            },
        )?;
        let OpStep::Complete(output) = output else {
            return Err("read produced effects".into());
        };
        let value = serde_json::to_value(output)?;
        assert!(serde_json::to_vec(&value)?.len() <= 32768);
        let value = if let Some(input) = value.get("assembled_model_input").and_then(Value::as_str)
        {
            serde_json::from_str(input)?
        } else {
            value
        };
        let mut printed = Vec::new();
        commands(&value, &mut printed)?;
        assert!(
            !printed.is_empty(),
            "bound context lost captured turn recovery"
        );
        for (argv, _) in printed {
            assert_eq!(
                &argv[..5],
                ["se", "--home", home, "--project", f.project.as_str()]
            );
        }
    }
    read.close()?;
    store.close()?;
    drop(lease);
    Ok(())
}
