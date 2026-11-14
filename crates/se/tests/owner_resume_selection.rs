//! The owner can follow a resume refusal to the actual saved-agent catalogue.
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
use se_store::*;
use std::process::{Command, Output};

fn run(f: &Fixture, args: &[String]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_se"))
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").ok_or("PATH absent")?)
        .env("HOME", &f.home)
        .env("USERPROFILE", &f.home)
        .current_dir(&f.home)
        .output()?)
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn owner_resume_refusal_lists_saved_agents_with_the_exact_home_and_project() -> Check {
    let mut f = Fixture::new()?;
    let renamed = f.home.with_extension("owner's selected home");
    f.move_home(renamed)?;
    let (mut store, lease) = f.direct()?;
    for (agent, key) in [(&f.a, "profile-a"), (&f.b, "profile-b")] {
        store.append(
            f.batch(
                f.owner_project(),
                Some(request(key)?),
                vec![EventBody::ProfileSaved {
                    agent: agent.clone(),
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
    }
    let head = store.info()?.head;
    store.close()?;
    drop(lease);
    let args = vec![
        "--home".into(),
        f.options
            .state_directory
            .to_str()
            .ok_or("home encoding")?
            .into(),
        "--project".into(),
        f.project.to_string(),
        "resume".into(),
    ];
    let plain = run(&f, &args)?;
    assert_eq!(plain.status.code(), Some(64));
    assert!(plain.stdout.is_empty());
    let mut json_args = vec!["--json".into()];
    json_args.extend(args.clone());
    let output = run(&f, &json_args)?;
    assert_eq!(output.status.code(), Some(64));
    let error: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(error["code"], "usage-missing-argument");
    let argv = error["remedy"]["command"]["argv"]
        .as_array()
        .ok_or("owner resume refusal omitted its executable selection remedy")?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or("non-string remedy argument")
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        argv,
        [
            "se",
            "--home",
            f.options.state_directory.to_str().ok_or("home encoding")?,
            "--project",
            f.project.as_str(),
            "agent",
            "list"
        ]
    );
    let quoted = se_core::ops::AgentCommand::from_argv(argv.clone())
        .ok_or("unrenderable selection command")?;
    let text = String::from_utf8(plain.stderr)?;
    assert!(
        text.contains(&quoted.command),
        "plain refusal lost its literal recovery command: {text}"
    );
    assert!(
        text.contains("does not restart"),
        "context inspection was not distinguished from provider restart: {text}"
    );
    let listed = run(&f, &argv[1..])?;
    assert!(
        listed.status.success(),
        "literal selection remedy failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed = String::from_utf8(listed.stdout)?;
    assert!(
        listed.contains("Sable") && listed.contains("Juniper"),
        "selection remedy did not list both saved agents: {listed}"
    );
    let mut preview = args;
    preview.extend(["--preview".into(), f.a.to_string()]);
    let preview = run(&f, &preview)?;
    assert!(
        preview.status.success(),
        "explicit owner preview failed: {}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    assert_eq!(reader.info()?.head, head, "inspection wrote durable state");
    Ok(())
}
