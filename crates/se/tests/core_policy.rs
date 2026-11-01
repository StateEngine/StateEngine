#![allow(
    dead_code,
    reason = "The real native fixture is shared across consumers."
)]
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
use se_core::{
    admission::HumanTerminal,
    commit::{Cx, OpStep},
    dispatch::{CallFacts, Kernel},
    ops::{AgentCreate, AnyOp, ConfigSet, DecisionPropose},
    ports::Then,
};
use se_store::*;
use se_types::{DecisionId, IdempotencyKey};
use std::{
    path::Path,
    process::{Command, Output},
    sync::Arc,
};

type Outcome<T> = Result<T, Box<dyn std::error::Error>>;
fn setup() -> Outcome<(Fixture, SqliteDirect, Arc<Lease>)> {
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
fn kernel() -> Outcome<Kernel> {
    Ok(Kernel::new(CallFacts {
        event: event()?,
        message: message()?,
        agent: agent()?,
        profile_event: event()?,
        occurred_at_us: 1_700_000_000_000_000,
        door: Door::Cli,
    })?
    .with_configuration(se_core::config_policy::ConfigFile::default())?)
}
fn plan(
    f: &Fixture,
    store: &SqliteDirect,
    kernel: &Kernel,
    op: AnyOp,
) -> Outcome<(AtomicBatch, Then)> {
    let admission = f.owner_project();
    let mut snapshot = store.snapshot(f.scoped(Visibility::Owner))?;
    let step = kernel.plan(
        op,
        &mut Cx {
            read: &mut snapshot,
            admission: &admission,
        },
        &HumanTerminal::OutsideAgentTree,
    );
    snapshot.close()?;
    match step? {
        OpStep::Commit { batch, then } => Ok((batch, then)),
        _ => Err("expected a real keyed commit plan".into()),
    }
}
fn continued(
    f: &Fixture,
    store: &SqliteDirect,
    kernel: &Kernel,
    then: Then,
    receipt: CommitReceipt,
) -> Outcome<se_types::Result<se_core::ops::AnyOutput>> {
    let admission = f.owner_project();
    let mut snapshot = store.snapshot(f.scoped(Visibility::Owner))?;
    let result = kernel.committed(
        then,
        receipt,
        &mut Cx {
            read: &mut snapshot,
            admission: &admission,
        },
    );
    snapshot.close()?;
    Ok(result)
}
fn receipt_case(family: &str) -> Check {
    let (f, mut store, lease) = setup()?;
    let key = IdempotencyKey::new(format!("receipt-{family}"))?;
    let op = match family {
        "decision" => AnyOp::DecisionPropose(DecisionPropose {
            key: "judge.policy".into(),
            statement: "Keep the original request and event".into(),
            rationale: None,
            supersedes: None,
            idempotency_key: key.clone(),
        }),
        "agent" => AnyOp::AgentCreate(AgentCreate {
            name: "receipt-agent".into(),
            provider: None,
            model: None,
            idempotency_key: key.clone(),
        }),
        "config" => AnyOp::ConfigSet(ConfigSet {
            key: format!("agent.{}.can-create", f.a),
            value: "true".into(),
            idempotency_key: key.clone(),
        }),
        _ => return Err("unknown receipt family".into()),
    };
    let kernel = kernel()?;
    let (batch, then) = plan(&f, &store, &kernel, op.clone())?;
    let receipt = store.append(batch, &*lease)?;
    let head = store.info()?.head;
    let value = serde_json::to_value(continued(&f, &store, &kernel, then, receipt.clone())??)?;
    assert_eq!(value["idempotency_key"], key.as_str());
    assert_eq!(value["event_id"], receipt.primary_event.as_str());
    for fault in ["wrong-key", "missing-key", "missing-primary-member"] {
        let (_, then) = plan(&f, &store, &kernel, op.clone())?;
        let mut mixed = receipt.clone();
        match fault {
            "wrong-key" => mixed.request_key = Some(IdempotencyKey::new("another-call")?),
            "missing-key" => mixed.request_key = None,
            "missing-primary-member" => mixed.events.clear(),
            _ => return Err("unknown continuation fault".into()),
        }
        let error = continued(&f, &store, &kernel, then, mixed)?
            .err()
            .ok_or_else(|| format!("{family}: accepted {fault} continuation"))?;
        assert_eq!(
            error.code().as_str(),
            "source-unreadable",
            "{family}/{fault}: {error}"
        );
        assert_eq!(
            store.info()?.head,
            head,
            "continuation advanced durable history"
        );
    }
    store.close()?;
    Ok(())
}

/// Protects: decision continuation mixups refuse, while a real immutable commit keeps its original key and event.
#[test]
fn decision_receipt_uses_the_original_request() -> Check {
    receipt_case("decision")
}
/// Protects: two-event agent registration keeps its original key and refuses mismatched or incomplete continuations.
#[test]
fn agent_receipt_uses_the_original_request() -> Check {
    receipt_case("agent")
}
/// Protects: security-setting continuations keep request provenance after deduplicating the common receipt check.
#[test]
fn config_receipt_uses_the_original_request() -> Check {
    receipt_case("config")
}

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
fn command(home: &Path, project: &str, key: &str, args: &[String]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
    clean(&mut command);
    command
        .arg("--json")
        .arg("--home")
        .arg(home)
        .args(["--project", project, "--key", key])
        .args(args);
    command
}
fn json(output: &Output) -> Outcome<serde_json::Value> {
    Ok(serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "CLI JSON: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })?)
}

/// Protects: actual direct CLI pipes cannot approve decisions or change security settings after redundant presence checks disappear; a real owner PTY can perform both operations.
#[test]
fn direct_cli_keeps_fixed_and_key_selected_human_presence() -> Check {
    let (f, mut store, lease) = setup()?;
    let id = DecisionId::from_parts(1_700_000_000_000 + serial(), [90; 10])?;
    store.append(
        f.batch(
            f.owner_project(),
            None,
            vec![EventBody::DecisionProposed {
                decision: id.clone(),
                key: "presence.policy".into(),
                statement: InputText::Inline("Only the real owner approves".into()),
                rationale: None,
                prior: None,
                kind: DecisionKind::Decision,
            }],
        )?,
        &*lease,
    )?;
    let head = store.info()?.head;
    let setting = format!("agent.{}.can-create", f.a);
    let calls = [
        vec!["config".into(), "set".into(), setting, "true".into()],
        vec!["decision".into(), "ratify".into(), id.to_string()],
    ];
    for (index, args) in calls.iter().enumerate() {
        let key = format!("refused-direct-{index}");
        let output =
            command(&f.options.state_directory, f.project.as_str(), &key, args).output()?;
        assert_eq!(
            output.status.code(),
            Some(1),
            "pipe command exit: {output:?}"
        );
        assert_eq!(json(&output)?["code"], "human-terminal-required");
        assert_eq!(
            store.info()?.head,
            head,
            "refused pipe command committed effects"
        );
        let mut snapshot = store.snapshot(f.scoped(Visibility::Owner))?;
        assert!(matches!(
            snapshot.operation_receipt(Actor::Human(f.owner.clone()), IdempotencyKey::new(key)?)?,
            se_types::Read::Absent { .. }
        ));
        snapshot.close()?;
        assert!(
            !f.options
                .state_directory
                .join("endpoint.json")
                .try_exists()?,
            "direct call started a host"
        );
    }
    #[cfg(target_os = "linux")]
    for (index, args) in calls.iter().enumerate() {
        let key = format!("accepted-direct-{index}");
        let output = terminal(&command(
            &f.options.state_directory,
            f.project.as_str(),
            &key,
            args,
        ))?;
        assert!(
            output.status.success(),
            "real owner PTY refused: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let value: serde_json::Value = String::from_utf8_lossy(&output.stdout)
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str(line).ok())
            .ok_or("owner PTY JSON")?;
        assert_eq!(value["state"], "committed");
        let mut snapshot = store.snapshot(f.scoped(Visibility::Owner))?;
        let receipt = present(
            snapshot.operation_receipt(Actor::Human(f.owner.clone()), IdempotencyKey::new(key)?)?,
        )?;
        assert_eq!(value["event_id"], receipt.primary_event.as_str());
        snapshot.close()?;
    }
    let mut snapshot = store.snapshot(f.scoped(Visibility::Owner))?;
    #[cfg(target_os = "linux")]
    {
        assert!(matches!(
            present(snapshot.grant(
                Actor::Agent(f.a.clone()),
                GrantKey::AgentCanCreate(f.a.clone())
            )?)?
            .current
            .body,
            EventBody::GrantRecorded { active: true, .. }
        ));
        assert!(matches!(
            present(snapshot.decision(id)?)?.current.body,
            EventBody::DecisionRatified { .. }
        ));
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert!(matches!(
            snapshot.grant(
                Actor::Agent(f.a.clone()),
                GrantKey::AgentCanCreate(f.a.clone())
            )?,
            se_types::Read::Absent { .. }
        ));
        assert!(matches!(
            present(snapshot.decision(id)?)?.current.body,
            EventBody::DecisionProposed { .. }
        ));
    }
    snapshot.close()?;
    store.close()?;
    Ok(())
}

/// Protects: a busy writer without an endpoint cannot hide the early human-only refusal.
#[test]
fn pipe_human_presence_refuses_before_busy_writer_rendezvous() -> Check {
    let (f, mut store, lease) = setup()?;
    let id = DecisionId::from_parts(1_700_000_000_000 + serial(), [91; 10])?;
    store.append(
        f.batch(
            f.owner_project(),
            None,
            vec![EventBody::DecisionProposed {
                decision: id.clone(),
                key: "presence.busy".into(),
                statement: InputText::Inline("A busy writer cannot bypass presence".into()),
                rationale: None,
                prior: None,
                kind: DecisionKind::Decision,
            }],
        )?,
        &*lease,
    )?;
    let head = store.info()?.head;
    drop(lease);
    let holder = Lease::acquire(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(f.store.clone()),
    )?;
    let probe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.options.state_directory.join("runtime.lock"))?;
    assert!(matches!(
        probe.try_lock_shared(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    let calls = [
        vec![
            "config".into(),
            "set".into(),
            format!("agent.{}.can-create", f.a),
            "true".into(),
        ],
        vec!["decision".into(), "ratify".into(), id.to_string()],
    ];
    for (index, args) in calls.iter().enumerate() {
        let key = format!("refused-busy-{index}");
        let output =
            command(&f.options.state_directory, f.project.as_str(), &key, args).output()?;
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert_eq!(json(&output)?["code"], "human-terminal-required");
        assert_eq!(store.info()?.head, head, "refusal committed effects");
        let mut snapshot = store.snapshot(f.scoped(Visibility::Owner))?;
        assert!(matches!(
            snapshot.operation_receipt(Actor::Human(f.owner.clone()), IdempotencyKey::new(key)?)?,
            se_types::Read::Absent { .. }
        ));
        snapshot.close()?;
        assert!(
            !f.options
                .state_directory
                .join("endpoint.json")
                .try_exists()?
        );
    }
    drop(holder);
    store.close()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn terminal(command: &Command) -> Outcome<Output> {
    let argv = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|value| value.to_str().ok_or("UTF8 native fixture argv"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut driver = Command::new("python3");
    clean(&mut driver);
    Ok(driver.arg("-c").arg(r#"
import json,os,pty,select,signal,subprocess,sys,time
args=json.loads(sys.argv[1]);master,slave=pty.openpty()
child=subprocess.Popen(args,stdin=slave,stdout=slave,stderr=slave,start_new_session=True)
os.close(slave);deadline=time.monotonic()+25;data=bytearray()
while time.monotonic()<deadline:
    if select.select([master],[],[],.1)[0]:
        try:part=os.read(master,65536)
        except OSError:break
        if not part:break
        data.extend(part)
        if len(data)>262144:raise RuntimeError('owner fixture output exceeded budget')
    if child.poll() is not None:break
else:
    actual=open('/proc/'+str(child.pid)+'/cmdline','rb').read().split(b'\0')[:-1]
    if actual!=[os.fsencode(arg) for arg in args]:raise RuntimeError('owned child identity changed; refusing signal')
    os.kill(child.pid,signal.SIGKILL);child.wait();raise RuntimeError('exact owner fixture exceeded deadline')
os.close(master);sys.stdout.buffer.write(data);sys.exit(child.wait(timeout=3))
"#).arg(serde_json::to_string(&argv)?).output()?)
}
