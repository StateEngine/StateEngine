//! Reviewer judge for temporary agents on a real host, driven through the
//! public CLI and MCP with a native provider double. A temporary child stops
//! with its parent without being retired, `se down` keeps it, an expired one
//! is retired by the host (at startup or on its deadline) and then refuses
//! launch, wake and mail by name. No product path creates temporary agents
//! yet, so the helper below records them through the store while the host is
//! down, exactly as a direct-mode client would.
#![cfg(target_os = "linux")]
use se_store::*;
use se_types::{AgentId, EventId, HumanId, ProjectId};
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[path = "../../test-support/directory.rs"]
mod directory;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::{Check, Lease, present, request};

type Boxed<T> = Result<T, Box<dyn std::error::Error>>;

fn var(name: &str) -> Boxed<String> {
    std::env::var(name).map_err(|_| format!("{name} is not set").into())
}

/// Identity parts unique across helper runs, unlike the per-process fixture serial.
fn parts(salt: u8) -> Boxed<(u64, [u8; 10])> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let nanos = now.subsec_nanos().to_le_bytes();
    let pid = std::process::id().to_le_bytes();
    let tail = [
        nanos[0], nanos[1], nanos[2], nanos[3], pid[0], pid[1], pid[2], pid[3], salt, 0x5e,
    ];
    Ok((u64::try_from(now.as_millis())?, tail))
}

fn now_us() -> Boxed<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros(),
    )?)
}

/// Registers one temporary child of `REVIEW_PARENT` with the parent's saved
/// profile. Run only by the judge, only while the host is down.
#[test]
#[ignore = "judge helper: ephemeral_host_review.py runs it while the host is down"]
fn inject_temporary_agent() -> Check {
    let state = PathBuf::from(var("REVIEW_STATE")?);
    let project: ProjectId = var("REVIEW_PROJECT")?.parse()?;
    let owner: HumanId = var("REVIEW_OWNER")?.parse()?;
    let parent: AgentId = var("REVIEW_PARENT")?.parse()?;
    let name = var("REVIEW_NAME")?;
    let ttl_seconds: u32 = var("REVIEW_TTL")?.parse()?;
    let options = StoreOptions {
        state_directory: state.clone(),
        busy_timeout: Duration::from_secs(5),
    };
    let admission = Admission {
        scope: Scope::Project(project),
        actor: Actor::Human(owner.clone()),
        session: None,
        generation: 1,
    };
    let reader = present(SqliteFactory::open_reader(&options)?)?;
    let info = reader.info()?;
    let mut snapshot = reader.snapshot(ReadScope {
        admission: admission.clone(),
        visibility: Visibility::Owner,
    })?;
    let saved = present(snapshot.profile(parent.clone())?)?;
    snapshot.close()?;
    drop(reader);
    let EventBody::ProfileSaved { profile, .. } = saved.current.body else {
        return Err("the parent has no saved profile".into());
    };
    let (ms, tail) = parts(1)?;
    let child = AgentId::from_parts(ms, tail)?;
    let occurred_at_us = now_us()?;
    let mut events = Vec::new();
    for (salt, body) in [
        (
            2,
            EventBody::PrincipalRegistered {
                principal: Actor::Agent(child.clone()),
                kind: PrincipalKind::Agent,
                owner,
                created_by: Some(Actor::Agent(parent)),
                name: name.clone(),
                role: String::new(),
                ephemeral: Some(EphemeralSpec {
                    one_shot: false,
                    ttl_seconds,
                }),
                expected: Expected::Absent,
            },
        ),
        (
            3,
            EventBody::ProfileSaved {
                agent: child.clone(),
                profile,
                expected: Expected::Absent,
            },
        ),
    ] {
        let (ms, tail) = parts(salt)?;
        events.push(NewEvent {
            header: EventHeader {
                event: EventId::from_parts(ms, tail)?,
                scope: admission.scope.clone(),
                actor: admission.actor.clone(),
                session: None,
                origin: info.id.clone(),
                door: Door::Cli,
                occurred_at_us,
                cause: None,
                supersedes: None,
            },
            body,
        });
    }
    let lease = Lease::acquire(&state, LeaseMode::DirectClient, Some(info.id.clone()))?;
    let mut direct = present(SqliteFactory::open_direct(&options, &*lease)?)?;
    direct.append(
        AtomicBatch {
            expected_incarnation: info.incarnation,
            admission,
            request: Some(request(&format!("review-temporary-{name}-{ms}"))?),
            events,
            import_checkpoint: None,
        },
        &*lease,
    )?;
    direct.close()?;
    std::fs::write(var("REVIEW_OUT")?, child.as_str())?;
    Ok(())
}

/// Protects: the parent's end stops its temporary child within its budget
/// without retiring it, `se down` keeps the child, and the host retires an
/// expired child at startup and on its deadline, after which launch, resume,
/// force, wake, owner mail and peer mail all refuse it by name.
#[test]
fn temporary_children_follow_their_parent_and_their_deadline() -> Check {
    let parent = directory::private_directory()?;
    let root = parent.join("output");
    let helper = std::env::current_exe()?;
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/judges/ephemeral_host_review.py"
        ))
        .arg("--se")
        .arg(env!("CARGO_BIN_EXE_se"))
        .arg("--helper")
        .arg(helper)
        .arg("--output")
        .arg(&root)
        .output()?;
    assert!(
        output.status.success(),
        "temporary agent judge failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
