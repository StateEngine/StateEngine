#![allow(
    dead_code,
    reason = "Shared native fixture also serves other store consumers."
)]
use se_store::*;
use se_types::{AgentId, HumanId, IdempotencyKey, ProjectId};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
static ROUTES: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn command(image: &Path, home: &Path, root: &Path) -> Command {
    let mut command = Command::new(image);
    command
        .args(["--json", "--home"])
        .arg(home)
        .current_dir(root);
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
    command
}
fn value(output: Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    assert!(
        output.status.success(),
        "actual CLI refused: {}; {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
// Linux can retire /proc/PID/exe before stat reports the final exited state.
// Retry only that typed observation failure, within the original cleanup bound;
// an unreadable process is never evidence of absence or permission to kill it.
fn read_exit_until(
    until: Instant,
    mut read: impl FnMut() -> se_proc::ProcResult<se_proc::ProcessRead>,
) -> Result<se_proc::ProcessRead, Box<dyn std::error::Error>> {
    let mut reported = false;
    loop {
        match read() {
            Ok(observation) => return Ok(observation),
            Err(error) => {
                let retiring_image = cfg!(target_os = "linux")
                    && error.code == se_proc::ProcErrorCode::IdentityUnreadable
                    && error.native.as_ref().is_some_and(|native| {
                        native.api == "read proc executable" && native.code == Some(2)
                    });
                if !retiring_image || Instant::now() >= until {
                    return Err(format!("outside host exit: {error:?}").into());
                }
                if !reported {
                    eprintln!("awaiting a readable native exit observation: {error:?}");
                    reported = true;
                }
                std::thread::park_timeout(
                    until
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(10)),
                );
            }
        }
    }
}
struct Host {
    image: PathBuf,
    home: PathBuf,
    root: PathBuf,
    identity: se_proc::ProcessIdentity,
    generation: u64,
    stopped: bool,
}
impl Host {
    fn start(image: &Path, home: &Path, root: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        value(command(image, home, root).arg("up").output_executable()?)?;
        let endpoint = se_host::client::endpoint::decode_endpoint(&std::fs::read(
            home.join("endpoint.json"),
        )?)?;
        let expected = endpoint.epoch.owner.fields();
        let observed = se_proc::NativeProcessRuntime::read_process(
            expected.machine.clone(),
            se_proc::ProcessId(expected.pid.get()),
        )
        .map_err(|e| format!("native host identity: {e:?}"))?;
        let se_proc::ProcessRead::Present(observed) = observed else {
            return Err("actual host is not live".into());
        };
        assert_eq!(observed.identity.pid.0, expected.pid.get());
        assert_eq!(
            std::fs::canonicalize(&observed.identity.image)?,
            std::fs::canonicalize(image)?,
            "published host PID is not running this fixture's exact image"
        );
        Ok(Self {
            image: image.into(),
            home: home.into(),
            root: root.into(),
            identity: observed.identity,
            generation: endpoint.generation.get(),
            stopped: false,
        })
    }
    fn exited(&self, until: Instant) -> Result<bool, Box<dyn std::error::Error>> {
        match read_exit_until(until, || {
            se_proc::NativeProcessRuntime::read_process(
                self.identity.machine.clone(),
                self.identity.pid,
            )
        })? {
            se_proc::ProcessRead::Absent { .. } => Ok(true),
            se_proc::ProcessRead::ExitedRecord {
                pid, boot, start, ..
            } if pid == self.identity.pid
                && boot == self.identity.boot
                && start == self.identity.start =>
            {
                Ok(true)
            }
            se_proc::ProcessRead::Present(observed) if observed.identity == self.identity => {
                Ok(observed.state == se_proc::NativeState::ExitedAwaitingReap)
            }
            _ => Err("host instance changed; refusing to stop another instance".into()),
        }
    }
    fn stop(&mut self) -> Check {
        if self.stopped {
            return Ok(());
        }
        let until = Instant::now() + Duration::from_secs(15);
        if !self.exited(until)? {
            let output = command(&self.image, &self.home, &self.root)
                .arg("down")
                .output_executable()?;
            assert!(
                matches!(output.status.code(), Some(0) | Some(2)),
                "actual down failed: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
        while !self.exited(until)? {
            if Instant::now() >= until {
                return Err("exact allocation host did not exit after graceful down".into());
            }
            std::thread::park_timeout(Duration::from_millis(10));
        }
        self.stopped = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod cleanup_observations {
    use super::*;

    fn failure(code: i64) -> se_proc::ProcError {
        se_proc::ProcError {
            code: se_proc::ProcErrorCode::IdentityUnreadable,
            detail: Box::new(se_proc::ProcErrorDetail::Input {
                field: "native operation".into(),
                reason: "read proc executable".into(),
            }),
            native: Some(se_proc::NativeFailure {
                api: "read proc executable".into(),
                code: Some(code),
                reason: "controlled native read failure".into(),
            }),
        }
    }

    #[test]
    fn cleanup_retries_retiring_image_until_actual_absence() -> Check {
        let mut calls = 0;
        let observed = read_exit_until(Instant::now() + Duration::from_secs(1), || {
            calls += 1;
            if calls == 1 {
                Err(failure(2))
            } else {
                Ok(se_proc::ProcessRead::Absent {
                    pid: se_proc::ProcessId(17),
                    observed_at_unix_ns: 1,
                })
            }
        })?;
        assert_eq!(calls, 2);
        assert!(matches!(observed, se_proc::ProcessRead::Absent { .. }));
        Ok(())
    }

    #[test]
    fn cleanup_persistent_unreadability_fails_with_its_native_cause() -> Check {
        let error = read_exit_until(Instant::now(), || Err(failure(2)))
            .err()
            .ok_or("unreadable exit became absence")?;
        assert!(error.to_string().contains("IdentityUnreadable"));
        assert!(error.to_string().contains("Some(2)"));
        Ok(())
    }

    #[test]
    fn cleanup_permission_failure_is_not_retried() -> Check {
        let mut calls = 0;
        let error = read_exit_until(Instant::now() + Duration::from_secs(1), || {
            calls += 1;
            Err(failure(13))
        })
        .err()
        .ok_or("permission failure became absence")?;
        assert_eq!(calls, 1);
        assert!(error.to_string().contains("Some(13)"));
        Ok(())
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!(
                "retaining exact allocation host {}: {error}",
                self.identity.pid.0
            );
        }
    }
}

/// Protects: the production direct allocator gives independent canonical UUIDs; same-route and hosted replay preserve original IDs, writer and durable head.
#[test]
fn direct_agent_allocations_remain_distinct_and_replay_without_new_events() -> Check {
    check(false)
}

/// Protects: real hosted receipts and stored writer facts prove the allocator route; same-route and direct replay preserve the original host writer, IDs and durable head.
#[test]
fn hosted_agent_allocations_remain_distinct_and_replay_without_new_events() -> Check {
    check(true)
}

#[expect(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn check(hosted: bool) -> Check {
    // Public init legitimately shares the native per-user installation claim.
    let _serial = ROUTES
        .lock()
        .map_err(|_| "allocation fixture mutex poisoned")?;
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let home = &f.options.state_directory;
    let installation = f.home.join("installed image");
    std::fs::create_dir(&installation)?;
    let image = installation.join(if cfg!(windows) { "se.exe" } else { "se" });
    // Cargo hard-links its Windows binary into deps. Exercise the same
    // single-link image layout as an installed archive on both platforms.
    std::fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    let root = f.home.join("allocation repository");
    std::fs::create_dir(&root)?;
    let initialized = value(
        command(&image, home, &root)
            .args(["init", "--name", "allocation-routes"])
            .output_executable()?,
    )?;
    let owner: HumanId = initialized["owner"]["human_id"]
        .as_str()
        .ok_or("init owner")?
        .parse()?;
    let project: ProjectId = initialized["project"]["id"]
        .as_str()
        .ok_or("init project")?
        .parse()?;
    let mut host = hosted
        .then(|| Host::start(&image, home, &root))
        .transpose()?;
    let expected_writer = if hosted {
        WriterKind::Host {
            generation: host
                .as_ref()
                .ok_or("missing native host witness")?
                .generation,
        }
    } else {
        WriterKind::Direct
    };
    let public_writer = match expected_writer {
        WriterKind::Direct => serde_json::json!({"mode":"direct"}),
        WriterKind::Host { generation } => {
            serde_json::json!({"mode":"host", "host_generation":generation.to_string()})
        }
    };
    let read_scope = || ReadScope {
        admission: Admission {
            scope: Scope::Project(project.clone()),
            actor: Actor::Human(owner.clone()),
            session: None,
            generation: 1,
        },
        visibility: Visibility::Owner,
    };
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut allocated = HashSet::new();
    let mut retained = Vec::new();
    for index in 0..3 {
        let name = format!("independent-{index}");
        let key = format!("route-allocation-{index}");
        let args = ["--key", key.as_str(), "agent", "add", name.as_str()];
        let first = value(
            command(&image, home, &root)
                .args(args)
                .output_executable()?,
        )?;
        assert_eq!(first["state"], "committed");
        assert_eq!(first["process_started"], false);
        assert_eq!(
            first["writer"], public_writer,
            "receipt used the wrong requested writer route"
        );
        let agent: AgentId = first["agent"]["id"]
            .as_str()
            .ok_or("allocated agent")?
            .parse()?;
        let head = reader.info()?.head;
        let mut snapshot = reader.snapshot(read_scope())?;
        let principal = present(snapshot.principal(Actor::Agent(agent.clone()))?)?;
        let profile = present(snapshot.profile(agent.clone())?)?;
        assert!(
            matches!(&profile.current.body,EventBody::ProfileSaved {agent:target,..} if target==&agent)
        );
        let receipt = present(
            snapshot.operation_receipt(Actor::Human(owner.clone()), IdempotencyKey::new(&key)?)?,
        )?;
        assert_eq!(
            receipt.writer.kind(),
            expected_writer,
            "stored receipt used the wrong writer route"
        );
        assert_eq!(principal.current.writer.kind(), expected_writer);
        assert_eq!(profile.current.writer.kind(), expected_writer);
        assert_eq!(
            receipt.events,
            vec![
                principal.current.header.event.clone(),
                profile.current.header.event.clone()
            ]
        );
        assert_eq!(first["event_id"], principal.current.header.event.as_str());
        let ids = [
            agent.canonical_bytes()?.ok_or("canonical agent")?,
            principal
                .current
                .header
                .event
                .canonical_bytes()?
                .ok_or("canonical registration")?,
            profile
                .current
                .header
                .event
                .canonical_bytes()?
                .ok_or("canonical profile")?,
        ];
        for bytes in ids {
            assert!(
                allocated.insert(bytes),
                "agent, registration or profile reused canonical allocation bytes"
            );
        }
        snapshot.close()?;
        let replay = value(
            command(&image, home, &root)
                .args(args)
                .output_executable()?,
        )?;
        assert_eq!(replay["state"], "replayed");
        assert_eq!(replay["agent"], first["agent"]);
        assert_eq!(replay["event_id"], first["event_id"]);
        assert_eq!(
            replay["writer"], first["writer"],
            "replay changed the original public writer"
        );
        let mut snapshot = reader.snapshot(read_scope())?;
        let replayed_receipt = present(
            snapshot.operation_receipt(Actor::Human(owner.clone()), IdempotencyKey::new(&key)?)?,
        )?;
        assert_eq!(
            replayed_receipt.writer.kind(),
            receipt.writer.kind(),
            "replay changed the original stored writer"
        );
        assert_eq!(replayed_receipt.events, receipt.events);
        snapshot.close()?;
        assert_eq!(
            reader.info()?.head,
            head,
            "key replay allocated durable records"
        );
        retained.push((name, key, first, receipt));
    }
    assert_eq!(allocated.len(), 9);
    // Change the actual execution route. A replay must name the original
    // committer even when the current request uses the other adapter.
    if hosted {
        host.as_mut().ok_or("missing native replay host")?.stop()?;
    } else {
        host = Some(Host::start(&image, home, &root)?);
    }
    let head = reader.info()?.head;
    for (name, key, first, original) in retained {
        let replay = value(
            command(&image, home, &root)
                .args(["--key", key.as_str(), "agent", "add", name.as_str()])
                .output_executable()?,
        )?;
        assert_eq!(replay["state"], "replayed");
        assert_eq!(replay["agent"], first["agent"]);
        assert_eq!(replay["event_id"], first["event_id"]);
        assert_eq!(
            replay["writer"], first["writer"],
            "opposite-route replay changed the original public writer"
        );
        let mut snapshot = reader.snapshot(read_scope())?;
        let receipt = present(
            snapshot.operation_receipt(Actor::Human(owner.clone()), IdempotencyKey::new(&key)?)?,
        )?;
        assert_eq!(
            receipt.writer.kind(),
            original.writer.kind(),
            "opposite-route replay changed the original stored writer"
        );
        assert_eq!(receipt.events, original.events);
        snapshot.close()?;
        assert_eq!(
            reader.info()?.head,
            head,
            "opposite-route replay allocated durable records"
        );
    }
    drop(reader);
    if let Some(host) = host.as_mut() {
        host.stop()?;
    }
    Ok(())
}

#[path = "../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
