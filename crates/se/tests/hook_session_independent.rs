//! Public CLI boundary: typed store setup is not a provider launch witness.
use se_store::*;
use se_types::{AgentId, LifecycleId};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/wave2_control_fixture.rs"]
#[allow(dead_code, reason = "Only typed process-fence setup is needed.")]
mod process;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(dead_code, reason = "Only session event constructors are needed.")]
mod session;

fn command(image: &Path, f: &Fixture, root: &Path) -> Command {
    let mut command = Command::new(image);
    command
        .args(["--json", "--home"])
        .arg(&f.options.state_directory)
        .current_dir(root);
    for (name, _) in std::env::vars_os() {
        let value = name.to_string_lossy();
        if value.starts_with("SE_")
            || value.starts_with("STATEENGINE_")
            || value.starts_with("CODEX_")
            || value == "CLAUDECODE"
        {
            command.env_remove(name);
        }
    }
    command
}
fn checked(
    image: &Path,
    f: &Fixture,
    root: &Path,
    label: &str,
    args: &[&str],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let output = command(image, f, root).args(args).output()?;
    std::fs::write(f.home.join(format!("{label}.stdout")), &output.stdout)?;
    std::fs::write(f.home.join(format!("{label}.stderr")), &output.stderr)?;
    assert!(
        output.status.success(),
        "{label} failed; retained {}",
        f.home.display()
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

/// Protects: invalid hook credentials refuse before reading stdin or starting a
/// host; current Prepared/Active credentials still reach native payload parsing.
fn check_case(case: &str) -> Check {
    se_proc::initialize_file_creation_owner()?;
    let mut f = std::mem::ManuallyDrop::new(Fixture::new()?);
    println!(
        "hook review case={case} retained-on-failure={}",
        f.home.display()
    );
    let root = f.home.join("repository");
    std::fs::create_dir(&root)?;
    let source = std::env::var_os("SE_HOOK_REVIEW_SE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_se").into());
    // Windows runtime pinning requires one link; Cargo hard-links its binary.
    #[cfg(windows)]
    let image = {
        let image = f.home.join("hook-review-se.exe");
        std::fs::copy(source, &image)?;
        image
    };
    // Unix forks can inherit a writable copied inode even after close/rename.
    #[cfg(not(windows))]
    let image = source;
    let initialized = checked(
        &image,
        &f,
        &root,
        "init",
        &[
            "init",
            "--repo",
            root.to_str().ok_or("UTF-8 fixture root")?,
            "--name",
            "Hook reviewer",
            "--agent",
            "Judge",
            "--provider",
            "claude",
            "--model",
            "claude-sonnet-5-5",
        ],
    )?;
    f.owner = initialized["profile"]["human_id"]
        .as_str()
        .ok_or("human id")?
        .parse()?;
    f.project = initialized["profile"]["project"]
        .as_str()
        .ok_or("project id")?
        .parse()?;
    f.a = initialized["profile"]["agent_id"]
        .as_str()
        .ok_or("agent id")?
        .parse()?;
    let up = checked(&image, &f, &root, "up", &["up"])?;
    let pid = u32::try_from(up["process"]["pid"].as_u64().ok_or("host PID absent")?)?;
    let native = se_proc::read_process(
        se_types::MachineId::new("hook-review")?,
        se_proc::ProcessId(pid),
    )
    .map_err(|e| format!("native host identity: {e:?}"))?;
    let se_proc::ProcessRead::Present(original) = native else {
        return Err("started host is absent".into());
    };
    let output = command(&image, &f, &root).arg("down").output()?;
    std::fs::write(f.home.join("down.stdout"), &output.stdout)?;
    std::fs::write(f.home.join("down.stderr"), &output.stderr)?;
    // Seed sessions only after the public shutdown succeeds and the outside
    // native observer confirms that this exact fixture owner has exited.
    assert!(
        output.status.success(),
        "fixture shutdown did not complete; retained {}",
        f.home.display()
    );
    let down: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(down["schema"], "se.runtime-stop/v1");
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match se_proc::read_process(original.identity.machine.clone(), original.identity.pid) {
            Ok(se_proc::ProcessRead::Absent { .. } | se_proc::ProcessRead::ExitedRecord { .. }) => {
                break;
            }
            Ok(se_proc::ProcessRead::Present(value))
                if value.identity == original.identity
                    && value.state == se_proc::NativeState::ExitedAwaitingReap =>
            {
                break;
            }
            Ok(se_proc::ProcessRead::Present(value)) if value.identity != original.identity => {
                return Err("fixture PID was reused before exit proof".into());
            }
            value => {
                if Instant::now() >= until {
                    return Err(format!("fixture owner exit remained unproved: {value:?}").into());
                }
                std::thread::park_timeout(Duration::from_millis(10));
            }
        }
    }
    assert!(
        !f.options
            .state_directory
            .join("endpoint.json")
            .try_exists()?
    );
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.options.state_directory.join("runtime.lock"))?;
    lock.try_lock()?;
    drop(lock);
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    f.store = reader.info()?.id;
    let lease = Lease::acquire(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(f.store.clone()),
    )?;
    let host = present(SqliteFactory::open_host(&f.options, &*lease)?)?;
    let owner = host.start_writer(
        WriterOptions {
            maximum_requests: std::num::NonZeroU16::new(4).ok_or("request capacity")?,
            queue_requests: std::num::NonZeroU16::new(8).ok_or("queue capacity")?,
            resident_bytes: std::num::NonZeroU32::new(1048576).ok_or("resident capacity")?,
            group_bytes: std::num::NonZeroU32::new(1048576).ok_or("group capacity")?,
        },
        lease.clone(),
    )?;
    let mut writer = HostAppender {
        client: owner.client(),
        owner,
        runtime: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    };
    let id = session::session()?;
    let credential = session::record()?;
    let token =
        se_types::Secret::new(format!("sec1.{}.{}", id.as_str(), "A".repeat(43)).into_bytes())?;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    let mut bodies = vec![
        session::prepared(&f, &id, &f.a),
        EventBody::CredentialIssued {
            credential,
            session: id.clone(),
            purpose: if case == "purpose" { "http" } else { "session" }.into(),
            secret_sha256: Sha256::digest(token.expose()).into(),
            expires_at_us: now
                + if case == "expired" {
                    3_100_000
                } else {
                    300_000_000
                },
            activation_deadline_us: now
                + if matches!(case, "expired" | "deadline") {
                    3_000_000
                } else {
                    60_000_000
                },
            expected: Expected::Absent,
        },
    ];
    if case == "active" {
        bodies.extend([
            session::activated(&id)?,
            EventBody::CredentialActivated {
                credential,
                session: id.clone(),
                expected: revision(1)?,
                first_request: session::record()?,
            },
        ]);
    }
    if case == "revoked" {
        bodies.push(EventBody::CredentialRevoked {
            credential,
            expected: revision(1)?,
            reason: InputText::Inline("reviewer revocation".into()),
        });
    }
    if case == "superseded" {
        bodies.push(session::prepared(&f, &session::session()?, &f.a));
    }
    let receipt = writer.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request(&format!(
                "fixture-hook_session_independent-240-{}",
                serial()
            ))?),
            bodies,
        )?,
        &lease,
    )?;
    if case == "stop-unproved" {
        let mut identity = process::identity(&f.a)?;
        identity.session = Some(id.clone());
        writer.append(
            f.batch(
                f.owner_project(),
                Some(fixture::request(&format!(
                    "fixture-hook_session_independent-245-{}",
                    serial()
                ))?),
                vec![process::registration(&identity, ProcessState::Starting)],
            )?,
            &lease,
        )?;
        writer.append(
            f.batch(
                f.owner_project(),
                Some(fixture::request(&format!(
                    "fixture-hook_session_independent-253-{}",
                    serial()
                ))?),
                vec![
                    process::transition(
                        &identity,
                        1,
                        ProcessState::Starting,
                        ProcessState::StopRequested,
                        receipt.primary_event.clone(),
                    )?,
                    process::transition(
                        &identity,
                        2,
                        ProcessState::StopRequested,
                        ProcessState::StopUnproved,
                        receipt.primary_event,
                    )?,
                ],
            )?,
            &lease,
        )?;
    }
    writer.close()?;
    drop(lease);
    se_proc::publish_session_pin(
        &se_proc::NativeStateFiles::open(&f.options.state_directory)?,
        &id,
        &token,
    )?;
    if matches!(case, "expired" | "deadline") {
        std::thread::sleep(Duration::from_millis(3200));
    }
    let before = reader.info()?.head;
    let mut child = command(&image, &f, &root)
        .args(["hook", "claude", "stop"])
        .env("SE_SESSION", id.as_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Keep stdin open to distinguish refusal from later payload validation.
    let input = child.stdin.take().ok_or("hook input pipe absent")?;
    let until = Instant::now()
        + if matches!(case, "prepared" | "active") {
            Duration::from_millis(300)
        } else {
            Duration::from_secs(5)
        };
    let early = loop {
        if child.try_wait()?.is_some() {
            break true;
        }
        if Instant::now() >= until {
            break false;
        }
        std::thread::park_timeout(Duration::from_millis(10));
    };
    drop(input);
    let output = child.wait_with_output()?;
    std::fs::write(f.home.join("hook.stdout"), &output.stdout)?;
    std::fs::write(f.home.join("hook.stderr"), &output.stderr)?;
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "JSON hook refusal became success");
    if matches!(case, "prepared" | "active") {
        assert!(
            !early && text.contains("hook stdin"),
            "{case}: current session failed before native input: {text}"
        );
    } else {
        assert!(
            early && text.contains("hook session") && !text.contains("hook stdin"),
            "{case}: invalid session reached native input: {text}"
        );
    }
    assert!(
        !f.options
            .state_directory
            .join("endpoint.json")
            .try_exists()?,
        "{case}: hook autostarted a host"
    );
    assert_eq!(
        reader.info()?.head,
        before,
        "{case}: read-only prefilter changed durable facts"
    );
    drop(reader);
    println!(
        "PASS hook session {case}: stdin ordering, absent endpoint and unchanged durable head"
    );
    drop(std::mem::ManuallyDrop::into_inner(f));
    Ok(())
}

// The public store owns these seeded facts. A direct client is correctly
// forbidden to publish native process state, even in an isolated fixture.
struct HostAppender {
    owner: SqliteWriter,
    client: SqliteClient,
    runtime: tokio::runtime::Runtime,
}
impl HostAppender {
    fn append(
        &mut self,
        batch: AtomicBatch,
        _lease: &Lease,
    ) -> Result<CommitReceipt, Box<dyn std::error::Error>> {
        Ok(self.runtime.block_on(self.client.submit(batch)?)?)
    }
    fn close(self) -> Check {
        let drained = self
            .runtime
            .block_on(self.owner.drain(Duration::from_secs(5)))?;
        assert_eq!(drained.report.pending_requests, 0);
        assert!(drained.report.indeterminate.is_empty());
        drop(drained.host);
        Ok(())
    }
}

#[test]
fn hook_session_revoked() -> Check {
    check_case("revoked")
}

#[test]
fn hook_session_superseded() -> Check {
    check_case("superseded")
}

#[test]
fn hook_session_stop_unproved() -> Check {
    check_case("stop-unproved")
}

#[test]
fn hook_session_expired() -> Check {
    check_case("expired")
}

#[test]
fn hook_session_deadline() -> Check {
    check_case("deadline")
}

#[test]
fn hook_session_purpose() -> Check {
    check_case("purpose")
}

#[test]
fn hook_session_prepared() -> Check {
    check_case("prepared")
}

#[test]
fn hook_session_active() -> Check {
    check_case("active")
}
