//! Public CLI regression consumers. Typed host-writer setup is not a provider
//! launch or stock-installer witness. Linux supplies the real PTY and procfs pins;
//! Windows console/uninstaller execution belongs to the native Windows kit.
#![cfg(target_os = "linux")]
use se_store::*;
use se_types::{AgentId, LifecycleId, NativePath, SessionId};
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path, time::Duration};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(
    dead_code,
    reason = "Only captured-session event constructors are used."
)]
mod capture;
#[path = "support/custody_cli.rs"]
mod cli;
#[path = "../../se-store/tests/support/wave2_control_fixture.rs"]
#[allow(dead_code, reason = "Only typed process transitions are used.")]
mod control;
#[path = "../../se-store/tests/support/host_fixture.rs"]
#[allow(
    dead_code,
    reason = "Shared real writer helpers serve several consumers."
)]
mod host;
#[path = "support/installation_account.rs"]
mod installation_account;
#[path = "support/custody_child.rs"]
mod native;

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Case {
    // Preserve failed fixture inputs and CLI output; successful cases remove them.
    f: std::mem::ManuallyDrop<Fixture>,
    child: native::Child,
    session: SessionId,
    identity: ProcessIdentityRecord,
    record: se_proc::ProcessRecord,
    writer: Option<SqliteWriter>,
    image: std::path::PathBuf,
    manifest: Vec<u8>,
}
impl Case {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        installation_account::require()?;
        se_proc::initialize_file_creation_owner()?;
        let mut f = std::mem::ManuallyDrop::new(Fixture::new()?);
        se_proc::NativeStateFiles::create(&f.home.join("user-home"))?;
        println!(
            "custody CLI fixture retained on failure: {}",
            f.home.display()
        );
        let repo = f.home.join("repository");
        std::fs::create_dir(&repo)?;
        std::fs::write(repo.join("user-work.txt"), b"retained user work")?;
        let image = f.home.join("installed-se");
        let source = std::env::var_os("SE_PUBLIC_JUDGE_IMAGE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_se").into());
        assert!(source.is_absolute(), "judge image must be absolute");
        std::fs::copy(source, &image)?;
        let initialized = cli::checked(
            &image,
            &f,
            "init",
            &[
                "init",
                "--repo",
                repo.to_str().ok_or("repo encoding")?,
                "--name",
                "Custody review",
                "--agent",
                "Judge",
                "--provider",
                "claude",
            ],
        )?;
        f.owner = initialized["profile"]["human_id"]
            .as_str()
            .ok_or("owner")?
            .parse()?;
        f.project = initialized["profile"]["project"]
            .as_str()
            .ok_or("project")?
            .parse()?;
        f.a = initialized["profile"]["agent_id"]
            .as_str()
            .ok_or("agent")?
            .parse()?;
        f.store = present(SqliteFactory::open_reader(&f.options)?)?.info()?.id;
        let child = native::Child::start()?;
        let session = capture::session()?;
        let (identity, record) = native::identity(&f, &session, &child)?;
        let lease = Lease::acquire(
            &f.options.state_directory,
            LeaseMode::Host,
            Some(f.store.clone()),
        )?;
        let mut store = present(SqliteFactory::open_host(&f.options, &*lease)?)?;
        store.record_runtime_ownership(
            f.batch(
                f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
                Some(fixture::request(&format!(
                    "fixture-wave2_custody_cli_independent-101-{}",
                    serial()
                ))?),
                vec![EventBody::RuntimeOwnerEstablished {
                    epoch: host::epoch()?,
                    generation: se_types::Generation::new(1)?,
                    expected_owner_generation: None,
                    expected: Expected::Absent,
                    witnesses: vec![],
                    recovered: None,
                }],
            )?,
            &*lease,
        )?;
        let writer = store.start_writer(host::options(16)?, lease)?;
        let client = writer.client();
        std::fs::write(f.home.join("transcript.jsonl"), b"ten bytes!")?;
        let pin = se_proc::NativeSourcePin::open(&f.home.join("transcript.jsonl"))?
            .ok_or("source pin")?;
        let source =
            se_core::ops::process_commit::session_credential_id(&session, "capture-source")?;
        let mut source_event = capture::source(source, &session, &pin.identity(), Expected::Absent);
        if let EventBody::CaptureSource { native_ref, .. } = &mut source_event {
            *native_ref = format!("provider-{}", f.a.as_str());
        }
        let receipt = host::wait(client.submit(f.batch(
            f.owner_project(),
            Some(fixture::request(&format!(
                "fixture-wave2_custody_cli_independent-126-{}",
                serial()
            ))?),
            vec![
                capture::prepared(&f, &session, &f.a),
                control::registration(&identity, ProcessState::Running),
                capture::activated(&session)?,
                source_event,
            ],
        )?)?)??;
        assert_eq!(receipt.durability, CommitDurability::Full);
        // Capture uses NORMAL commits; the drain below checkpoints and closes
        // the actual writer before any CLI consumer is invoked.
        host::wait(client.submit(capture::capture(
            &f,
            &session,
            source,
            &pin.identity(),
            0,
            1,
            "public-cli-turn",
        )?)?)??;
        let owner = match se_proc::observe_owner_self(&[])?.owner() {
            se_proc::NativeOwner::Unix {
                real_uid,
                effective_uid,
            } if real_uid == effective_uid => effective_uid.to_string(),
            _ => return Err("same native Unix owner required".into()),
        };
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schema":"stateengine-install/v1", "owner":owner,
            "files":[{"path":image,"sha256":format!("{:x}", Sha256::digest(std::fs::read(&image)?))}],
            "created_directories":[], "path_edits":[],
        }))?;
        let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
        let mut stage = files.create_staging(&f.options.state_directory)?;
        stage.file.write_all(&manifest)?;
        stage.file.sync_all()?;
        drop(stage.file);
        files.publish_no_replace(
            &stage.path,
            &f.options.state_directory.join("standalone-install.json"),
        )?;
        Ok(Self {
            f,
            child,
            session,
            identity,
            record,
            writer: Some(writer),
            image,
            manifest,
        })
    }
    fn write(&self, events: Vec<EventBody<InputText>>) -> Check {
        let writer = self.writer.as_ref().ok_or("writer already drained")?;
        host::wait(writer.client().submit(self.f.batch(
            self.f.owner_project(),
            Some(fixture::request(&format!(
                "fixture-wave2_custody_cli_independent-182-{}",
                serial()
            ))?),
            events,
        )?)?)??;
        Ok(())
    }
    fn transition(&self, rev: u64, from: ProcessState, to: ProcessState) -> Check {
        let observation = control::head(&self.f, self.identity.record.clone())?
            .current
            .header
            .event;
        self.write(vec![control::transition(
            &self.identity,
            rev,
            from,
            to,
            observation,
        )?])
    }
    fn checkpoint(&mut self, kind: se_proc::CheckpointKind) -> Check {
        self.identity.custody.record = se_proc::encode_checkpoint(&se_proc::Checkpoint {
            format_version: 1,
            lifecycle: self.identity.record.clone(),
            principal: se_proc::CheckpointPrincipal::Agent(self.f.a.clone()),
            session: Some(self.session.clone()),
            root_identity: se_proc::RootPublication::Identified,
            checkpoint: kind,
        })?;
        Ok(())
    }
    fn unproved(&mut self) -> Check {
        self.record.state = se_proc::LifecycleState::StopRequested;
        self.checkpoint(se_proc::CheckpointKind::Process(self.record.clone()))?;
        self.transition(1, ProcessState::Running, ProcessState::StopRequested)?;
        self.record.state = se_proc::LifecycleState::StopUnproved;
        self.checkpoint(se_proc::CheckpointKind::Process(self.record.clone()))?;
        self.transition(2, ProcessState::StopRequested, ProcessState::StopUnproved)
    }
    fn recorded_exit(&mut self) -> Check {
        self.checkpoint(native::exit_checkpoint(&self.record))?;
        self.transition(1, ProcessState::Running, ProcessState::Exited)
    }
    fn close_session(&self) -> Check {
        self.write(vec![EventBody::SessionRevoked {
            session: self.session.clone(),
            expected: revision(2)?,
            reason: InputText::Inline("fixture capture and custody cleanup completed".into()),
        }])
    }
    fn drain(&mut self) -> Check {
        let head = self.retained_head()?;
        let drained = host::wait(
            self.writer
                .take()
                .ok_or("writer already drained")?
                .drain(Duration::from_secs(2)),
        )??;
        assert_eq!(drained.report.through, head);
        assert_eq!(drained.report.pending_requests, 0);
        assert!(drained.report.indeterminate.is_empty());
        assert!(!drained.report.maintenance_pending);
        drop(drained);
        Ok(())
    }
    fn retained_head(&self) -> Result<Option<StorePosition>, Box<dyn std::error::Error>> {
        Ok(present(SqliteFactory::open_reader(&self.f.options)?)?
            .info()?
            .head)
    }
    fn verify_retained(&self, head: Option<StorePosition>) -> Check {
        assert_eq!(
            self.retained_head()?,
            head,
            "public consumer changed durable history"
        );
        assert_eq!(
            std::fs::read(self.f.home.join("repository/user-work.txt"))?,
            b"retained user work"
        );
        let record = control::head(&self.f, self.identity.record.clone())?;
        assert_eq!(
            record.current.header.scope,
            Scope::Project(self.f.project.clone())
        );
        Ok(())
    }
    fn done(mut self) -> Check {
        self.child.finish()?;
        // ManuallyDrop is only used to retain failures, and is taken exactly once.
        drop(std::mem::ManuallyDrop::into_inner(self.f));
        Ok(())
    }
}

fn uninstall_refusal(unproved: bool) -> Check {
    let _serial = SERIAL.lock().map_err(|_| "fixture mutex")?;
    let mut c = Case::new()?;
    if unproved {
        c.unproved()?;
    }
    c.drain()?;
    let head = c.retained_head()?;
    let image = std::fs::read(&c.image)?;
    let output = cli::uninstall(&c.image, &c.f)?;
    let printed = cli::printed(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "custody uninstall must refuse: {printed}"
    );
    assert_eq!(cli::json(&output)?["code"], "state-conflict");
    assert!(
        printed.contains("uninstall runtime shutdown")
            && printed.contains("Unresolved owned process or session cleanup"),
        "refusal must name unverified shutdown custody: {printed}"
    );
    assert!(
        printed.contains("Run se down") && printed.contains("then retry se uninstall"),
        "missing cold-runtime reconciliation remedy: {printed}"
    );
    assert_eq!(std::fs::read(&c.image)?, image);
    assert_eq!(
        std::fs::read(c.f.options.state_directory.join("standalone-install.json"))?,
        c.manifest
    );
    assert!(c.child.live()?, "refused uninstall displaced live custody");
    c.verify_retained(head)?;
    c.done()
}
/// Protects: initialized-home uninstall must preserve unresolved cold custody too.
#[test]
fn unmanaged_uninstall_refuses_cold_custody_without_history_change() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "fixture mutex")?;
    let mut c = Case::new()?;
    c.unproved()?;
    c.drain()?;
    std::fs::remove_file(c.f.options.state_directory.join("standalone-install.json"))?;
    let head = c.retained_head()?;
    let image = std::fs::read(&c.image)?;
    let output = cli::uninstall(&c.image, &c.f)?;
    let after = c.retained_head()?;
    println!(
        "unmanaged uninstall exit={:?}, head_before={:?}, head_after={:?}, output={}",
        output.status.code(),
        head,
        after,
        cli::printed(&output)
    );
    assert_eq!(std::fs::read(&c.image)?, image);
    assert!(
        !c.f.options
            .state_directory
            .join("standalone-install.json")
            .try_exists()?
    );
    assert!(c.child.live()?, "refused cleanup displaced live custody");
    c.child.finish()?;
    assert!(!output.status.success(), "unresolved custody must refuse");
    c.verify_retained(head)?;
    c.done()
}

/// Protects: without a live engine to verify shutdown, public uninstall preserves live custody and all installation bytes.
#[test]
fn uninstall_refuses_live_custody_before_removing_files() -> Check {
    uninstall_refusal(false)
}
/// Protects: StopUnproved cannot be mistaken for completed exit or owner release.
#[test]
fn uninstall_refuses_unproved_custody_before_removing_files() -> Check {
    uninstall_refusal(true)
}

fn uninstall_completed(released: bool) -> Check {
    let _serial = SERIAL.lock().map_err(|_| "fixture mutex")?;
    let mut c = Case::new()?;
    if released {
        c.unproved()?;
        c.record.ownership_release = Some(native::release(&c.record)?);
        c.checkpoint(se_proc::CheckpointKind::Process(c.record.clone()))?;
        c.transition(3, ProcessState::StopUnproved, ProcessState::StopUnproved)?;
    } else {
        c.child.finish()?;
        c.recorded_exit()?;
    }
    c.close_session()?;
    c.drain()?;
    let reader = present(SqliteFactory::open_reader(&c.f.options)?)?;
    let inventory = reader.owner_guard(
        &Files(se_proc::NativeStateFiles::open(
            &c.f.options.state_directory,
        )?),
        budget(20, 1_000_000, None)?,
    )?;
    assert!(
        inventory.has_process_records,
        "positive case must retain process history"
    );
    assert!(
        inventory.processes.is_empty(),
        "positive fixture still owns unresolved custody"
    );
    drop(reader);
    let head = c.retained_head()?;
    let output = cli::uninstall(&c.image, &c.f)?;
    assert!(
        output.status.success(),
        "completed custody must allow public uninstall: {}",
        cli::printed(&output)
    );
    assert!(
        !c.image.try_exists()?,
        "successful uninstall kept its owned image"
    );
    assert!(
        !c.f.options
            .state_directory
            .join("standalone-install.json")
            .try_exists()?,
        "successful uninstall kept installation record"
    );
    if released {
        assert!(
            c.child.live()?,
            "explicit release is not permission to kill the relinquished process"
        );
    }
    c.verify_retained(head)?;
    c.done()
}
/// Protects: completed exit history is retained but no longer prevents uninstall.
#[test]
fn uninstall_allows_completed_exit_and_preserves_history() -> Check {
    uninstall_completed(false)
}
/// Protects: explicit owner release retires custody without claiming native exit.
#[test]
fn uninstall_allows_retired_custody_without_killing_released_child() -> Check {
    uninstall_completed(true)
}

fn observation(contradiction: bool) -> Check {
    let _serial = SERIAL.lock().map_err(|_| "fixture mutex")?;
    let mut c = Case::new()?;
    if !contradiction {
        c.child.finish()?;
    }
    // In the contradiction case this is intentionally false durable input,
    // not an exit witness claim: the real exact child remains live below.
    c.recorded_exit()?;
    c.drain()?;
    let head = c.retained_head()?;
    for args in [
        vec!["status"],
        vec!["agent", "list"],
        vec!["agent", "show", c.f.a.as_str()],
    ] {
        let label = args.join("-");
        let output = cli::checked(&c.image, &c.f, &label, &args)?;
        let row = cli::agent_row(&output, c.f.a.as_str())
            .ok_or_else(|| format!("missing exact agent in {label}: {output}"))?;
        assert_eq!(
            row["conversation"]["state"], "saved",
            "must reach verified capture: {row}"
        );
        assert_eq!(
            row["resume"]["ready"], false,
            "unsafe resume in {label}: {row}"
        );
        assert!(
            row["resume"]["command"].is_null() && row["resume"]["argv"].is_null(),
            "not-ready resume published an executable command: {row}"
        );
        if contradiction {
            assert!(
                c.child.live()?,
                "contradiction input must still be the original live child"
            );
            assert_eq!(row["session"]["state"], "unknown");
            assert_eq!(row["session"]["liveness"]["state"], "unreadable");
            assert!(
                row["session"]["liveness"]["reason"]
                    .as_str()
                    .is_some_and(|s| s.contains("despite its recorded exit")),
                "missing exact-live/recorded-exit diagnosis: {row}"
            );
        } else {
            assert_eq!(row["session"]["state"], "stopped");
            assert_eq!(row["session"]["recorded_state"], "activated");
            assert!(
                row["resume"]["reason"]
                    .as_str()
                    .is_some_and(|s| s.contains("cleanup is still pending")),
                "missing cleanup-pending reason: {row}"
            );
        }
    }
    if !contradiction {
        let output = cli::uninstall(&c.image, &c.f)?;
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(cli::json(&output)?["code"], "state-conflict");
        assert!(
            cli::printed(&output).contains("Run se down"),
            "pending exit lost its uninstall diagnosis: {}",
            cli::printed(&output)
        );
        assert!(
            c.image.try_exists()?,
            "unfinished cleanup allowed image removal"
        );
        assert_eq!(
            std::fs::read(c.f.options.state_directory.join("standalone-install.json"))?,
            c.manifest
        );
    }
    c.verify_retained(head)?;
    c.done()
}
/// Protects: status/list/show name an exact live process contradicting recorded exit.
#[test]
fn observation_names_recorded_exit_of_the_exact_live_process() -> Check {
    observation(true)
}
/// Protects: saved transcript alone cannot enable resume before session cleanup.
#[test]
fn observation_disables_resume_until_exit_cleanup_completes() -> Check {
    observation(false)
}

#[path = "../../test-support/executable.rs"]
mod executable;
