//! Author regression tests through the real canonical writer and native file port.
use crate::*;
#[path = "../tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../tests/support/host_fixture.rs"]
#[allow(
    dead_code,
    reason = "These regressions reuse the native epoch helper only."
)]
mod native;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Cursor,
    path::Path,
    sync::{Arc, Mutex},
};

struct StagingFiles {
    native: se_proc::NativeStateFiles,
    created: Mutex<Option<fs::Metadata>>,
}
fn file_error(e: se_proc::StateFileError) -> Box<StoreError> {
    crate::error::fail(StoreErrorCode::Unreadable, e.to_string())
}
impl StateFiles for StagingFiles {
    fn prepare_directory(&self, path: &Path) -> StoreResult<()> {
        self.native.prepare_directory(path).map_err(file_error)
    }
    fn retire_empty_staging(&self, staged: ProtectedStaging) -> StoreResult<std::fs::File> {
        self.native
            .retire_empty_staging(se_proc::ProtectedStateStaging {
                path: staged.path,
                file: staged.file,
            })
            .map_err(file_error)
    }
    fn create_staging(&self, path: &Path) -> StoreResult<ProtectedStaging> {
        let staged = self.native.create_staging(path).map_err(file_error)?;
        *self
            .created
            .lock()
            .map_err(|_| crate::error::invalid("metadata lock"))? = Some(
            staged
                .file
                .metadata()
                .map_err(|e| crate::error::invalid(e.to_string()))?,
        );
        Ok(ProtectedStaging {
            path: staged.path,
            file: staged.file,
        })
    }
    fn readback(&self, path: &Path) -> StoreResult<se_types::Read<fs::File>> {
        Ok(match self.native.readback(path).map_err(file_error)? {
            Some(value) => se_types::Read::Present { value },
            None => se_types::Read::Absent {
                checked: "native file absent".into(),
            },
        })
    }
    fn publish_no_replace(&self, from: &Path, to: &Path) -> StoreResult<()> {
        self.native.publish_no_replace(from, to).map_err(file_error)
    }
    fn remove_owned(&self, path: &Path, digest: [u8; 32]) -> StoreResult<()> {
        let owned = se_proc::OwnedFile::open(path)
            .map_err(file_error)?
            .ok_or_else(|| crate::error::invalid("staging file absent before retirement"))?;
        owned.remove(digest).map_err(file_error)?;
        assert!(self.native.readback(path).map_err(file_error)?.is_none());
        Ok(())
    }
}
struct StagingLease {
    held: Arc<Lease>,
    files: StagingFiles,
}
impl StagingLease {
    fn new(f: &Fixture, held: Arc<Lease>) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            held,
            files: StagingFiles {
                native: se_proc::NativeStateFiles::open(&f.options.state_directory)?,
                created: Mutex::new(None),
            },
        })
    }
}
impl RuntimeLease for StagingLease {
    fn identity(&self) -> StoreResult<LeaseIdentity> {
        self.held.identity()
    }
    fn files(&self) -> &dyn StateFiles {
        &self.files
    }
}

#[test]
fn caller_key_replays_original_receipt_after_a_later_head() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let first = store.append(
        f.working("original", Expected::Absent, "retry-key")?,
        &*lease,
    )?;
    store.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.b.clone()),
            message()?,
            "later unrelated fact",
            "later-key",
        )?,
        &*lease,
    )?;
    let head = store.info()?.head;
    // Fresh output IDs and a now-stale expected revision cannot replace the original receipt.
    let replay = store.append(
        f.working("original", Expected::Absent, "retry-key")?,
        &*lease,
    );
    assert!(
        replay.is_ok(),
        "key replay reapplied stale preconditions: {:?}",
        replay.as_ref().err()
    );
    let retry = replay?;
    assert_eq!(retry.state, CommitState::Replayed);
    assert_eq!(retry.primary_event, first.primary_event);
    assert_eq!(retry.events, first.events);
    assert_eq!(retry.writer, first.writer);
    assert_eq!(retry.durability, first.durability);
    assert_eq!(store.info()?.head, head);
    store.close()?;
    Ok(())
}

#[test]
fn reused_key_refuses_changed_intent_without_a_write() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let first = store.append(
        f.working("original", Expected::Absent, "retry-key")?,
        &*lease,
    )?;
    let head = store.info()?.head;
    let mut changed = f.working("different payload", revision(1)?, "retry-key")?;
    changed
        .request
        .as_mut()
        .ok_or("request missing")?
        .intent
        .sha256 = Sha256::digest(b"different payload").into();
    let result = store.append(changed, &*lease);
    assert!(result.is_err(), "a reused key accepted a different intent");
    let error = result.err().ok_or("changed intent accepted")?;
    assert_eq!(error.code, StoreErrorCode::IdempotencyKeyReused);
    assert!(
        matches!(error.detail, StoreDetail::Request { original_event: Some(id), .. } if id == first.primary_event)
    );
    assert_eq!(store.info()?.head, head);
    store.close()?;
    Ok(())
}

fn cold_host(f: &Fixture) -> Result<(SqliteHost, Arc<Lease>), Box<dyn std::error::Error>> {
    let (direct, lease) = f.direct()?;
    direct.close()?;
    drop(lease);
    let lease = Lease::acquire(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(f.store.clone()),
    )?;
    Ok((
        present(SqliteFactory::open_host(&f.options, &*lease)?)?,
        lease,
    ))
}
fn binding(
    f: &Fixture,
    id: &se_types::SessionId,
    bad: bool,
) -> Result<FirstBinding, Box<dyn std::error::Error>> {
    Ok(FirstBinding {
        owner: f.batch(
            f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
            Some(request("cold-owner")?),
            vec![EventBody::RuntimeOwnerEstablished {
                epoch: native::epoch()?,
                generation: se_types::Generation::new(1)?,
                expected_owner_generation: None,
                expected: Expected::Absent,
                witnesses: vec![],
                recovered: None,
            }],
        )?,
        session: f.batch(
            f.owner_project(),
            Some(request("cold-session")?),
            vec![
                EventBody::SessionPrepared {
                    session: id.clone(),
                    agent: f.a.clone(),
                    provider: Provider::Claude,
                    surface: Some(SessionSurface::SeCode),
                    native_ref: "unit-native-session".into(),
                    consent: Consent::Capture,
                    generation: 1,
                    expected: Expected::Absent,
                },
                EventBody::SessionActivated {
                    session: id.clone(),
                    expected: revision(if bad { 99 } else { 1 })?,
                    incumbent: None,
                    process: None,
                    containment: ContainmentFact::NotLaunched,
                    witnesses: vec![],
                },
            ],
        )?,
    })
}
fn session() -> Result<se_types::SessionId, Box<dyn std::error::Error>> {
    Ok(se_types::SessionId::from_parts(
        1_700_000_000_000 + serial(),
        [81; 10],
    )?)
}

#[test]
fn first_binding_failure_rolls_back_both_operations() -> Check {
    let f = Fixture::new()?;
    let (mut host, lease) = cold_host(&f)?;
    let id = session()?;
    let head = host.info()?.head;
    let result = host.record_first_binding(binding(&f, &id, true)?, &*lease);
    assert!(
        result.is_err(),
        "invalid activation committed a first binding"
    );
    assert_eq!(
        result.err().ok_or("activation accepted")?.code,
        StoreErrorCode::RevisionConflict
    );
    assert!(
        matches!(host.runtime_owner()?, se_types::Read::Absent { .. }),
        "owner survived failed pair"
    );
    let mut read = host.snapshot(f.scoped(Visibility::Owner))?;
    assert!(matches!(read.session(id)?, se_types::Read::Absent { .. }));
    read.close()?;
    assert_eq!(host.info()?.head, head);
    Ok(())
}

#[test]
fn first_binding_replays_the_original_full_pair() -> Check {
    let f = Fixture::new()?;
    let (mut host, lease) = cold_host(&f)?;
    let id = session()?;
    let first = host.record_first_binding(binding(&f, &id, false)?, &*lease)?;
    let head = host.info()?.head;
    let result = host.record_first_binding(binding(&f, &id, true)?, &*lease);
    assert!(
        result.is_ok(),
        "first binding retry reapplied stale preconditions: {:?}",
        result.as_ref().err()
    );
    let replay = result?;
    for (old, retry) in [
        (&first.owner, &replay.owner),
        (&first.session, &replay.session),
    ] {
        assert_eq!(old.durability, CommitDurability::Full);
        assert_eq!(retry.durability, old.durability);
        assert_eq!(retry.state, CommitState::Replayed);
        assert_eq!(retry.primary_event, old.primary_event);
        assert_eq!(retry.events, old.events);
        assert_eq!(retry.writer, old.writer);
    }
    assert_eq!(first.owner.events.len(), 1);
    assert_eq!(first.session.events.len(), 2);
    assert_eq!(host.info()?.head, head);
    Ok(())
}

#[test]
fn first_binding_refuses_a_retained_half_pair() -> Check {
    let f = Fixture::new()?;
    let (mut host, lease) = cold_host(&f)?;
    let id = session()?;
    host.record_runtime_ownership(binding(&f, &id, false)?.owner, &*lease)?;
    let head = host.info()?.head;
    let result = host.record_first_binding(binding(&f, &id, false)?, &*lease);
    assert!(result.is_err(), "a retained half pair was completed");
    assert_eq!(
        result.err().ok_or("half pair accepted")?.code,
        StoreErrorCode::ProjectionInconsistent
    );
    assert_eq!(host.info()?.head, head);
    Ok(())
}

#[test]
fn keyless_non_natural_write_is_refused() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let head = store.info()?.head;
    let mut batch = f.working("must not persist", Expected::Absent, "unused")?;
    batch.request = None;
    let result = store.append(batch, &*lease);
    assert!(result.is_err(), "keyless non-natural write was accepted");
    assert_eq!(
        result.err().ok_or("keyless accepted")?.code,
        StoreErrorCode::EventInvalid
    );
    assert_eq!(store.info()?.head, head);
    store.close()?;
    Ok(())
}

#[test]
fn staging_refuses_oversize_without_a_named_residue() -> Check {
    let f = Fixture::new()?;
    let (store, lease) = f.direct()?;
    let lease = StagingLease::new(&f, lease)?;
    let mut source = Cursor::new(b"too large");
    let cap = store.stage_text(&mut source, 1024 * 1024 + 1, &lease);
    assert!(cap.is_err(), "stage accepted a cap over 1 MiB");
    assert_eq!(
        cap.err().ok_or("cap accepted")?.code,
        StoreErrorCode::BodyTooLarge
    );
    assert_eq!(source.position(), 0);
    let result = store.stage_text(&mut source, 3, &lease);
    assert!(
        result.is_err(),
        "stage accepted bytes beyond the caller's maximum"
    );
    assert_eq!(
        result.err().ok_or("oversize accepted")?.code,
        StoreErrorCode::BodyTooLarge
    );
    assert_eq!(
        fs::read_dir(f.options.state_directory.join("staging"))?.count(),
        0
    );
    store.close()?;
    Ok(())
}

#[test]
fn staged_work_mail_keeps_its_body_and_recipient_wake() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let lease = StagingLease::new(&f, lease)?;
    let body = "lossless work body 🦀";
    let staged = store.stage_text(&mut Cursor::new(body.as_bytes()), 128, &lease)?;
    let batch = f.batch(
        f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
        Some(request("staged-work")?),
        vec![EventBody::WorkMessageSent {
            quiet: false,
            message: message()?,
            work: se_types::WorkAddressing {
                action: se_types::WorkAction::Finding,
                addressees: vec![f.b.clone()],
            },
            kind: "finding".into(),
            body: InputText::Staged(staged),
            refs: vec![],
            reply_to: None,
        }],
    )?;
    let result = store.append(batch, &lease);
    assert!(
        result.is_ok(),
        "staged work mail was not materialized: {:?}",
        result.as_ref().err()
    );
    let receipt = result?;
    assert_eq!(receipt.wakes.len(), 1, "work addressee lost its wake");
    assert_eq!(receipt.wakes[0].principal, Actor::Agent(f.b.clone()));
    let mut read = store.snapshot(f.scoped(Visibility::Owner))?;
    let saved = present(read.event(receipt.primary_event)?)?;
    assert!(
        matches!(saved.body, EventBody::WorkMessageSent { body: StoredText::Present(ref text), .. } if text == body)
    );
    read.close()?;
    store.close()?;
    Ok(())
}

#[test]
fn rejected_staged_payload_drops_its_native_handle() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let lease = StagingLease::new(&f, lease)?;
    let staged = store.stage_text(&mut Cursor::new(b"private staged body"), 64, &lease)?;
    let mut batch = f.working("unused", Expected::Absent, "unused")?;
    if let EventBody::WorkingStateSet { text, .. } = &mut batch.events[0].body {
        *text = InputText::Staged(staged);
    }
    batch.request = None;
    let result = store.append(batch, &lease);
    assert!(result.is_err(), "expected a rejected staged batch");
    assert_eq!(
        result.err().ok_or("staged batch accepted")?.code,
        StoreErrorCode::EventInvalid
    );
    assert_eq!(
        fs::read_dir(f.options.state_directory.join("staging"))?.count(),
        0
    );
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let created = lease.files.created.lock().map_err(|_| "metadata lock")?;
        let created = created.as_ref().ok_or("no native staging file observed")?;
        for entry in fs::read_dir("/proc/self/fd")? {
            let metadata = match fs::metadata(entry?.path()) {
                Ok(metadata) => metadata,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            assert!(
                metadata.dev() != created.dev() || metadata.ino() != created.ino(),
                "rejected batch retained its anonymous native staging handle"
            );
        }
    }
    store.close()?;
    Ok(())
}
