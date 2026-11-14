//! Production registry publication: slow durable I/O cannot hold other sessions' map lock.
use super::*;
use crate::test_directory as cleanup_directory;
use se_store::RecordIdentity;
use std::{
    sync::{
        Condvar,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
};

type Check = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Source {
    path: std::path::PathBuf,
    pin: Option<BoundTranscript>,
    _root_owner: cleanup_directory::PrivateDirectory,
}
impl Source {
    fn new() -> std::result::Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("se-registry-{}-{n}", std::process::id()));
        #[cfg(unix)]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(not(unix))]
        let builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&directory)?;
        let root_owner = cleanup_directory::PrivateDirectory::adopt(directory.clone());
        let path = directory.join("source.jsonl");
        std::fs::write(&path, b"source\n")?;
        let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("native source absent")?;
        let binding = crate::TranscriptPin {
            identity: crate::SessionIdentity {
                project: se_types::ProjectId::from_parts(1_700_000_000_000 + n, [1; 10])?,
                agent: se_types::AgentId::from_parts(1_700_000_000_000 + n, [2; 10])?,
                session: SessionId::from_parts(1_700_000_000_000 + n, [3; 10])?,
            },
            conversation: se_types::ProviderSessionId::new(format!("provider-{n}"))?,
            path: se_types::NativePath::from_local(path.clone())?,
            file_identity: se_types::Sha256::from_bytes(pin.identity()),
        };
        Ok(Self {
            path,
            pin: Some(BoundTranscript {
                binding,
                source: se_store::RecordId::from_parts(1_700_000_000_000 + n, [4; 10])?,
                pin,
                queue: Default::default(),
                tools: Default::default(),
            }),
            _root_owner: root_owner,
        })
    }
    fn take(
        &mut self,
    ) -> std::result::Result<BoundTranscript, Box<dyn std::error::Error + Send + Sync>> {
        self.pin
            .take()
            .ok_or_else(|| "source already consumed".into())
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        self.pin.take();
        if let Err(error) = std::fs::remove_file(&self.path) {
            eprintln!(
                "registry fixture cleanup failed at {}: {error}",
                self.path.display()
            );
        }
        if let Some(directory) = self.path.parent()
            && let Err(error) = std::fs::remove_dir(directory)
        {
            eprintln!(
                "registry directory cleanup failed at {}: {error}",
                directory.display()
            );
        }
    }
}

#[test]
fn publishing_distinct_sessions_releases_registry_and_reserves_capacity() -> Check {
    let registry = TranscriptBindings::new(2);
    let (entered, notices) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let mut first = Source::new()?;
    let mut second = Source::new()?;
    let a = first.take()?;
    let a_session = a.binding.identity.session.clone();
    let b = second.take()?;
    let b_session = b.binding.identity.session.clone();
    thread::scope(|scope| -> Check {
        let jobs = [a, b]
            .into_iter()
            .map(|source| {
                let registry = registry.clone();
                let entered = entered.clone();
                let release = release.clone();
                scope.spawn(move || {
                    registry.insert_published(source, |_| {
                        entered.send(()).map_err(|_| busy())?;
                        let (lock, wake) = &*release;
                        let released = lock.lock().map_err(|_| busy())?;
                        let (released, timeout) = wake
                            .wait_timeout_while(
                                released,
                                std::time::Duration::from_secs(5),
                                |value| !*value,
                            )
                            .map_err(|_| busy())?;
                        if timeout.timed_out() && !*released {
                            return Err(busy());
                        }
                        Ok(())
                    })
                })
            })
            .collect::<Vec<_>>();
        // These checks run while BOTH actual publication callbacks are paused.
        // A full/poisoned map must refuse, but an unrelated native publisher
        // may never hold the map while doing filesystem work.
        let result: Check = (|| {
            notices.recv_timeout(std::time::Duration::from_secs(2))?;
            notices.recv_timeout(std::time::Duration::from_secs(2))?;
            let pins = registry
                .pins
                .try_lock()
                .map_err(|_| "durable publication holds the shared registry")?;
            assert_eq!(pins.publishing.len(), 2);
            assert!(pins.active.is_empty());
            drop(pins);
            let mut third = Source::new()?;
            assert!(matches!(
                registry
                    .insert_published(third.take()?, |_| panic!(
                        "capacity must refuse before publication"
                    ))
                    .err()
                    .ok_or("capacity exceeded")?
                    .body
                    .detail(),
                se_types::Detail::StoreBusy(_)
            ));
            let mut duplicate = Source::new()?;
            let mut duplicate = duplicate.take()?;
            duplicate.binding.identity.session = a_session.clone();
            assert!(matches!(
                registry
                    .insert_published(duplicate, |_| panic!(
                        "duplicate must refuse before publication"
                    ))
                    .err()
                    .ok_or("pending session replaced")?
                    .body
                    .detail(),
                se_types::Detail::UsageInvalidValue(_)
            ));
            assert!(
                registry.get(&a_session).is_err(),
                "unpublished source became readable"
            );
            assert!(
                registry
                    .quarantine(Some(a_session.clone()), busy().body)
                    .is_err(),
                "in-flight source was replaced"
            );
            Ok(())
        })();
        {
            let (lock, wake) = &*release;
            *lock.lock().map_err(|_| "release poisoned")? = true;
            wake.notify_all();
        }
        for job in jobs {
            job.join().map_err(|_| "publisher panicked")??;
        }
        result
    })?;
    assert!(registry.get(&a_session).is_ok());
    assert!(registry.get(&b_session).is_ok());
    assert!(registry.registry()?.publishing.is_empty());
    // Drop native pins before fixture paths are removed on Windows.
    drop(registry);
    Ok(())
}

#[test]
fn publication_failure_returns_capacity_preserves_quarantine_and_permits_exact_source_retry()
-> Check {
    let registry = TranscriptBindings::new(1);
    let mut first = Source::new()?;
    let source = first.take()?;
    let session = source.binding.identity.session.clone();
    registry.quarantine(Some(session.clone()), busy().body)?;
    let failed = registry.insert_published(source, |_| {
        Err(se_core::scope::unreadable("publisher", "permission denied"))
    });
    assert!(matches!(
        failed
            .err()
            .ok_or("failed publication accepted")?
            .body
            .detail(),
        se_types::Detail::SourceUnreadable(_)
    ));
    {
        let pins = registry.registry()?;
        assert!(pins.active.is_empty());
        assert!(pins.publishing.is_empty());
        assert!(pins.failed.contains_key(&session));
    }
    let mut replacement = Source::new()?;
    let mut source = replacement.take()?;
    source.binding.identity.session = session.clone();
    registry.insert_published(source, |_| Ok(()))?;
    assert!(registry.get(&session).is_ok());
    assert!(registry.registry()?.failed.is_empty());
    drop(registry);
    Ok(())
}

#[test]
fn failed_new_publication_does_not_consume_another_sessions_slot() -> Check {
    let registry = TranscriptBindings::new(1);
    let mut failed = Source::new()?;
    assert!(
        registry
            .insert_published(failed.take()?, |_| Err(busy()))
            .is_err()
    );
    let mut next = Source::new()?;
    let source = next.take()?;
    let session = source.binding.identity.session.clone();
    registry.insert_published(source, |_| Ok(()))?;
    assert!(registry.get(&session).is_ok());
    drop(registry);
    Ok(())
}
