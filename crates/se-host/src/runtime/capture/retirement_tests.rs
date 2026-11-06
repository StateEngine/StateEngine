//! Real host capture bindings, protected metadata, native locks and original clocks.
use super::*;
use crate::client::ClientOptions;
use crate::runtime::test_support as support;
use crate::*;
use se_store::*;
use se_types::{NativePath, ProviderSessionId, Sha256};
use std::{
    future::Future,
    sync::atomic::AtomicBool,
    task::Poll,
    time::{Duration, Instant},
};
use support::{session, *};

fn deadline(timeout: Duration, cancelled: Arc<AtomicBool>) -> se_types::Result<Deadline> {
    Deadline::from_options(&ClientOptions {
        timeout,
        cancelled,
        expected_generation: None,
    })
}

/// Protects: sibling retirement waiting cannot renew an expired/cancelled request or delete its recovery metadata; a subsequent exact retry succeeds.
#[test]
fn queued_retirement_preserves_original_expiry_and_cancellation() -> Check {
    scenario("deadline")?;
    scenario("cancelled")
}

/// Protects: serialization never turns a real external directory lock into successful retirement, and the original recovery file survives a failed attempt.
#[test]
fn genuine_native_custody_failure_retains_metadata_and_allows_repair() -> Check {
    scenario("native-lock")
}

/// Protects: retirement still verifies the original project/agent/session in the protected file rather than deleting drifted metadata.
#[test]
fn changed_metadata_identity_is_refused_without_deleting_the_file() -> Check {
    scenario("identity")
}

fn scenario(case: &str) -> Check {
    let f = std::mem::ManuallyDrop::new(Fixture::new()?);
    seed(&f)?;
    let mut sources = Vec::new();
    let (mut direct, lease) = direct(&f)?;
    for agent in [&f.a, &f.b] {
        let id = session::session()?;
        let conversation = ProviderSessionId::new(format!("provider-{}", agent.as_str()))?;
        let path = f.home.join(format!("{id}.jsonl"));
        std::fs::write(&path, b"")?;
        let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("native source absent")?;
        let source = session::record()?;
        direct.append(
            f.batch(
                f.owner_project(),
                Some(fixture::request(id.as_str())?),
                vec![
                    session::prepared(&f, &id, agent),
                    session::activated(&id)?,
                    session::source(source, &id, &pin.identity(), Expected::Absent),
                ],
            )?,
            &*lease,
        )?;
        sources.push((
            TranscriptPin {
                identity: SessionIdentity {
                    project: f.project.clone(),
                    agent: agent.clone(),
                    session: id,
                },
                conversation,
                path: NativePath::from_local(path)?,
                file_identity: Sha256::from_bytes(pin.identity()),
            },
            source,
            pin,
        ));
    }
    direct.close()?;
    drop(lease);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host = HostedRuntime::prepare(
            initialize_host_process()?,
            start(&f)?,
            rt.handle().clone(),
            &bound()?,
        )
        .await?;
        let capture = host.capture_handle();
        let identities = sources
            .iter()
            .map(|(p, _, _)| p.identity.clone())
            .collect::<Vec<_>>();
        for (binding, source, pin) in sources {
            capture.bind(binding, source, pin, &bound()?).await?;
        }
        let path = |i: usize| {
            f.options
                .state_directory
                .join("transcripts")
                .join(format!("{}.json", identities[i].session))
        };
        let before = [std::fs::read(path(0))?, std::fs::read(path(1))?];
        let result: Check = async {
            match case {
                "deadline" | "cancelled" => {
                    // Occupy the real host's native-work admission. Poll the
                    // first retirement through its actual queue point before
                    // starting the sibling, without replacing I/O or its clock.
                    let pool = host.blocking_pool().foreground_admission();
                    let held = pool
                        .clone()
                        .acquire_many_owned(u32::try_from(pool.available_permits())?)
                        .await?;
                    let first_bound = bound()?;
                    let mut first =
                        std::pin::pin!(capture.retire(identities[0].clone(), true, &first_bound));
                    let pending = std::future::poll_fn(|cx| {
                        Poll::Ready(first.as_mut().poll(cx).is_pending())
                    })
                    .await;
                    assert!(
                        pending,
                        "native admission did not hold the first retirement"
                    );
                    let cancelled = Arc::new(AtomicBool::new(false));
                    let second_bound = deadline(Duration::from_millis(150), cancelled.clone())?;
                    let mut second =
                        std::pin::pin!(capture.retire(identities[1].clone(), true, &second_bound));
                    let pending = std::future::poll_fn(|cx| {
                        Poll::Ready(second.as_mut().poll(cx).is_pending())
                    })
                    .await;
                    assert!(pending, "sibling did not queue behind held native work");
                    if case == "cancelled" {
                        cancelled.store(true, std::sync::atomic::Ordering::Release);
                    }
                    let now = Instant::now();
                    let error = second
                        .await
                        .err()
                        .ok_or("queued retirement ignored its original bound")?;
                    assert!(
                        now.elapsed() < Duration::from_secs(2),
                        "retirement renewed its admission clock"
                    );
                    assert_eq!(
                        error.code(),
                        if case == "cancelled" {
                            se_types::Code::Cancelled
                        } else {
                            se_types::Code::DeadlineExceeded
                        }
                    );
                    assert_eq!(
                        std::fs::read(path(1))?,
                        before[1],
                        "unadmitted retirement removed recovery metadata"
                    );
                    drop(held);
                    first.await?;
                    assert!(!path(0).try_exists()?);
                    capture
                        .retire(identities[1].clone(), true, &bound()?)
                        .await?;
                }
                "native-lock" => {
                    let directory =
                        std::fs::File::open(path(0).parent().ok_or("metadata directory")?)?;
                    directory.try_lock()?;
                    let error = capture
                        .retire(identities[0].clone(), true, &bound()?)
                        .await
                        .err()
                        .ok_or("external native custody collision became successful retirement")?;
                    assert_ne!(
                        error.code(),
                        se_types::Code::DeadlineExceeded,
                        "external lock was treated as sibling queue waiting"
                    );
                    assert_eq!(std::fs::read(path(0))?, before[0]);
                    drop(directory);
                    capture
                        .retire(identities[0].clone(), true, &bound()?)
                        .await?;
                    capture
                        .retire(identities[1].clone(), true, &bound()?)
                        .await?;
                }
                "identity" => {
                    let mut drift: serde_json::Value = serde_json::from_slice(&before[0])?;
                    drift["agent"] = serde_json::to_value(&identities[1].agent)?;
                    let bytes = serde_json::to_vec(&drift)?;
                    std::fs::write(path(0), &bytes)?;
                    assert!(
                        capture
                            .retire(identities[0].clone(), true, &bound()?)
                            .await
                            .is_err()
                    );
                    assert_eq!(std::fs::read(path(0))?, bytes);
                    std::fs::write(path(0), &before[0])?;
                    capture
                        .retire(identities[0].clone(), true, &bound()?)
                        .await?;
                    capture
                        .retire(identities[1].clone(), true, &bound()?)
                        .await?;
                }
                _ => return Err("unknown retirement control".into()),
            }
            assert!(!path(0).try_exists()? && !path(1).try_exists()?);
            Ok(())
        }
        .await;
        // No provider or listener is launched by this host-level fixture.
        // Close its real writer and lease even when the assertion is returned.
        drop(capture);
        let drained = host.drain_storage(&bound()?).await?;
        assert!(
            drained.writer_joined && drained.pending.is_empty(),
            "fixture writer did not drain"
        );
        drop(host);
        drop(Lease::acquire(
            &f.options.state_directory,
            LeaseMode::Host,
            Some(f.store.clone()),
        )?);
        result
    })?;
    drop(std::mem::ManuallyDrop::into_inner(f));
    Ok(())
}
