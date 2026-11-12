//! Protects the portable verifier-to-coordinator handoff. These typed facts are
//! adapter fixtures, not evidence of HTTP/sec1 possession or an activated C3.
#![cfg(feature = "runtime")]
use se_host::client::{ClientOptions, lease::Deadline};
use se_host::{PreparedRequestProofs, VerifiedPreparedRequest};
use se_store::{RecordId, RecordIdentity};
use se_types::SessionId;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
    task::Poll,
    time::Duration,
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn session(n: u8) -> Check<SessionId> {
    Ok(SessionId::from_parts(1_700_000_000_000, [n; 10])?)
}
fn request(n: u8) -> Check<RecordId> {
    Ok(RecordId::from_parts(1_700_000_000_000, [n; 10])?)
}
fn deadline() -> Check<Deadline> {
    Ok(Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout: Duration::from_millis(80),
        cancelled: Arc::new(AtomicBool::new(false)),
    })?)
}
fn observed(
    session: &SessionId,
    purpose: &'static str,
    hash: u8,
    generation: u64,
    id: u8,
) -> Check<VerifiedPreparedRequest> {
    Ok(VerifiedPreparedRequest {
        session: session.clone(),
        purpose,
        secret_sha256: [hash; 32],
        generation,
        request: request(id)?,
    })
}
async fn once<F: Future + ?Sized>(mut f: Pin<&mut F>) -> Option<F::Output> {
    std::future::poll_fn(|cx| {
        Poll::Ready(match f.as_mut().poll(cx) {
            Poll::Pending => None,
            Poll::Ready(v) => Some(v),
        })
    })
    .await
}
/// Protects: one purpose never completes the barrier; cancelled waiters retain
/// no authority, and replay cannot replace either first admitted request ID.
#[test]
fn verifier_handoff_waits_for_both_exact_first_requests_and_survives_waiter_drop() -> Check {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let proofs = PreparedRequestProofs::new(2);
        let a = session(1)?;
        proofs.register(a.clone(), 7, [11; 32], [22; 32])?;
        let original_deadline = deadline()?;
        let mut waiting = Box::pin(proofs.wait(&a, &original_deadline));
        assert!(
            once(waiting.as_mut()).await.is_none(),
            "empty verifier barrier completed"
        );
        proofs.observe_verified(observed(&a, "http", 22, 7, 31)?)?;
        assert!(
            once(waiting.as_mut()).await.is_none(),
            "one purpose completed the first-use barrier"
        );
        drop(waiting);
        let clone = proofs.clone();
        clone.observe_verified(observed(&a, "http", 22, 7, 99)?)?;
        clone.observe_verified(observed(&a, "session", 11, 7, 32)?)?;
        clone.observe_verified(observed(&a, "session", 11, 7, 98)?)?;
        let actual = proofs.wait(&a, &original_deadline).await?;
        assert_eq!(
            actual.http_request,
            request(31)?,
            "replay replaced the first HTTP request"
        );
        assert_eq!(
            actual.session_request,
            request(32)?,
            "replay replaced the first session request"
        );
        Ok(())
    })
}
/// Protects: stale adapter facts cannot satisfy another retained launch, and a
/// missing second witness ends at the original deadline with a named refusal.
#[test]
fn verifier_handoff_rejects_adapter_drift_without_completing_or_crossing_sessions() -> Check {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let proofs = PreparedRequestProofs::new(2);
        let a = session(1)?;
        let b = session(2)?;
        proofs.register(a.clone(), 7, [11; 32], [22; 32])?;
        proofs.register(b.clone(), 8, [44; 32], [55; 32])?;
        for stale in [
            observed(&a, "session", 11, 6, 1)?,
            observed(&a, "session", 22, 7, 2)?,
            observed(&a, "http", 11, 7, 3)?,
            observed(&b, "session", 11, 8, 4)?,
            observed(&session(3)?, "http", 22, 7, 5)?,
        ] {
            assert!(
                proofs.observe_verified(stale).is_err(),
                "stale adapter binding was accepted"
            );
        }
        proofs.observe_verified(observed(&b, "http", 55, 8, 41)?)?;
        proofs.observe_verified(observed(&b, "session", 44, 8, 42)?)?;
        let ready = proofs.wait(&b, &deadline()?).await?;
        assert_eq!(ready.http_request, request(41)?);
        proofs.observe_verified(observed(&a, "session", 11, 7, 43)?)?;
        let error = proofs
            .wait(&a, &deadline()?)
            .await
            .err()
            .ok_or("missing HTTP witness activated readiness")?;
        assert!(
            error
                .to_string()
                .contains("actual first-use request witnesses did not arrive"),
            "missing witness refusal lost its reason: {error}"
        );
        Ok(())
    })
}
/// Protects: retained readiness is bounded, duplicate registration preserves
/// its facts, removal frees only that slot, and late facts cannot resurrect it.
#[test]
fn verifier_handoff_bounds_retained_slots_and_fences_removed_launches() -> Check {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let proofs = PreparedRequestProofs::new(1);
        let a = session(1)?;
        let b = session(2)?;
        proofs.register(a.clone(), 7, [11; 32], [22; 32])?;
        proofs.observe_verified(observed(&a, "session", 11, 7, 61)?)?;
        assert!(proofs.register(a.clone(), 9, [77; 32], [88; 32]).is_err());
        assert!(
            proofs.register(b.clone(), 8, [44; 32], [55; 32]).is_err(),
            "retained verifier bound was exceeded"
        );
        proofs.observe_verified(observed(&a, "http", 22, 7, 62)?)?;
        assert_eq!(
            proofs.wait(&a, &deadline()?).await?.session_request,
            request(61)?,
            "duplicate registration replaced retained facts"
        );
        proofs.remove(&a)?;
        assert!(
            proofs.wait(&a, &deadline()?).await.is_err(),
            "removed launch retained readiness"
        );
        assert!(
            proofs
                .observe_verified(observed(&a, "session", 11, 7, 63)?)
                .is_err(),
            "late request resurrected removed launch"
        );
        proofs.register(b.clone(), 8, [44; 32], [55; 32])?;
        assert!(
            proofs.wait(&b, &deadline()?).await.is_err(),
            "reused capacity inherited another session's proof"
        );
        proofs.remove(&b)?;
        Ok(())
    })
}

/// Protects: ready facts cannot evade an expired/cancelled original bound, and
/// retiring a pending launch wakes its existing waiter without a second fact.
#[test]
fn verifier_handoff_obeys_original_bounds_and_wakes_a_retired_waiter() -> Check {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let proofs = PreparedRequestProofs::new(2);
        let a = session(1)?;
        let b = session(2)?;
        proofs.register(a.clone(), 7, [11; 32], [22; 32])?;
        proofs.register(b.clone(), 8, [44; 32], [55; 32])?;
        let bound = deadline()?;
        let mut pending = Box::pin(proofs.wait(&a, &bound));
        assert!(once(pending.as_mut()).await.is_none());
        proofs.remove(&a)?;
        assert!(
            matches!(once(pending.as_mut()).await, Some(Err(_))),
            "retired launch did not wake its existing waiter"
        );
        drop(pending);
        proofs.observe_verified(observed(&b, "session", 44, 8, 71)?)?;
        proofs.observe_verified(observed(&b, "http", 55, 8, 72)?)?;
        let cancelled = Deadline::from_options(&ClientOptions {
            expected_generation: None,
            timeout: Duration::from_secs(1),
            cancelled: Arc::new(AtomicBool::new(false)),
        })?;
        cancelled
            .native_bound()
            .cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        assert!(
            proofs.wait(&b, &cancelled).await.is_err(),
            "ready facts bypassed original cancellation"
        );
        let expired = Deadline::from_options(&ClientOptions {
            expected_generation: None,
            timeout: Duration::from_millis(1),
            cancelled: Arc::new(AtomicBool::new(false)),
        })?;
        tokio::time::sleep(Duration::from_millis(3)).await;
        assert!(
            proofs.wait(&b, &expired).await.is_err(),
            "ready facts bypassed original deadline"
        );
        let ready = proofs.wait(&b, &deadline()?).await?;
        assert_eq!(ready.session_request, request(71)?);
        assert_eq!(ready.http_request, request(72)?);
        Ok(())
    })
}

/// Protects: a delayed old waiter stays retired even if capacity is immediately
/// reused for another issuance with the same session ID, before it runs again.
#[test]
fn verifier_handoff_pending_wait_cannot_cross_a_replaced_slot_incarnation() -> Check {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        for next_generation in [2, 3] {
            let proofs = PreparedRequestProofs::new(1);
            let a = session(1)?;
            proofs.register(a.clone(), 2, [11; 32], [22; 32])?;
            let original = deadline()?;
            let mut stale = Box::pin(proofs.wait(&a, &original));
            assert!(once(stale.as_mut()).await.is_none());
            proofs.remove(&a)?;
            proofs.register(a.clone(), next_generation, [11; 32], [22; 32])?;
            proofs.observe_verified(observed(&a, "session", 11, next_generation, 81)?)?;
            proofs.observe_verified(observed(&a, "http", 22, next_generation, 82)?)?;
            let retired = once(stale.as_mut())
                .await
                .is_some_and(|value| value.is_err());
            drop(stale);
            let replacement = proofs.wait(&a, &deadline()?).await?;
            assert_eq!(replacement.session_request, request(81)?);
            assert_eq!(replacement.http_request, request(82)?);
            assert!(
                retired,
                "retired waiter consumed replacement C1 issuance at generation {next_generation}"
            );
        }
        Ok(())
    })
}
