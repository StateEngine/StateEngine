//! Public portable proof handoff only; no authentication or native effects.
#![cfg(feature = "runtime")]
use se_host::{
    PreparedRequestProofs, VerifiedPreparedRequest,
    client::{ClientOptions, lease::Deadline},
};
use se_store::{RecordId, RecordIdentity};
use se_types::SessionId;
use std::{
    future::{Future, poll_fn},
    sync::{Arc, atomic::AtomicBool},
    task::Poll,
    time::Duration,
};
type Check = Result<(), Box<dyn std::error::Error>>;
fn session(n: u8) -> Result<SessionId, Box<dyn std::error::Error>> {
    Ok(SessionId::from_parts(
        1_700_000_000_000 + u64::from(n),
        [n; 10],
    )?)
}
fn id(n: u8) -> Result<RecordId, Box<dyn std::error::Error>> {
    Ok(RecordId::from_parts(
        1_700_000_000_000 + u64::from(n),
        [n; 10],
    )?)
}
fn deadline(ms: u64) -> Result<Deadline, Box<dyn std::error::Error>> {
    Ok(Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout: Duration::from_millis(ms),
        cancelled: Arc::new(AtomicBool::new(false)),
    })?)
}
fn observed(
    s: &SessionId,
    purpose: &'static str,
    hash: u8,
    generation: u64,
    request: u8,
) -> Result<VerifiedPreparedRequest, Box<dyn std::error::Error>> {
    Ok(VerifiedPreparedRequest {
        session: s.clone(),
        purpose,
        secret_sha256: [hash; 32],
        generation,
        request: id(request)?,
    })
}
fn runtime() -> Result<tokio::runtime::Runtime, std::io::Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
#[test]
fn exact_bindings_preserve_first_requests_and_capacity() -> Check {
    runtime()?.block_on(async {
        let p = PreparedRequestProofs::new(1);
        let s = session(1)?;
        p.register(s.clone(), 2, [1; 32], [2; 32])?;
        assert!(p.register(s.clone(), 2, [1; 32], [2; 32]).is_err());
        assert!(p.register(session(2)?, 2, [1; 32], [2; 32]).is_err());
        for bad in [
            observed(&s, "wrong", 1, 2, 3)?,
            observed(&s, "http", 1, 2, 3)?,
            observed(&s, "session", 1, 1, 3)?,
            observed(&session(2)?, "session", 1, 2, 3)?,
        ] {
            assert!(p.observe_verified(bad).is_err());
        }
        p.observe_verified(observed(&s, "session", 1, 2, 3)?)?;
        p.observe_verified(observed(&s, "session", 1, 2, 4)?)?;
        let d = deadline(1000)?;
        let mut waiting = Box::pin(p.wait(&s, &d));
        assert!(poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx).is_pending())).await);
        p.observe_verified(observed(&s, "http", 2, 2, 5)?)?;
        let result = waiting.await?;
        assert_eq!(result.session_request, id(3)?);
        assert_eq!(result.http_request, id(5)?);
        p.remove(&s)?;
        p.register(session(2)?, 2, [1; 32], [2; 32])?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}
#[test]
fn retired_waiter_is_woken_and_expired_deadline_stays_expired() -> Check {
    runtime()?.block_on(async {
        let p = PreparedRequestProofs::new(1);
        let s = session(1)?;
        p.register(s.clone(), 2, [1; 32], [2; 32])?;
        let d = deadline(1000)?;
        let mut waiting = Box::pin(p.wait(&s, &d));
        assert!(poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx).is_pending())).await);
        p.remove(&s)?;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), waiting)
                .await?
                .is_err()
        );
        p.register(s.clone(), 2, [1; 32], [2; 32])?;
        p.observe_verified(observed(&s, "session", 1, 2, 3)?)?;
        p.observe_verified(observed(&s, "http", 2, 2, 5)?)?;
        let expired = deadline(1)?;
        tokio::time::sleep(Duration::from_millis(3)).await;
        assert!(p.wait(&s, &expired).await.is_err());
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}
#[test]
fn outstanding_waiter_cannot_consume_replacement_generation() -> Check {
    runtime()?.block_on(async {
        let p = PreparedRequestProofs::new(1);
        let s = session(1)?;
        p.register(s.clone(), 2, [1; 32], [2; 32])?;
        let d = deadline(1000)?;
        let mut old = Box::pin(p.wait(&s, &d));
        assert!(poll_fn(|cx| Poll::Ready(old.as_mut().poll(cx).is_pending())).await);
        p.remove(&s)?;
        p.register(s.clone(), 3, [3; 32], [4; 32])?;
        p.observe_verified(observed(&s, "session", 3, 3, 7)?)?;
        p.observe_verified(observed(&s, "http", 4, 3, 8)?)?;
        let result = old.await;
        if let Ok(value) = &result {
            eprintln!(
                "old generation2 waiter received generation3 request IDs: {:?} / {:?}",
                value.session_request, value.http_request
            );
        }
        assert!(
            result.is_err(),
            "retired C1 waiter consumed a replacement generation's proofs"
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}
