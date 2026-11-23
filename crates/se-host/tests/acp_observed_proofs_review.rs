//! Public proof handoff for ACP launches: observed first-use requests only.
#![cfg(feature = "runtime")]
use se_host::{PreparedRequestProofs, VerifiedPreparedRequest};
use se_store::{RecordId, RecordIdentity};
use se_types::SessionId;

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
fn verified(
    s: &SessionId,
    purpose: &'static str,
    hash: u8,
    request: u8,
) -> Result<VerifiedPreparedRequest, Box<dyn std::error::Error>> {
    Ok(VerifiedPreparedRequest {
        session: s.clone(),
        purpose,
        secret_sha256: [hash; 32],
        generation: 2,
        request: id(request)?,
    })
}

/// Protects: an unobserved transport reads as absent, never as a fabricated
/// request identity, and repeated reads stay absent.
#[test]
fn unobserved_transports_are_absent_without_fabricated_ids() -> Check {
    let proofs = PreparedRequestProofs::new(1);
    let s = session(1)?;
    proofs.register(s.clone(), 2, [1; 32], [2; 32])?;
    for _ in 0..2 {
        let observed = proofs.observed(&s)?;
        assert_eq!(observed.session_request, None);
        assert_eq!(observed.http_request, None);
    }
    Ok(())
}

/// Protects: verified first uses are preserved exactly (first wins), and a
/// missing purpose stays absent rather than being filled in.
#[test]
fn verified_first_requests_are_preserved_and_the_other_stays_absent() -> Check {
    let proofs = PreparedRequestProofs::new(1);
    let s = session(1)?;
    proofs.register(s.clone(), 2, [1; 32], [2; 32])?;
    proofs.observe_verified(verified(&s, "session", 1, 3)?)?;
    proofs.observe_verified(verified(&s, "session", 1, 4)?)?;
    let observed = proofs.observed(&s)?;
    assert_eq!(observed.session_request, Some(id(3)?));
    assert_eq!(observed.http_request, None);
    proofs.observe_verified(verified(&s, "http", 2, 5)?)?;
    let observed = proofs.observed(&s)?;
    assert_eq!(observed.session_request, Some(id(3)?));
    assert_eq!(observed.http_request, Some(id(5)?));
    Ok(())
}

/// Protects: a session with no retained verifier slot is refused, not read
/// as two absent witnesses.
#[test]
fn unregistered_session_is_refused() -> Check {
    let proofs = PreparedRequestProofs::new(1);
    proofs.register(session(1)?, 2, [1; 32], [2; 32])?;
    assert!(proofs.observed(&session(2)?).is_err());
    proofs.remove(&session(1)?)?;
    assert!(proofs.observed(&session(1)?).is_err());
    Ok(())
}
