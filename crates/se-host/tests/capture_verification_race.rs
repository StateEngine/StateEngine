//! EOF acknowledgements must preserve failures committed after their observation.
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(
    dead_code,
    reason = "The shared fixture also supplies a complete active source setup."
)]
mod session;

use fixture::*;
use se_core::{
    commit::Cx,
    dispatch::{CallFacts, Kernel},
    ops::process_commit,
};
use se_store::*;
use se_types::{EventId, SessionId};

struct Capture {
    fixture: Fixture,
    direct: SqliteDirect,
    lease: std::sync::Arc<Lease>,
    session: SessionId,
    source: RecordId,
    pin: se_proc::NativeSourcePin,
}

impl Capture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let (mut direct, lease) = fixture.direct()?;
        let session = session::session()?;
        let source = process_commit::session_credential_id(&session, "capture-source")?;
        let path = fixture.home.join("transcript.jsonl");
        std::fs::write(&path, b"")?;
        let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("missing native source")?;
        direct.append(
            fixture.batch(
                fixture.owner_project(),
                Some(request("source")?),
                vec![
                    session::prepared(&fixture, &session, &fixture.a),
                    session::activated(&session)?,
                    session::source(source, &session, &pin.identity(), Expected::Absent),
                ],
            )?,
            &*lease,
        )?;
        Ok(Self {
            fixture,
            direct,
            lease,
            session,
            source,
            pin,
        })
    }

    fn scope(&self) -> ReadScope {
        let mut scope = self.fixture.self_scope(&self.fixture.a);
        scope.admission.session = Some(self.session.clone());
        scope
    }

    fn kernel() -> Result<Kernel, Box<dyn std::error::Error>> {
        Ok(Kernel::new(CallFacts {
            event: event()?,
            message: message()?,
            agent: agent()?,
            profile_event: event()?,
            occurred_at_us: 1_700_000_000_000_000,
            door: Door::Hook,
        })?)
    }

    fn fail(&mut self, description: &str) -> Result<EventId, Box<dyn std::error::Error>> {
        let scope = self.scope();
        let mut read = self.direct.snapshot(scope.clone())?;
        let batch = process_commit::capture_failure(
            &Self::kernel()?,
            self.session.clone(),
            se_types::SeError::invalid("native source", description).body,
            &mut Cx {
                read: &mut read,
                admission: &scope.admission,
            },
        )?;
        read.close()?;
        let event = batch.events[0].header.event.clone();
        self.direct.append(batch, &*self.lease)?;
        Ok(event)
    }

    fn verify(&self, failure: EventId) -> se_types::Result<AtomicBatch> {
        let scope = self.scope();
        let mut read = self
            .direct
            .snapshot(scope.clone())
            .map_err(|e| se_core::store_error::store_error(&e))?;
        let kernel = Self::kernel()
            .map_err(|e| se_types::SeError::invalid("fixture facts", &e.to_string()))?;
        let result = process_commit::capture_verified(
            &kernel,
            self.session.clone(),
            &self.fixture.owner,
            Some((0, failure)),
            &mut Cx {
                read: &mut read,
                admission: &scope.admission,
            },
        );
        read.close()
            .map_err(|e| se_core::store_error::store_error(&e))?;
        result
    }

    fn eof(&mut self) -> Check {
        let tail = self.pin.read_at(0, 1)?;
        assert!(tail.bytes.is_empty() && tail.end_of_file);
        Ok(())
    }

    fn outcome(&self) -> Result<StoredEvent, Box<dyn std::error::Error>> {
        let mut read = self.direct.snapshot(self.scope())?;
        let result = present(read.capture_outcome(self.source, None)?)?;
        read.close()?;
        Ok(result)
    }

    fn close(self) -> Check {
        self.direct.close()?;
        Ok(())
    }
}

#[test]
fn unchanged_observation_can_clear_the_observed_failure() -> Check {
    let mut capture = Capture::new()?;
    let failure = capture.fail("temporary write uncertainty")?;
    capture.eof()?;
    let verified = capture.verify(failure)?;
    capture.direct.append(verified, &*capture.lease)?;
    assert!(matches!(
        capture.outcome()?.body,
        EventBody::CaptureVerified { .. }
    ));
    capture.close()
}

#[test]
fn failure_changed_before_planning_is_refused() -> Check {
    let mut capture = Capture::new()?;
    let original = capture.fail("temporary write uncertainty")?;
    capture.eof()?;
    let newer = capture.fail("new incomplete native record")?;
    assert!(capture.verify(original).is_err());
    assert_eq!(capture.outcome()?.header.event, newer);
    capture.close()
}

#[test]
fn failure_changed_after_planning_cannot_be_cleared_by_the_old_eof() -> Check {
    let mut capture = Capture::new()?;
    let original = capture.fail("temporary write uncertainty")?;
    capture.eof()?;
    // Production planning closes its snapshot before submitting the FULL batch.
    let verified = capture.verify(original)?;
    // Another admitted hook can retain a new failure at the same committed cursor.
    std::fs::write(capture.fixture.home.join("transcript.jsonl"), b"{\"type\":")?;
    let newer = capture.fail("new incomplete native record")?;
    let commit = capture.direct.append(verified, &*capture.lease);
    let outcome = capture.outcome()?;
    assert_eq!(
        outcome.header.event,
        newer,
        "stale EOF verification erased a newer capture failure; commit accepted={}",
        commit.is_ok()
    );
    assert!(matches!(outcome.body, EventBody::CaptureFailed { .. }));
    capture.close()
}

#[test]
fn cursor_progress_after_planning_refuses_the_stale_eof_commit() -> Check {
    let mut capture = Capture::new()?;
    let original = capture.fail("temporary write uncertainty")?;
    capture.eof()?;
    let verified = capture.verify(original)?;
    std::fs::write(capture.fixture.home.join("transcript.jsonl"), b"ten bytes!")?;
    let progress = session::capture(
        &capture.fixture,
        &capture.session,
        capture.source,
        &capture.pin.identity(),
        0,
        1,
        "new-reply",
    )?;
    capture.direct.append(progress, &*capture.lease)?;
    let error = capture
        .direct
        .append(verified, &*capture.lease)
        .err()
        .ok_or("stale offset verification was accepted")?;
    assert_eq!(error.code, StoreErrorCode::SourceChanged);
    capture.close()
}

#[test]
fn legacy_unbound_acknowledgement_can_verify_a_healthy_cursor() -> Check {
    let mut capture = Capture::new()?;
    capture.eof()?;
    let scope = capture.scope();
    let mut read = capture.direct.snapshot(scope.clone())?;
    let mut verified = process_commit::capture_verified(
        &Capture::kernel()?,
        capture.session.clone(),
        &capture.fixture.owner,
        None,
        &mut Cx {
            read: &mut read,
            admission: &scope.admission,
        },
    )?;
    read.close()?;
    // This is the acknowledgement shape emitted before causal binding existed.
    for event in &mut verified.events {
        event.header.cause = None;
    }
    capture.direct.append(verified, &*capture.lease)?;
    assert!(matches!(
        capture.outcome()?.body,
        EventBody::CaptureVerified { .. }
    ));
    capture.close()
}

#[test]
fn legacy_unbound_acknowledgement_preserves_a_retained_failure() -> Check {
    let mut capture = Capture::new()?;
    let failure = capture.fail("temporary write uncertainty")?;
    capture.eof()?;
    let mut verified = capture.verify(failure.clone())?;
    for event in &mut verified.events {
        event.header.cause = None;
    }
    assert!(capture.direct.append(verified, &*capture.lease).is_err());
    assert_eq!(capture.outcome()?.header.event, failure);
    capture.close()
}
