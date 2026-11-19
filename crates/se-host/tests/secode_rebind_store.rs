//! Real FULL transactions protect both grants across a service restart.
#![cfg(all(feature = "secode", any(target_os = "linux", windows)))]
use se_config::config_policy::ConfigFile;
use se_core::{
    commit::Cx,
    dispatch::{CallFacts, Kernel},
    ops::{
        agent_launch::{AgentLaunch, LaunchPlan},
        process_commit, process_plan,
    },
};
use se_store::*;
use se_types::{AgentId, LifecycleId, NativePath, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/host_fixture.rs"]
mod native_host;
use native_host::*;
#[path = "support/process_barrier_fixture.rs"]
#[allow(dead_code, reason = "shared real-store lifecycle fixture")]
mod barrier;
use barrier::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(dead_code, reason = "shared session identifier fixtures")]
mod capture;
#[path = "../../se-store/tests/support/wave2_control_fixture.rs"]
#[allow(dead_code, reason = "shared control fixture")]
mod control;

fn setup(h: &Harness) -> Result<se_types::SessionId, Box<dyn std::error::Error>> {
    let session = capture::session()?;
    let mut prepared = capture::prepared(&h.f, &session, &h.target);
    if let EventBody::SessionPrepared { provider, .. } = &mut prepared {
        *provider = Provider::SeCode;
    }
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
    let mut events = vec![prepared];
    for (purpose, hash) in [("session", [11; 32]), ("http", [12; 32])] {
        events.push(EventBody::CredentialIssued {
            credential: process_commit::session_credential_id(&session, purpose)?,
            session: session.clone(),
            purpose: purpose.into(),
            secret_sha256: hash,
            expires_at_us: now + 3_600_000_000,
            activation_deadline_us: now + 600_000_000,
            expected: Expected::Absent,
        });
    }
    h.write(events)?;
    let mut events = vec![capture::activated(&session)?];
    for purpose in ["session", "http"] {
        events.push(EventBody::CredentialActivated {
            credential: process_commit::session_credential_id(&session, purpose)?,
            session: session.clone(),
            expected: revision(1)?,
            first_request: capture::record()?,
        });
    }
    h.write(events)?;
    Ok(session)
}

fn rebind_batch(
    h: &Harness,
    session: &se_types::SessionId,
    restart: CredentialRestart,
    key: &str,
    hashes: [[u8; 32]; 2],
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let admission = h.f.owner_project();
    let mut snapshot = h.snapshot(&h.owner())?;
    let batch = process_commit::rebind(
        &barrier::kernel()?,
        process_commit::RebindGrant {
            session: session.clone(),
            agent: h.target.clone(),
            restart,
            key: se_types::IdempotencyKey::new(key)?,
            session_hash: hashes[0],
            http_hash: hashes[1],
        },
        &mut Cx {
            read: &mut snapshot,
            admission: &admission,
        },
    )?;
    Ok(batch)
}

#[test]
fn rotation_is_atomic_and_same_restart_replays_the_original_grants() -> Check {
    let h = Harness::new()?;
    let session = setup(&h)?;
    let peer = se_proc::native_ipc::observe_ipc_self()?;
    let restart = CredentialRestart {
        boot: se_types::BootId::new("native-observation")?,
        pid: std::num::NonZeroU32::new(peer.pid()).ok_or("zero pid")?,
        started: peer.started().clone(),
        image_sha256: peer.image_sha256(),
        control_endpoint: "http://127.0.0.1:43123/".into(),
    };
    let before = h.snapshot(&h.owner())?;
    let hashes = [[21; 32], [22; 32]];
    let receipt = h.commit(rebind_batch(
        &h,
        &session,
        restart.clone(),
        "restart-first",
        hashes,
    )?)?;
    assert_eq!(receipt.state, CommitState::Committed);
    for purpose in ["session", "http"] {
        let id = process_commit::session_credential_id(&session, purpose)?;
        assert!(present(before.credential_head(id)?)?.restart.is_none());
    }
    for hash in [[11; 32], [12; 32]] {
        assert!(matches!(
            present(SqliteFactory::open_reader(&h.f.options)?)?.credential(hash)?,
            Read::Absent { .. }
        ));
    }
    for hash in hashes {
        assert_eq!(h.credential(hash)?.state, CredentialState::Active);
    }
    let replay = h.commit(rebind_batch(
        &h,
        &session,
        restart.clone(),
        "restart-first",
        hashes,
    )?)?;
    assert_eq!(replay.state, CommitState::Replayed);
    let mut ambiguous = restart.clone();
    ambiguous.control_endpoint = "http://127.0.0.1:43124/".into();
    assert!(
        rebind_batch(
            &h,
            &session,
            ambiguous,
            "restart-ambiguous",
            [[31; 32], [32; 32]]
        )
        .is_err()
    );
    let after = h.snapshot(&h.owner())?;
    for purpose in ["session", "http"] {
        let id = process_commit::session_credential_id(&session, purpose)?;
        assert_eq!(
            present(after.credential_head(id)?)?.restart,
            Some(restart.clone())
        );
    }
    drop(after);
    drop(before);
    h.finish()
}
