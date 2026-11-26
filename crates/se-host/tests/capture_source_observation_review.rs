//! Reviewer judge: status keeps "no conversation yet", "no capture source"
//! and "capture failed" as distinct, readable resume facts, and a real capture
//! failure keeps its own diagnostic. The real store and observation run; no
//! provider process is launched.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(
    dead_code,
    reason = "The shared fixture also supplies capture progress setups."
)]
mod session;

use fixture::*;
use se_core::{
    commit::Cx,
    dispatch::{CallFacts, Kernel},
    ops::{AgentRow, process_commit, session_reference::CODEX_PENDING},
};
use se_host::{observe_agent, prepare_agent_observation};
use se_store::*;
use se_types::SessionId;
use std::time::{Duration, Instant};

/// How far the recorded session got before status observes it.
enum Recorded {
    /// Prepared for a provider that has not yet allocated its conversation.
    PendingConversation,
    /// A recorded conversation whose capture source was never bound.
    NoSource,
    /// A bound capture source whose latest capture failed.
    CaptureFailed(&'static str),
}

fn profile(f: &Fixture, provider: Provider) -> se_types::Result<EventBody<InputText>> {
    Ok(EventBody::ProfileSaved {
        agent: f.a.clone(),
        profile: Profile {
            provider_settings: Default::default(),
            provider,
            model: None,
            permission: PermissionProfile::WorkspaceWrite,
            harness: None,
            named_profile: "default".into(),
            effort: None,
            external: false,
        },
        expected: Expected::Absent,
    })
}

fn kernel() -> Result<Kernel, Box<dyn std::error::Error>> {
    Ok(Kernel::new(CallFacts {
        event: event()?,
        message: message()?,
        agent: agent()?,
        profile_event: event()?,
        notification_event: event()?,
        notification_message: message()?,
        occurred_at_us: 1_700_000_000_000_000,
        door: Door::Hook,
    })?)
}

fn record(f: &Fixture, recorded: &Recorded) -> Result<SessionId, Box<dyn std::error::Error>> {
    let (mut direct, lease) = f.direct()?;
    let id = session::session()?;
    let provider = match recorded {
        Recorded::PendingConversation => Provider::Codex,
        _ => Provider::Claude,
    };
    let mut prepared = session::prepared(f, &id, &f.a);
    let EventBody::SessionPrepared {
        provider: recorded_provider,
        native_ref,
        ..
    } = &mut prepared
    else {
        return Err("fixture preparation changed shape".into());
    };
    *recorded_provider = provider;
    if matches!(recorded, Recorded::PendingConversation) {
        *native_ref = format!("{CODEX_PENDING}{id}");
    }
    let conversation = native_ref.clone();
    let mut events = vec![profile(f, provider)?, prepared];
    if !matches!(recorded, Recorded::PendingConversation) {
        events.push(session::activated(&id)?);
    }
    if let Recorded::CaptureFailed(_) = recorded {
        let path = f.home.join("transcript.jsonl");
        std::fs::write(&path, b"")?;
        let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("missing native source")?;
        let source = process_commit::session_credential_id(&id, "capture-source")?;
        let mut bound = session::source(source, &id, &pin.identity(), Expected::Absent);
        if let EventBody::CaptureSource { native_ref, .. } = &mut bound {
            *native_ref = conversation;
        }
        events.push(bound);
    }
    direct.append(
        f.batch(
            f.owner_project(),
            Some(request("observed-session")?),
            events,
        )?,
        &*lease,
    )?;
    if let Recorded::CaptureFailed(cause) = recorded {
        let mut scope = f.self_scope(&f.a);
        scope.admission.session = Some(id.clone());
        let mut read = direct.snapshot(scope.clone())?;
        let batch = process_commit::capture_failure(
            &kernel()?,
            id.clone(),
            se_types::SeError::invalid("native source", cause).body,
            &mut Cx {
                read: &mut read,
                admission: &scope.admission,
            },
        )?;
        read.close()?;
        direct.append(batch, &*lease)?;
    }
    direct.close()?;
    drop(lease);
    Ok(id)
}

/// The agent row exactly as status observes it from a fresh snapshot.
fn observed(f: &Fixture) -> Result<AgentRow, Box<dyn std::error::Error>> {
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut read = reader.snapshot(f.scoped(Visibility::Owner))?;
    let admission = f.owner_project();
    let mut row = present(
        se_core::ops::agent_status::show(
            se_core::ops::AgentShow {
                target_agent_id: Some(f.a.clone()),
            },
            &mut Cx {
                read: &mut read,
                admission: &admission,
            },
        )?
        .agent,
    )?;
    let plan = prepare_agent_observation(&f.project, &row, &mut read)?;
    read.close()?;
    observe_agent(plan, Instant::now() + Duration::from_secs(2))?.apply(&mut row)?;
    Ok(row)
}

fn not_resumable(row: &AgentRow) {
    assert!(!row.resume.ready, "{:?}", row.resume);
    assert!(row.resume.command.is_none() && row.resume.argv.is_none());
}

/// A session whose provider never allocated a conversation has nothing to
/// verify: status says so plainly instead of reporting an internal failure.
#[test]
fn no_recorded_conversation_reads_as_none_not_unverifiable() -> Check {
    let f = Fixture::new()?;
    record(&f, &Recorded::PendingConversation)?;
    let row = observed(&f)?;
    assert_eq!(row.conversation.id, None);
    assert_eq!(row.conversation.state, "none", "{:?}", row.resume);
    not_resumable(&row);
    assert_eq!(
        row.resume.reason.as_deref(),
        Some("No provider conversation has been recorded for this agent.")
    );
    assert!(
        matches!(row.resume.mode.as_str(), "new" | "running"),
        "{}",
        row.resume.mode
    );
    Ok(())
}

/// A recorded conversation without a capture source is not "none": it is a
/// conversation status cannot verify, with a reason a person can act on.
#[test]
fn a_recorded_conversation_without_a_capture_source_is_unverifiable() -> Check {
    let f = Fixture::new()?;
    record(&f, &Recorded::NoSource)?;
    let row = observed(&f)?;
    assert!(row.conversation.id.is_some());
    assert_eq!(row.conversation.state, "unverifiable");
    not_resumable(&row);
    assert_eq!(
        row.resume.reason.as_deref(),
        Some(
            "No capture source has been recorded for this session; its conversation cannot be verified for resume."
        )
    );
    Ok(())
}

/// A failed capture is unreadable, not absent: its own diagnostic reaches the
/// resume reason unchanged instead of a wrapped internal error.
#[test]
fn a_failed_capture_keeps_its_own_diagnostic() -> Check {
    let f = Fixture::new()?;
    let cause = "synthetic truncated native record";
    record(&f, &Recorded::CaptureFailed(cause))?;
    let row = observed(&f)?;
    assert!(row.conversation.id.is_some());
    assert_eq!(row.conversation.state, "unverifiable");
    not_resumable(&row);
    let reason = row.resume.reason.as_deref().ok_or("no resume reason")?;
    assert!(
        reason.starts_with("Capture failed since the last committed turn")
            && reason.contains(cause),
        "the capture diagnostic was replaced or wrapped: {reason}"
    );
    assert!(
        !reason.contains("No capture source has been recorded"),
        "a failed capture was reported as an absent source: {reason}"
    );
    Ok(())
}
