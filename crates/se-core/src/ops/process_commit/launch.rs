//! Reservation, native creation and C3 activation store barriers.
use super::*;

/// C1: process reservation and both prepared credentials precede all native
/// creation. Hashes bind the exact delivered sec1 and sels token bytes.
pub fn reserve<R: Snapshot>(
    kernel: &Kernel,
    plan: &LaunchPlan,
    identity: ProcessIdentityRecord,
    session_hash: [u8; 32],
    http_hash: [u8; 32],
    cx: &mut Cx<'_, R>,
) -> Result<AtomicBatch> {
    let now = kernel.facts()?.occurred_at_us;
    let deadline = now
        .checked_add(600_000_000)
        .ok_or_else(|| scope::unreadable("credential deadline", "clock overflow"))?;
    let expires = now
        .checked_add(86_400_000_000)
        .ok_or_else(|| scope::unreadable("credential expiry", "clock overflow"))?;
    let mut bodies = vec![
        super::super::session_commit::prepare(super::super::session_commit::SessionPreparation {
            session: plan.session.clone(),
            agent: plan.agent.id.clone(),
            provider: plan.profile.provider,
            surface: Some(if plan.input.detach {
                se_store::SessionSurface::Headless
            } else {
                se_store::SessionSurface::Window
            }),
            native_ref: match &plan.conversation {
                se_types::Read::Present { value } => value.to_string(),
                _ if plan.profile.provider == se_store::Provider::Codex => format!(
                    "{}{}",
                    super::super::session_reference::CODEX_PENDING,
                    plan.session
                ),
                _ if plan.profile.provider == se_store::Provider::Acp => format!(
                    "{}{}",
                    super::super::session_reference::ACP_PENDING,
                    plan.session
                ),
                _ if plan.profile.provider == se_store::Provider::SeCode => format!(
                    "{}{}",
                    super::super::session_reference::SECODE_PENDING,
                    plan.session
                ),
                _ => plan.session.as_str()[se_types::SessionId::PREFIX.len()..].into(),
            },
            consent: if plan.capture {
                se_store::Consent::Capture
            } else {
                se_store::Consent::Suppressed
            },
            generation: cx.admission.generation,
            expected: Expected::Absent,
        })?,
        EventBody::ProcessRegistered {
            identity: Box::new(identity),
            initial: ProcessState::Reserved,
        },
    ];
    if let Some((connection, action)) = &plan.channel_resume {
        // The normal SessionPrepared remains primary for launch replay. The
        // grant is consumed in this same C1 transaction before native creation.
        bodies.insert(
            1,
            EventBody::ChannelRecorded {
                change: se_store::channel::Change::ResumeReleased {
                    connection: connection.clone(),
                    action: action.clone(),
                    session: plan.session.clone(),
                },
            },
        );
    }
    // Re-read the control grant and preparations in the same finite planning
    // snapshot. No new native effect may coexist with an unreleased lifecycle.
    let current = scope::require_present(
        cx.read
            .control_target(plan.agent.id.clone())
            .map_err(|e| crate::store_error::store_error(&e))?,
        "launch control",
        "Restore the current create grant or use the owner's terminal.",
    )?;
    if !current.processes.is_empty() {
        return Err(se_types::SeError::invalid(
            "launch target",
            "stop or reconcile the target's owned lifecycle before launching again",
        ));
    }
    for old in current.sessions {
        let session = match &old.current.body {
            EventBody::SessionPrepared { session, .. } => session,
            _ => {
                return Err(se_types::SeError::invalid(
                    "launch target",
                    "stop its active session before launching again",
                ));
            }
        };
        // Managed preparations have exactly these two capabilities;
        // missing or independently changed credentials refuse the whole batch.
        for purpose in ["session", "http"] {
            bodies.push(EventBody::CredentialRevoked {
                credential: session_credential_id(session, purpose)?,
                expected: revision(1)?,
                reason: InputText::Inline(
                    "superseded by a newer managed launch preparation".into(),
                ),
            });
        }
        bodies.push(EventBody::SessionRevoked {
            session: session.clone(),
            expected: Expected::Revision(old.revision),
            reason: InputText::Inline("superseded by a newer managed launch preparation".into()),
        });
    }
    for (purpose, hash) in [("session", session_hash), ("http", http_hash)] {
        bodies.push(EventBody::CredentialIssued {
            credential: credential_id(plan, purpose)?,
            session: plan.session.clone(),
            purpose: purpose.into(),
            secret_sha256: hash,
            expires_at_us: expires,
            activation_deadline_us: deadline,
            expected: Expected::Absent,
        });
    }
    let intent = plan.input.intent(&plan.agent.id)?;
    batch(
        kernel,
        "agent.launch",
        plan.input.idempotency_key.clone(),
        intent,
        bodies,
        cx,
    )
}
/// C2 and the tracked-helper RootCheckpoint: the previous protected revision
/// and observation event come from the same admitted finite control read.
pub fn transition<R: Snapshot>(
    kernel: &Kernel,
    plan: &LaunchPlan,
    phase: &str,
    previous: &se_store::ProjectionRecord,
    identity: ProcessIdentityRecord,
    edge: (ProcessState, ProcessState),
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let containment = identity.containment.clone();
    batch(
        kernel,
        "agent.launch",
        phase_key(&plan.input.idempotency_key, phase)?,
        serde_json::json!({"session":plan.session,"phase":phase}),
        vec![EventBody::ProcessTransition {
            process: plan.lifecycle.clone(),
            identity: Box::new(identity),
            expected: Expected::Revision(previous.revision),
            from: edge.0,
            to: edge.1,
            observation: previous.current.header.event.clone(),
            outcome: phase.into(),
            containment,
        }],
        cx,
    )
}
/// C3: native exec plus the owned stdout init echo have both been witnessed.
/// Running, session activation and both capabilities become visible atomically.
pub struct CaptureActivation {
    pub source: RecordId,
    pub native_ref: String,
    pub incarnation: Vec<u8>,
}
pub struct CredentialActivation {
    pub session_request: RecordId,
    pub http_request: RecordId,
}
pub struct Activation {
    pub capture: Option<CaptureActivation>,
    pub credentials: CredentialActivation,
}
pub fn activate<R: Snapshot>(
    kernel: &Kernel,
    plan: &LaunchPlan,
    previous: &se_store::ProjectionRecord,
    identity: ProcessIdentityRecord,
    activation: Activation,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    let Activation {
        capture,
        credentials,
    } = activation;
    if ((plan.capture || plan.profile.provider == se_store::Provider::SeCode) && capture.is_none())
        || (!plan.capture
            && capture.is_some()
            && plan.profile.provider == se_store::Provider::Claude)
    {
        return Err(se_types::SeError::invalid(
            "capture activation",
            "a trusted conversation binding for SE Code, or a native transcript pin when capture was consented",
        ));
    }
    let containment = identity.containment.clone();
    let observation = previous.current.header.event.clone();
    let mut bodies = vec![
        EventBody::ProcessTransition {
            process: plan.lifecycle.clone(),
            identity: Box::new(identity),
            expected: Expected::Revision(previous.revision),
            from: ProcessState::Starting,
            to: ProcessState::Running,
            observation: observation.clone(),
            outcome: "provider-init-witnessed".into(),
            containment: containment.clone(),
        },
        super::super::session_commit::activate(super::super::session_commit::SessionActivation {
            session: plan.session.clone(),
            expected: revision(1)?,
            incumbent: None,
            process: Some(plan.lifecycle.clone()),
            containment,
            witnesses: vec![observation],
        })?,
    ];
    if let Some(capture) = capture {
        bodies.push(EventBody::CaptureSource {
            source: capture.source,
            session: plan.session.clone(),
            consent: if plan.capture {
                se_store::Consent::Capture
            } else {
                se_store::Consent::Suppressed
            },
            native_ref: capture.native_ref,
            incarnation: capture.incarnation,
            expected: Expected::Absent,
        });
    }
    for purpose in ["session", "http"] {
        bodies.push(EventBody::CredentialActivated {
            credential: credential_id(plan, purpose)?,
            session: plan.session.clone(),
            expected: revision(1)?,
            first_request: if purpose == "session" {
                credentials.session_request
            } else {
                credentials.http_request
            },
        });
    }
    batch(
        kernel,
        "agent.launch",
        phase_key(&plan.input.idempotency_key, "activate")?,
        serde_json::json!({"session":plan.session,"phase":"activate"}),
        bodies,
        cx,
    )
}
