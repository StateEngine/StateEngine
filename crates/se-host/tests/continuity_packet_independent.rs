//! Independent public continuity operations over the real store and captured
//! transcript producer. These reads must not acknowledge or activate anything.
#![cfg(any(target_os = "linux", windows))]
use se_core::{commit::Cx, ops::continuity::*};
use se_store::*;
use se_types::{AgentId, SessionId, UnixMicros};
use sha2::{Digest, Sha256};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
mod capture;
use std::sync::Arc;
struct Harness {
    f: Fixture,
    direct: SqliteDirect,
    lease: Arc<Lease>,
    a: SessionId,
    b: SessionId,
    source: RecordId,
}
impl Harness {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let f = Fixture::new()?;
        let (mut direct, lease) = f.direct()?;
        let a = capture::session()?;
        let b = capture::session()?;
        let source = capture::record()?;
        capture::active(&f, &mut direct, &lease, &a, source)?;
        std::fs::write(f.home.join("transcript.jsonl"), b"ten bytes!".repeat(8))?;
        for ordinal in 0..6 {
            direct.append(
                capture::capture(
                    &f,
                    &a,
                    source,
                    b"first",
                    ordinal * 10,
                    ordinal + 1,
                    &format!("packet-turn-{ordinal}"),
                )?,
                &*lease,
            )?;
        }
        direct.append(
            f.batch(
                f.owner_project(),
                Some(fixture::request(&format!(
                    "fixture-continuity_packet_independent-45-{}",
                    serial()
                ))?),
                vec![
                    capture::prepared(&f, &b, &f.b),
                    capture::activated(&b)?,
                    EventBody::ProfileSaved {
                        agent: f.a.clone(),
                        profile: Profile {
                            provider: Provider::SeCode,
                            model: Some("profile-drift-model".into()),
                            permission: PermissionProfile::WorkspaceWrite,
                            named_profile: "default".into(),
                            effort: None,
                        },
                        expected: Expected::Absent,
                    },
                    EventBody::ProfileSaved {
                        agent: f.b.clone(),
                        profile: Profile {
                            provider: Provider::Claude,
                            model: None,
                            permission: PermissionProfile::WorkspaceWrite,
                            named_profile: "default".into(),
                            effort: None,
                        },
                        expected: Expected::Absent,
                    },
                ],
            )?,
            &*lease,
        )?;
        direct.append(
            f.working(
                &"private A state 🦊é".repeat(300),
                Expected::Absent,
                "packet-state",
            )?,
            &*lease,
        )?;
        direct.append(
            f.send(
                Actor::Agent(f.b.clone()),
                Actor::Agent(f.a.clone()),
                message()?,
                "unread A packet marker",
                "packet-unread",
            )?,
            &*lease,
        )?;
        Ok(Self {
            f,
            direct,
            lease,
            a,
            b,
            source,
        })
    }
    fn scope(&self, agent: &AgentId, session: Option<SessionId>) -> ReadScope {
        let mut scope = self.f.self_scope(agent);
        scope.admission.session = session;
        scope
    }
    fn context(
        &self,
        agent: &AgentId,
        session: Option<SessionId>,
        input: SessionContextRequest,
    ) -> Result<se_types::Result<SessionContextOutput>, Box<dyn std::error::Error>> {
        let scope = self.scope(agent, session);
        let admission = scope.admission.clone();
        let mut read = self.direct.snapshot(scope)?;
        Ok(context(
            input,
            UnixMicros::new(1_800_000_000_000_000)?,
            &mut Cx {
                read: &mut read,
                admission: &admission,
            },
        ))
    }
    fn resume(
        &self,
        scope: ReadScope,
        input: Resume,
    ) -> Result<se_types::Result<ResumeOutput>, Box<dyn std::error::Error>> {
        let admission = scope.admission.clone();
        let mut read = self.direct.snapshot(scope)?;
        Ok(resume(
            input,
            UnixMicros::new(1_800_000_000_000_000)?,
            &mut Cx {
                read: &mut read,
                admission: &admission,
            },
        ))
    }
    fn head(&self) -> Result<Option<StorePosition>, Box<dyn std::error::Error>> {
        Ok(self
            .direct
            .snapshot(self.f.scoped(Visibility::Owner))?
            .info()
            .head)
    }
    fn finish(self) -> Check {
        self.direct.close()?;
        drop(self.lease);
        Ok(())
    }
}
fn request(bytes: u32) -> SessionContextRequest {
    SessionContextRequest {
        governing_cursor: None,
        limit: 20,
        since: None,
        byte_budget: bytes,
    }
}
fn resume_request(bytes: u32, preview_agent: Option<AgentId>) -> Resume {
    Resume {
        limit: 20,
        governing_cursor: None,
        since: None,
        byte_budget: bytes,
        preview_agent,
    }
}
fn model(output: &SessionContextOutput) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(&output.assembled_model_input)?)
}
fn encoded<T: serde::Serialize>(
    schema: &str,
    value: &T,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut value = serde_json::to_value(value)?;
    value
        .as_object_mut()
        .ok_or("wire object")?
        .insert("schema".into(), schema.into());
    Ok(serde_json::to_vec(&value)?.len())
}

/// Protects: the packet carries the saved active-session identity, truthful
/// UTF-8 byte/digest accounting and the same unacknowledged read set as resume.
#[test]
fn context_and_resume_share_real_read_state_without_writing() -> Check {
    let h = Harness::new()?;
    let before = h.head()?;
    let context = h.context(&h.f.a, Some(h.a.clone()), request(32768))??;
    let resume = h.resume(
        h.scope(&h.f.a, Some(h.a.clone())),
        resume_request(32768, None),
    )??;
    assert_eq!(context.agent_id, h.f.a);
    assert_eq!(context.session_id, h.a);
    assert_eq!(
        context.harness, "claude",
        "profile drift replaced the saved session provider"
    );
    assert_eq!(context.conversation, format!("provider-{}", h.f.a.as_str()));
    assert_eq!(
        context.byte_size,
        context.assembled_model_input.len() as u64
    );
    assert_eq!(
        context.packet_id,
        format!(
            "{:x}",
            Sha256::digest(context.assembled_model_input.as_bytes())
        ),
        "packet digest changed"
    );
    let model = model(&context)?;
    assert_eq!(
        model["working_state"],
        serde_json::to_value(&resume.working_state)?
    );
    assert_eq!(model["unread"], serde_json::to_value(&resume.unread)?);
    assert_eq!(
        model["recent_turns"],
        serde_json::to_value(&resume.recent_turns)?
    );
    assert_eq!(
        model["required_reads"]
            .as_array()
            .ok_or("required reads")?
            .len(),
        1
    );
    assert_eq!(model["resume_status"], "needs_read");
    assert_eq!(
        resume.budget.used_bytes,
        encoded("se.resume/v1", &resume)? as u64
    );
    assert_eq!(
        h.head()?,
        before,
        "context or resume committed an acknowledgement"
    );
    let mut outside = h.direct.snapshot(h.scope(&h.f.a, Some(h.a.clone())))?;
    assert!(
        matches!(
            outside.cursor(h.f.a.clone(), "continuity".into())?,
            se_types::Read::Absent { .. }
        ),
        "read issued a durable cursor head"
    );
    assert!(matches!(
        present(outside.session(h.a.clone())?)?.current.body,
        EventBody::SessionActivated { .. }
    ));
    drop(outside);
    h.finish()
}

/// Protects: budget reduction keeps valid Unicode and honest omissions instead
/// of silently dropping work or exceeding the full serialized output budget.
#[test]
fn context_byte_boundaries_preserve_unicode_and_name_every_cut() -> Check {
    let h = Harness::new()?;
    for bytes in [32768, 16384, 8192] {
        let context = h.context(&h.f.a, Some(h.a.clone()), request(bytes))??;
        assert!(
            encoded("secode.session-context-v1", &context)? <= bytes as usize,
            "context exceeded requested wire budget"
        );
        assert_eq!(
            context.byte_size,
            context.assembled_model_input.len() as u64
        );
        assert_eq!(
            context.packet_id,
            format!(
                "{:x}",
                Sha256::digest(context.assembled_model_input.as_bytes())
            ),
            "packet digest changed"
        );
        let parsed = model(&context)?;
        let omissions = parsed["omissions"].as_array().ok_or("omission array")?;
        if context.truncated {
            assert!(
                !omissions.is_empty() || !context.failures.is_empty(),
                "truncated packet hid its cause"
            );
        }
        let working = &parsed["working_state"]["value"];
        if let (Some(text), Some(bytes)) = (working["text"].as_str(), working["bytes"].as_u64())
            && (text.len() as u64) < bytes
        {
            assert_eq!(
                working["complete"], false,
                "working-state truncation claimed complete"
            );
        }
        let retained = parsed["recent_turns"]
            .as_array()
            .ok_or("recent turns")?
            .len() as u64;
        let omitted = omissions
            .iter()
            .filter(|item| item["section"] == "recent_turns")
            .map(|item| {
                item["count"]
                    .as_u64()
                    .ok_or("unknown bounded turn omission")
            })
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .sum::<u64>();
        assert_eq!(
            retained + omitted,
            6,
            "packet lost its recent-turn accounting"
        );
        assert!(
            !context.assembled_model_input.contains('\u{fffd}'),
            "byte trimming split UTF-8"
        );
    }
    for bytes in [0, 1023, 1_048_577] {
        assert!(
            h.context(&h.f.a, Some(h.a.clone()), request(bytes))?
                .is_err(),
            "invalid byte bound accepted"
        );
    }
    h.finish()
}

/// Protects: owner preview does not impersonate an agent; replay positions
/// preserve their principal/target purpose and agents cannot preview peers.
#[test]
fn preview_and_since_do_not_cross_their_authority_or_target() -> Check {
    let h = Harness::new()?;
    let preview = h.resume(
        h.f.scoped(Visibility::Owner),
        resume_request(32768, Some(h.f.a.clone())),
    )??;
    assert!(preview.principal.preview);
    assert_eq!(preview.principal.agent.id, h.f.a);
    let b_preview = h.resume(
        h.f.scoped(Visibility::Owner),
        resume_request(32768, Some(h.f.b.clone())),
    )??;
    assert_eq!(b_preview.principal.agent.id, h.f.b);
    let mut wrong = resume_request(32768, Some(h.f.b.clone()));
    wrong.since = Some(preview.cursor.clone());
    assert!(
        h.resume(h.f.scoped(Visibility::Owner), wrong)?.is_err(),
        "owner preview cursor crossed target"
    );
    let mut wrong = request(32768);
    wrong.since = Some(preview.cursor);
    assert!(
        h.context(&h.f.a, Some(h.a.clone()), wrong)?.is_err(),
        "owner cursor crossed to bound-session authority"
    );
    assert!(
        h.resume(
            h.scope(&h.f.a, Some(h.a.clone())),
            resume_request(32768, Some(h.f.b.clone()))
        )?
        .is_err(),
        "agent acquired owner preview authority"
    );
    assert!(
        h.context(&h.f.a, None, request(32768))?.is_err(),
        "unbound agent received session context"
    );
    assert!(
        h.context(&h.f.b, Some(h.a.clone()), request(32768))?
            .is_err(),
        "foreign session received context"
    );
    let mut successor = h.scope(&h.f.a, Some(h.a.clone()));
    successor.admission.generation += 1;
    assert!(
        h.resume(successor, resume_request(32768, None))?.is_err(),
        "a new generation received context without current-host native reconciliation"
    );
    let b = h.context(&h.f.b, Some(h.b.clone()), request(32768))??;
    assert!(!b.assembled_model_input.contains("private A state"));
    assert!(!b.assembled_model_input.contains("unread A packet marker"));
    assert!(!b.assembled_model_input.contains("packet-turn-"));
    h.finish()
}

/// Protects: loss of the governing source is a named incomplete packet, never
/// a complete model input that silently drops current project law.
#[test]
fn governing_source_is_complete_or_explicitly_failed() -> Check {
    let mut h = Harness::new()?;
    let decision = se_types::DecisionId::from_parts(1_700_000_000_000 + serial(), [57; 10])?;
    let proposed = h.direct.append(
        h.f.batch(
            h.f.admission(
                Scope::Project(h.f.project.clone()),
                Actor::Agent(h.f.a.clone()),
            ),
            Some(fixture::request(&format!(
                "fixture-continuity_packet_independent-394-{}",
                serial()
            ))?),
            vec![EventBody::DecisionProposed {
                decision: decision.clone(),
                key: "governing.packet".into(),
                statement: InputText::Inline("current project law marker".into()),
                rationale: None,
                prior: None,
                kind: DecisionKind::Decision,
            }],
        )?,
        &*h.lease,
    )?;
    h.direct.append(
        h.f.batch(
            h.f.owner_project(),
            Some(fixture::request(&format!(
                "fixture-continuity_packet_independent-412-{}",
                serial()
            ))?),
            vec![EventBody::DecisionRatified {
                decision,
                expected: revision(1)?,
                approval: proposed.primary_event,
            }],
        )?,
        &*h.lease,
    )?;
    let context = h.context(&h.f.a, Some(h.a.clone()), request(32768))??;
    let parsed = model(&context)?;
    if context.failures.is_empty() {
        assert!(
            context
                .assembled_model_input
                .contains("current project law marker"),
            "complete governing source silently dropped law"
        );
    } else {
        assert!(context.truncated);
        assert_eq!(parsed["resume_status"], "integrity_blocked");
        assert!(
            parsed["omissions"]
                .as_array()
                .ok_or("omissions")?
                .iter()
                .any(|item| item["section"] == "governing_decisions" && item["count"].is_null()),
            "refused governing source invented a zero omission count"
        );
        assert!(
            context
                .failures
                .iter()
                .any(|failure| failure.message().contains("visibility")),
            "governing source failure lost its reason"
        );
    }
    h.finish()
}

/// Protects: another agent's newer private write cannot prevent this bound
/// agent from receiving its own packet, nor become visible through its cursor.
#[test]
fn unrelated_private_head_cannot_block_bound_continuity() -> Check {
    let mut h = Harness::new()?;
    h.direct.append(
        h.f.batch(
            h.f.admission(
                Scope::Project(h.f.project.clone()),
                Actor::Agent(h.f.b.clone()),
            ),
            Some(fixture::request(&format!(
                "fixture-continuity_packet_independent-460-{}",
                serial()
            ))?),
            vec![EventBody::WorkingStateSet {
                agent: h.f.b.clone(),
                text: InputText::Inline("PRIVATE B LAST HEAD".into()),
                expected: Expected::Absent,
            }],
        )?,
        &*h.lease,
    )?;
    let result = h.context(&h.f.a, Some(h.a.clone()), request(32768))?;
    assert!(
        result.is_ok(),
        "newer private B head blocked A continuity: {result:?}"
    );
    assert!(
        !result?
            .assembled_model_input
            .contains("PRIVATE B LAST HEAD")
    );
    h.finish()
}

#[path = "support/continuity_delta.rs"]
mod delta;
