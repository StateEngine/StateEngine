//! Canonical native turns: no transcript file, invented cursor or second writer.
use super::{EmbeddedHost, binding, store};
use crate::linked::{FromLinked, ToLinked};
use se_core::{scope, store_error::store_error};
use se_store::{EventBody, Expected, InputText, RecordIdentity, Snapshot};
use se_types::{Result, SeError};
use secode_stateengine_api as api;
use sha2::{Digest, Sha256};

/// Delivery identity belongs to the current reply, never the immutable source.
struct CaptureBatch {
    batch: se_store::AtomicBatch,
    delivery_key: api::IdempotencyKey,
}

impl EmbeddedHost {
    pub(super) async fn capture(
        &self,
        session: &api::BoundSession,
        turn: api::CapturedTurn,
        options: api::CallOptions,
    ) -> Result<api::Receipt<api::EventRef>> {
        let binding = self.bindings.verify(session)?;
        let (router, deadline, _cancel) = self.ready(&options).await?;
        if session.generation != options.generation || turn.conversation != binding.conversation {
            return Err(SeError::invalid(
                "linked capture",
                "the original bound generation and provider conversation",
            ));
        }
        if turn.content.utf8_bytes != turn.content.text.len() as u64
            || !turn.content.complete
            || turn.content.omitted_bytes.is_some_and(|n| n != 0)
        {
            return Err(SeError::invalid(
                "linked capture content",
                "complete text with matching byte count and SHA-256",
            ));
        }
        se_core::ops::inputs::bounded("vendor turn", &turn.vendor_turn, 512, false)?;
        se_core::ops::inputs::bounded("source CLI", &turn.source_cli, 64, false)?;
        if turn.source_cli != "secode" || turn.content.text.is_empty() {
            return Err(SeError::invalid(
                "linked capture source",
                "nonempty canonical SE Code text",
            ));
        }
        let occurred = i64::try_from(turn.occurred_at.0).map_err(|_| {
            SeError::invalid("capture timestamp", "representable Unix microseconds")
        })?;
        for (field, value, cap) in [
            ("native event", turn.vendor_event.as_deref(), 512),
            ("source reference", turn.source_ref.as_deref(), 512),
            ("machine identity", turn.machine_id.as_deref(), 128),
        ] {
            if let Some(value) = value {
                se_core::ops::inputs::bounded(field, value, cap, false)?;
            }
        }
        if let Some(nesting) = &turn.nesting {
            if nesting.depth > 32 {
                return Err(SeError::invalid("native nesting depth", "at most 32"));
            }
            for value in [
                nesting.parent_session.as_ref().map(|v| v.0.as_str()),
                nesting.nested_agent.as_ref().map(|v| v.0.as_str()),
            ]
            .into_iter()
            .flatten()
            {
                se_core::ops::inputs::bounded("native nesting identity", value, 512, false)?;
            }
        }
        // One immutable event is a native source, not a file byte offset. A
        // per-event source keeps replay independent of later captured turns.
        let digest: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&serde_json::json!([
                session.identity.session.0,
                turn.vendor_turn
            ]))
            .map_err(|e| scope::unreadable("native source identity", &e.to_string()))?,
        )
        .into();
        let mut random = [0; 10];
        random.copy_from_slice(&digest[..10]);
        // This is a derived identity, not an observation clock. The actual
        // occurrence time remains on the events; retries keep the same source.
        let source = se_store::RecordId::from_parts(0, random).map_err(|e| store_error(&e))?;
        let incarnation = digest.to_vec();
        let metadata = serde_json::to_string(&serde_json::json!({
            "conversation":turn.conversation.0,"event":turn.vendor_event,"source_ref":turn.source_ref,
            "source_cli":turn.source_cli,"machine_id":turn.machine_id,
            "nesting":turn.nesting.map(|n| serde_json::json!({"parent_session":n.parent_session.map(|v|v.0),"nested_agent":n.nested_agent.map(|v|v.0),"depth":n.depth}))
        })).map_err(|e| scope::unreadable("native source metadata", &e.to_string()))?;
        se_core::ops::inputs::bounded("native source metadata", &metadata, 32768, false)?;
        let scope = binding::session_scope(session)?;
        let admission = scope.admission.clone();
        let revision = session.binding_revision;
        let check_scope = scope.clone();
        let CaptureBatch {
            batch,
            delivery_key,
        } = store::read(&router, scope.clone(), &deadline, move |read| {
            binding::check(read, &check_scope, revision)?;
            let text = se_types::Body::new(turn.content.text)?;
            if *text.digest().as_bytes() != turn.source_sha256.0 {
                return Err(SeError::invalid(
                    "linked capture digest",
                    "SHA-256 of the exact canonical text",
                ));
            }

            let facts = super::super::start::allocate_facts()?;
            let last = super::super::start::allocate_facts()?;
            let turn_id = se_store::RecordId::from_bytes(
                facts
                    .message
                    .canonical_bytes()?
                    .ok_or_else(|| SeError::invalid("turn allocation", "UUIDv7"))?,
            )
            .map_err(|e| store_error(&e))?;
            let bytes = text.len() as u64;
            let events = vec![
                store::event(
                    read,
                    &admission,
                    facts.event,
                    occurred,
                    EventBody::CaptureSource {
                        source,
                        session: admission.session.clone().ok_or_else(|| {
                            SeError::invalid("capture session", "a bound session")
                        })?,
                        consent: se_store::Consent::Capture,
                        native_ref: metadata,
                        incarnation: incarnation.clone(),
                        expected: Expected::Absent,
                    },
                ),
                store::event(
                    read,
                    &admission,
                    facts.profile_event,
                    occurred,
                    EventBody::SessionTurn {
                        turn: turn_id,
                        agent: se_types::AgentId::from_linked(binding.identity.agent)?,
                        session: se_types::SessionId::from_linked(binding.identity.session)?,
                        provider: se_store::Provider::SeCode,
                        vendor_ref: turn.vendor_turn,
                        role: match turn.role {
                            api::TurnRole::User => se_store::Role::User,
                            api::TurnRole::Assistant => se_store::Role::Assistant,
                            api::TurnRole::Tool => se_store::Role::Tool,
                        },
                        text: InputText::Inline(text.into()),
                        evidence: se_store::SourceEvidence {
                            path: None,
                            incarnation: incarnation.clone(),
                            offset: 0,
                            length: bytes,
                            sha256: Some(turn.source_sha256.0),
                        },
                    },
                ),
                store::event(
                    read,
                    &admission,
                    last.event,
                    occurred,
                    EventBody::CaptureProgress {
                        source,
                        expected: Expected::Revision(se_store::Revision {
                            value: std::num::NonZeroU64::MIN,
                        }),
                        incarnation,
                        old_offset: 0,
                        new_offset: bytes,
                        last_turn: turn_id,
                        replay_evidence: None,
                    },
                ),
            ];
            Ok(CaptureBatch {
                batch: se_store::AtomicBatch {
                    expected_incarnation: read.info().incarnation,
                    admission,
                    request: None,
                    events,
                    import_checkpoint: None,
                },
                delivery_key: turn.idempotency_key,
            })
        })
        .await?;
        let receipt = store::write(&router, batch, "session.capture", &deadline).await?;
        let committed = store::known("session.capture", &receipt);
        store::read(&router, scope, &deadline, move |read| {
            // The source is first in the atomic batch; select the actual turn
            // from the original committed members, including natural replay.
            let mut turn = None;
            for id in &receipt.events {
                let event = scope::require_present(
                    read.event(id.clone()).map_err(|e| store_error(&e))?,
                    "native capture receipt",
                    scope::COMMITTED_READ_RECOVERY,
                )?;
                if matches!(event.body, EventBody::SessionTurn { .. }) {
                    turn = Some(api::EventRef {
                        id: id.to_linked(),
                        position: read
                            .position_cursor(&event.position, se_store::PositionPurpose::Receipt)
                            .map_err(|e| store_error(&e))?
                            .to_linked(),
                    });
                }
            }
            store::receipt(
                read,
                receipt,
                delivery_key,
                turn.ok_or_else(|| {
                    SeError::invalid("capture receipt", "its original committed turn")
                })?,
            )
        })
        .await
        .map_err(|e| committed.response_error(e))
    }
}
