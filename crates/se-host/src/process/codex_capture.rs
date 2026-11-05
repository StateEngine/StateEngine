//! Queue acknowledgement follows outside-the-writer readback of the exact
//! canonical message. A failed or not-yet-persisted completion remains queued.
use super::{owned::Work, *};
use crate::client::lease::Deadline;
use se_store::{EventBody, Snapshot, StoredText};
use se_types::{Read, Result};
impl LaunchCoordinator {
    pub(super) async fn acknowledge_codex_capture(
        &self,
        work: &Work,
        deadline: &Deadline,
    ) -> Result<()> {
        let Some(binding) = work
            .binding
            .as_ref()
            .and_then(|binding| binding.codex.as_ref())
            .cloned()
        else {
            // Cold native exit has no live connection. Its protected pin and
            // complete native rollout are the recovery reader instead.
            return Ok(());
        };
        let conversation = binding.conversation()?;
        if !matches!(&work.meta.conversation, Read::Present { value } if value == &conversation) {
            return Err(error(
                "Codex capture acknowledgement",
                "the owned conversation differs",
            ));
        }
        let pending = binding.retained_notifications()?;
        let mut committed = Vec::new();
        let admission = se_store::Admission {
            scope: se_store::Scope::Project(work.meta.project.id.clone()),
            actor: se_store::Actor::Agent(work.meta.agent.id.clone()),
            session: Some(work.meta.session.clone()),
            generation: self.store.generation.get(),
        };
        for notification in &pending {
            let tool =
                crate::harness::tool_capture::codex::notification(notification, &conversation)?;
            let record = if tool.is_some() {
                None
            } else {
                crate::codex_capture::notification(notification, &conversation)?
            };
            if tool.is_none() && record.is_none() {
                committed.push(notification.clone());
                continue;
            }
            let session = work.meta.session.clone();
            let agent = work.meta.agent.id.clone();
            let vendor = tool
                .as_ref()
                .map(|fact| fact.vendor(&session))
                .or_else(|| record.as_ref().map(|record| record.vendor.clone()))
                .ok_or_else(|| {
                    error(
                        "Codex capture acknowledgement",
                        "the completed native identity",
                    )
                })?;
            let matched = self.store.read(admission.clone(), deadline, move |cx| {
                match cx.read.native_turn(session.clone(), se_store::Provider::Codex, &vendor).map_err(|cause| se_core::store_error::store_error(&cause))? {
                    Read::Absent { .. } => Ok(false),
                    Read::Present { value } if tool.is_some()=>crate::harness::tool_capture::committed(
                        tool.as_ref().ok_or_else(||error("Codex tool acknowledgement","the actual native item"))?,value,&agent),
                    Read::Present { value } => match value.body {
                        EventBody::SessionTurn {provider: se_store::Provider::Codex, vendor_ref, role, text: StoredText::Present(text), ..}
                            if record.as_ref().is_some_and(|record|vendor_ref == record.vendor && role == record.role && text == record.text.as_str()) => Ok(true),
                        _ => Err(error("Codex capture acknowledgement", "the immutable item differs or was erased; preserve its original identity")),
                    },
                    Read::Unreadable { reason, .. } => Err(error("Codex committed item", reason)),
                    Read::Unknown { what } => Err(error("Codex committed item", what)),
                }
            }).await?;
            if !matched {
                break;
            }
            committed.push(notification.clone());
        }
        binding.acknowledge_notifications(&committed)?;
        if committed.len() < pending.len() && work.process_retired {
            return Err(error(
                "Codex final capture",
                "a completed provider item is missing from the pinned rollout; retain the queue and committed cursor",
            ));
        }
        Ok(())
    }
}
