//! Atlas context for an adopted provider's tool call. Admission has already
//! proved the registered provider and its conversation; this reads the index
//! for that registered project only and observes or commits nothing.
use super::*;
use se_core::ops::{AtlasAugment, atlas_hook::HOOK_HOST_BUDGET};
use std::sync::Arc;

impl HostedRouter {
    pub(super) async fn adopted_context(
        &self,
        input: crate::adoption::Input,
        deadline: &Deadline,
    ) -> Result<crate::OperationOutput> {
        let target = input
            .context
            .ok_or_else(|| crate::adoption::invalid("a context call names what to look up"))?;
        let augment = AtlasAugment {
            target,
            root: None,
            deadline: Some(std::time::Instant::now() + HOOK_HOST_BUDGET),
        };
        let owner = Admission {
            actor: Actor::Human(self.context.owner.clone()),
            scope: se_store::Scope::Project(input.project.clone()),
            session: None,
            generation: self.execution.generation.get(),
        };
        // Capture the record fence before the snapshot, as planned Atlas reads do.
        let ticket = self.execution.atlas.records.ticket().ok().flatten();
        let atlas = Arc::clone(&self.execution.atlas);
        let output = self
            .adoption_read(owner, deadline, move |_, cx| {
                crate::atlas_hooks::owner_augment(&atlas, ticket, &augment, cx.read, cx.admission)
            })
            .await?;
        Ok(crate::OperationOutput {
            schema: "se.adoption/1".into(),
            value: json!({"state":"observed","context":output.stdout}),
            window: None,
        })
    }
}
