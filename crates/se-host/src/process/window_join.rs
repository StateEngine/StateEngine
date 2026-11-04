//! Bind the real app-server thread, then durably authorize the original native
//! root to exec its remote TUI. The same native scope owns every process.
use super::launch_util::call;
use super::*;
use crate::{BindingWitness, HarnessRequest, ProviderTransport, client::lease::Deadline};
use se_proc::CheckpointKind;
use se_store::ProcessState;

impl LaunchCoordinator {
    pub(super) async fn join_codex_window(
        &self,
        work: &mut owned::Work,
        request: &HarnessRequest,
        transport: ProviderTransport,
        deadline: &Deadline,
    ) -> Result<BindingWitness> {
        let outcome = self
            .codex
            .attach_transport(
                request,
                transport,
                work.meta.lifecycle.clone(),
                call(self.store.generation, deadline)?,
            )
            .await?;
        // Retain the connection before any further fallible step, so ordinary
        // launch rollback can close it even when the second C2 cannot commit.
        work.binding = Some(outcome.binding);
        let arguments = self
            .codex
            .console_arguments(request, &outcome.witness.conversation)?;
        let native = self.native.clone();
        let process = work
            .process
            .clone()
            .ok_or_else(|| error("Codex window", "native scope is absent"))?;
        let (root, digest) = self
            .store
            .pool
            .run_owned(deadline, move || {
                native
                    .prepare_window_exec(&process, arguments)
                    .map_err(|e| error("console argument staging", e))
            })
            .await?;
        let stored = native_record::identity_meta(
            &work.meta,
            CheckpointKind::Root(root.clone()),
            Some((&root.pre_exec, digest)),
            Some(root.scope.guarantee),
            &self.options.epoch.owner.fields().boot,
        )?;
        self.change(
            work,
            "console-prepared",
            stored,
            (ProcessState::Starting, ProcessState::Starting),
            deadline,
        )
        .await?;
        let native = self.native.clone();
        let process = work
            .process
            .clone()
            .ok_or_else(|| error("Codex window", "native scope is absent"))?;
        self.store
            .pool
            .run_owned(deadline, move || {
                native
                    .authorize_window_exec(&process)
                    .map_err(|e| error("console exec authorization", e))
            })
            .await?;
        Ok(outcome.witness)
    }
}
