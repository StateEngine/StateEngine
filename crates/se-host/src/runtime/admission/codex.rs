//! Codex has no CLI hook. Its real MCP discovery request proves possession of
//! both issued credentials; only the HTTP bearer ever authorizes an operation.
use super::*;
impl AdmissionContext {
    fn codex_discovery(&self, bearer: &se_types::Secret, pin: &se_types::Secret) -> Result<()> {
        let phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let result = (|| {
            self.check_generation(&phase)?;
            let http = self.credential_in(
                &phase,
                bearer,
                crate::MCP_BEARER_PURPOSE,
                Pending::ValidateOnly,
            )?;
            let session =
                self.credential_in(&phase, pin, SESSION_CAPABILITY, Pending::ValidateOnly)?;
            if http.scope != session.scope
                || http.actor != session.actor
                || http.session != session.session
                || http.generation != session.generation
            {
                return Err(SeError::invalid(
                    "Codex credential discovery",
                    "both exact purposes bound to one current project, agent, session and generation",
                ));
            }
            // Validate the pair before recording either first-use observation.
            let mut records = Vec::new();
            for (secret, purpose) in [
                (bearer, crate::MCP_BEARER_PURPOSE),
                (pin, SESSION_CAPABILITY),
            ] {
                let hash: [u8; 32] = Hasher::digest(secret.expose()).into();
                let record = se_core::scope::require_present(
                    phase.credential(hash).map_err(|e| store_error(&e))?,
                    "Codex first-use credential",
                    "Retry the exact original launch.",
                )?;
                records.push((record, hash, purpose));
            }
            if records[0].0.state != records[1].0.state {
                return Err(SeError::invalid(
                    "Codex credential discovery",
                    "both purposes in the same committed activation state",
                ));
            }
            for (record, hash, purpose) in records {
                if record.state == se_store::CredentialState::Prepared {
                    self.observe_prepared(&phase, &record, hash, purpose)?;
                }
            }
            Ok(())
        })();
        super::super::executor::close_read(result, phase.close())
    }
}
impl HostedRouter {
    pub(crate) async fn codex_discovery(
        &self,
        bearer: Arc<se_types::Secret>,
        pin: Arc<se_types::Secret>,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<()> {
        self.check_open()?;
        let context = self.context.clone();
        self.execution
            .blocking
            .run_owned(deadline, move || context.codex_discovery(&bearer, &pin))
            .await
    }
}
