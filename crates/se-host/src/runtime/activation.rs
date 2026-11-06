//! Verified transport possession hands off first-use facts to the coordinator.
//! This port neither activates a credential nor admits a prepared operation.
use super::{HostedRuntime, admission::AdmissionContext};
use crate::{PreparedRequestProofs, VerifiedPreparedRequest};
use se_store::{CredentialRecord, ReadPhase, RecordId, RecordIdentity};
use se_types::{Result, SeError};

impl HostedRuntime {
    /// The same slot is cloned into CLI/MCP/linked execution. Install its native
    /// controller before readiness; an absent port refuses rather than opening
    /// another cache from an individual query route.
    pub fn install_atlas_read_port(
        &mut self,
        reader: std::sync::Arc<dyn crate::atlas_runtime::read_port::AtlasReadPort>,
    ) -> Result<()> {
        if self.phase != crate::HostPhase::Prepared {
            return Err(SeError::invalid(
                "Atlas read port",
                "installation before host readiness",
            ));
        }
        self.execution.atlas.install(reader)
    }
    /// Install the coordinator's exact registry before either listener serves.
    pub fn install_prepared_request_proofs(&mut self, proofs: PreparedRequestProofs) -> Result<()> {
        if self.phase != crate::HostPhase::Prepared {
            return Err(SeError::invalid(
                "launch proof handoff",
                "installation before readiness",
            ));
        }
        self.prepared_requests.set(proofs).map_err(|_| {
            SeError::invalid("launch proof handoff", "one registry per host generation")
        })
    }
}

impl AdmissionContext {
    /// Called only after the shared verifier checked purpose, expiry, current
    /// preparation and generation. Discovery may list tools under a fence, but
    /// its possession cannot activate an agent whose earlier stop is unproved.
    pub(super) fn observe_prepared(
        &self,
        phase: &ReadPhase,
        credential: &CredentialRecord,
        hash: [u8; 32],
        purpose: &'static str,
    ) -> Result<()> {
        let Some(proofs) = self.prepared_requests.get() else {
            return Ok(());
        };
        if phase
            .credential_stop_unproved(hash)
            .map_err(|e| se_core::store_error::store_error(&e))?
        {
            return Ok(());
        }
        let mut entropy = [0; 10];
        se_proc::fill_entropy(&mut entropy)
            .map_err(|e| se_core::scope::unreadable("verified request identity", &e.to_string()))?;
        let now = u64::try_from(super::start::now_unix_micros()?).map_err(|_| {
            SeError::invalid("verified request clock", "nonnegative Unix microseconds")
        })?;
        proofs.observe_verified(VerifiedPreparedRequest {
            session: credential.session.clone(),
            purpose,
            secret_sha256: hash,
            generation: self.generation.get(),
            request: RecordId::from_parts(now / 1000, entropy)
                .map_err(|e| se_core::store_error::store_error(&e))?,
        })
    }
}
