//! Renewal requires the original secret and native custody of its active session.
use super::*;
use crate::{decode_owner_inventory, runtime::start::owner_budget};
use se_store::RuntimeLease;

impl AdmissionContext {
    pub(crate) fn renewal_identity(
        &self,
        peer: &PeerProof,
        secret: &se_types::Secret,
    ) -> Result<se_store::CredentialRecord> {
        let mut phase = self
            .reads
            .read_phase()
            .map_err(|error| store_error(&error))?;
        let result = (|| {
            self.check_generation(&phase)?;
            let local = se_proc::native_ipc::observe_ipc_self().map_err(|error| {
                se_core::scope::unreadable("native host identity", &error.to_string())
            })?;
            if peer.native().principal() != local.principal()
                || peer.native().image_sha256() != self.image_sha256
            {
                return Err(SeError::invalid(
                    "session renewal",
                    "the installed executable under the host account",
                ));
            }
            let hash: [u8; 32] = Hasher::digest(secret.expose()).into();
            let credential = se_core::scope::require_present(
                phase
                    .credential(hash)
                    .map_err(|error| store_error(&error))?,
                "session renewal",
                "Launch through se launch with the original session.",
            )?;
            if credential.purpose != SESSION_CAPABILITY
                || credential.state != se_store::CredentialState::Active
                || credential.credential
                    != se_core::ops::process_commit::session_credential_id(
                        &credential.session,
                        SESSION_CAPABILITY,
                    )?
                || phase
                    .credential_stop_unproved(hash)
                    .map_err(|error| store_error(&error))?
                || phase
                    .credential_superseded(hash)
                    .map_err(|error| store_error(&error))?
                || !credential.session_active
            {
                return Err(SeError::invalid(
                    "session renewal",
                    "the original unfenced active session credential",
                ));
            }
            let lease = self.lease()?;
            let inventory = phase
                .owner_guard(lease.files(), owner_budget()?)
                .map_err(|error| store_error(&error))?;
            let records = decode_owner_inventory(&inventory)?;
            let start = crate::host_process::proc_start(peer.native().started());
            let observation = se_proc::observe_owner(
                se_proc::OwnerTarget::Process {
                    pid: se_proc::ProcessId(peer.native().pid()),
                    start: &start,
                },
                &records,
            )
            .map_err(|error| {
                se_core::scope::unreadable("session process custody", &error.to_string())
            })?;
            let valid = observation.agent_trees().iter().any(|matched| {
                if !matches!(
                    matched.basis,
                    se_proc::AgentTreeBasis::ExactRoot
                        | se_proc::AgentTreeBasis::Ancestor
                        | se_proc::AgentTreeBasis::WindowsJob
                ) {
                    return false;
                }
                records.get(matched.record_index).is_some_and(|record| {
                    inventory.processes.iter().any(|saved| {
                        saved.project == credential.project
                            && saved.identity.record == record.lifecycle
                            && saved.identity.principal == Actor::Agent(credential.agent.clone())
                            && saved.identity.session.as_ref() == Some(&credential.session)
                            && matches!(
                                saved.state,
                                se_store::ProcessState::Running
                                    | se_store::ProcessState::LeaderExited
                            )
                    })
                })
            });
            if !valid {
                return Err(SeError::invalid(
                    "session renewal",
                    "the live native process tree of the same launched session; use se launch to start it",
                ));
            }
            Ok(credential)
        })();
        crate::runtime::executor::close_read(result, phase.close())
    }
}
