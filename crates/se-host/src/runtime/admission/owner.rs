use super::AdmissionContext;
use super::start::owner_budget;
use crate::{PeerProof, decode_owner_inventory};
use se_core::store_error::store_error;
use se_store::RuntimeLease;
use se_types::{Read, Result, SeError};
use std::io::Read as ByteRead;
use zeroize::Zeroizing;
impl AdmissionContext {
    pub(crate) fn machine_key(&self) -> Result<se_types::Secret> {
        let path = self.state_directory.join("credential");
        let lease = self.lease()?;
        let mut file = match lease.files().readback(&path).map_err(|e| store_error(&e))? {
            Read::Present { value } => value,
            _ => {
                return Err(SeError::invalid(
                    "machine credential",
                    "a present protected 32-byte credential from explicit init",
                ));
            }
        };
        let mut bytes = Zeroizing::new(Vec::with_capacity(33));
        (&mut file)
            .take(33)
            .read_to_end(&mut bytes)
            .map_err(|e| se_core::scope::unreadable("machine credential", &e.to_string()))?;
        if bytes.len() != 32 {
            return Err(SeError::invalid(
                "machine credential",
                "exactly 32 protected bytes",
            ));
        }
        se_types::Secret::new(std::mem::take(&mut *bytes))
    }
    pub(in crate::runtime) fn owner_peer(
        &self,
        phase: &mut se_store::ReadPhase,
        peer: &PeerProof,
    ) -> Result<()> {
        // This finite auth phase deliberately retains its SQL pin through the
        // protected readback and bounded native ancestry observation below.
        // machine_key likewise reads a protected file before the phase closes;
        // none of these synchronous reads submits a write or awaits the network.
        let lease = self.lease()?;
        let inventory = phase
            .owner_guard(lease.files(), owner_budget()?)
            .map_err(|e| store_error(&e))?;
        if inventory.owners.as_slice() != [self.owner.clone()] {
            return Err(SeError::invalid(
                "host owner",
                "the same current protected store owner",
            ));
        }
        let records = decode_owner_inventory(&inventory)?;
        let native = peer.native();
        let start = match native.started() {
            se_types::StartIdentity::Linux { start_ticks } => se_proc::StartIdentity::Linux {
                start_ticks: *start_ticks,
            },
            se_types::StartIdentity::Macos {
                start_seconds,
                start_micros,
            } => se_proc::StartIdentity::MacOs {
                seconds: *start_seconds,
                microseconds: *start_micros,
            },
            se_types::StartIdentity::Windows { creation_filetime } => {
                se_proc::StartIdentity::Windows {
                    creation_filetime: creation_filetime.get(),
                }
            }
        };
        let observed = se_proc::observe_owner(
            se_proc::OwnerTarget::Process {
                pid: se_proc::ProcessId(native.pid()),
                start: &start,
            },
            &records,
        )
        .map_err(|e| se_core::scope::unreadable("native IPC peer ancestry", &e.to_string()))?;
        let owner = match observed.owner() {
            se_proc::NativeOwner::Unix {
                real_uid,
                effective_uid,
            } if real_uid == effective_uid => effective_uid.to_string(),
            se_proc::NativeOwner::Windows { sid } => sid.clone(),
            _ => {
                return Err(SeError::invalid(
                    "native peer owner",
                    "matching real and effective OS users",
                ));
            }
        };
        let expected = match native.principal() {
            se_proc::native_ipc::IpcPrincipal::Unix { uid } => uid.to_string(),
            se_proc::native_ipc::IpcPrincipal::Windows { sid } => sid.clone(),
        };
        if owner != expected {
            return Err(SeError::new(se_types::Detail::OsUserMismatch(
                se_types::details::OsUserMismatch {
                    expected,
                    actual: owner,
                },
            )));
        }
        if !observed.agent_trees().is_empty() {
            return Err(SeError::new(se_types::Detail::OwnerRequired(
                se_types::details::OwnerRequired {
                    op: "IPC owner".into(),
                },
            )));
        }
        // Only peer OS identity and native ancestry were observed here. Local
        // CLI provenance checks ambient markers; host flags are never peer facts.
        Ok(())
    }
}
