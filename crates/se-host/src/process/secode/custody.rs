//! Durable custody for the private service and its finite initializer. The
//! journal is product recovery state, independent of client launch cleanup.
use super::*;
use se_proc::{Checkpoint, CheckpointKind, CheckpointPrincipal, RootPublication};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) struct Journal {
    pub version: u16,
    #[serde(default)]
    pub retired: bool,
    #[serde(default)]
    pub lost: bool,
    #[serde(default)]
    pub stop_failure: Option<String>,
    pub project: se_types::ProjectId,
    pub agent: se_types::AgentId,
    pub profile: NativePath,
    pub session: se_types::SessionId,
    pub vendor_session: String,
    pub initial_input: String,
    pub initial_sha256: se_types::Sha256,
    pub initial_offered: bool,
    pub session_create_attempted: bool,
    pub policy_sha256: Option<se_types::Sha256>,
    #[serde(default)]
    pub previous_policy_sha256: Option<se_types::Sha256>,
    #[serde(default)]
    pub client_closed: Option<ClientClosed>,
    #[serde(default)]
    pub resume_release: Option<ResumeRelease>,
    #[serde(default)]
    pub input_free_resume: bool,
    pub notice: Option<Notice>,
    pub bootstrap: Option<Checkpoint>,
    pub service: Option<Checkpoint>,
    #[serde(default)]
    pub retirement: Option<Checkpoint>,
    #[serde(default)]
    pub registration: Option<Vec<u8>>,
    #[serde(default)]
    pub server_sha256: Option<se_types::Sha256>,
    pub endpoint: Option<String>,
    pub identity: Option<crate::harness::secode_process::ServiceIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_repair: Option<crate::harness::secode_process::CapabilityRepair>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClientClosed {
    pub witness: se_proc::StopWitness,
    pub capture_complete: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResumeRelease {
    pub session: se_types::SessionId,
    pub binding: crate::harness::secode_process::NoticeBinding,
    pub completed: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Notice {
    pub input: String,
    pub binding: crate::harness::secode_process::NoticeBinding,
    pub messages: Vec<String>,
}
impl Journal {
    pub fn auxiliary(&self, auxiliary: Auxiliary) -> &Option<Checkpoint> {
        match auxiliary {
            Auxiliary::Bootstrap => &self.bootstrap,
            Auxiliary::Service => &self.service,
            Auxiliary::Retirement => &self.retirement,
        }
    }
    pub fn auxiliary_mut(&mut self, auxiliary: Auxiliary) -> &mut Option<Checkpoint> {
        match auxiliary {
            Auxiliary::Bootstrap => &mut self.bootstrap,
            Auxiliary::Service => &mut self.service,
            Auxiliary::Retirement => &mut self.retirement,
        }
    }
    pub fn checkpoint_lifecycle(&self, auxiliary: Auxiliary) -> Result<se_types::LifecycleId> {
        let checkpoint = self.auxiliary(auxiliary);
        checkpoint
            .as_ref()
            .map(|c| c.lifecycle.clone())
            .ok_or_else(|| error("SE Code auxiliary lifecycle", "original checkpoint absent"))
    }
    pub fn path(
        home: &std::path::Path,
        project: &se_types::ProjectId,
        agent: &se_types::AgentId,
    ) -> PathBuf {
        home.join("secode").join(format!(
            "{}.json",
            crate::harness::secode_process::service_key(project, agent)
        ))
    }
    pub fn profile(
        home: &std::path::Path,
        project: &se_types::ProjectId,
        agent: &se_types::AgentId,
    ) -> PathBuf {
        crate::harness::secode_process::private_profile(home, project, agent)
    }
    pub fn read(path: &std::path::Path, deadline: &Deadline) -> Result<Option<Self>> {
        Ok(Self::read_with_digest(path, deadline)?.map(|(value, _)| value))
    }
    pub fn read_with_digest(
        path: &std::path::Path,
        deadline: &Deadline,
    ) -> Result<Option<(Self, [u8; 32])>> {
        let Some(mut file) = open_journal(path, deadline)? else {
            return Ok(None);
        };
        let bytes = file
            .read(1024 * 1024)
            .map_err(|e| error("SE Code custody", e))?;
        let value: Self =
            serde_json::from_slice(&bytes).map_err(|e| error("SE Code custody", e))?;
        if value.version != 1 {
            return Err(error("SE Code custody", "unsupported version"));
        }
        if let Some(repair) = &value.capability_repair {
            repair.validate(&value.vendor_session)?;
        }
        for checkpoint in Auxiliary::ALL
            .into_iter()
            .filter_map(|key| value.auxiliary(key).as_ref())
        {
            se_proc::encode_checkpoint(checkpoint)
                .map_err(|e| error("SE Code custody checkpoint", e))?;
            if !matches!(&checkpoint.principal, CheckpointPrincipal::Agent(agent) if agent == &value.agent)
            {
                return Err(error("SE Code custody", "checkpoint principal differs"));
            }
        }
        Ok(Some((value, Sha256::digest(&bytes).into())))
    }
    pub fn save(
        &self,
        path: &std::path::Path,
        expected: Option<[u8; 32]>,
        deadline: &Deadline,
    ) -> Result<[u8; 32]> {
        let directory = path
            .parent()
            .ok_or_else(|| error("SE Code custody", "missing parent"))?;
        let files = se_proc::NativeStateFiles::create(directory)
            .map_err(|e| error("SE Code custody directory", e))?;
        let bytes = serde_json::to_vec(self).map_err(|e| error("SE Code custody encoding", e))?;
        if bytes.len() > 1024 * 1024 {
            return Err(error("SE Code custody", "journal exceeds one MiB"));
        }
        let wanted: [u8; 32] = Sha256::digest(&bytes).into();
        if let Some(mut observed) = open_journal(path, deadline)?
            && observed
                .sha256()
                .map_err(|e| error("SE Code custody reconciliation", e))?
                == wanted
        {
            return Ok(wanted);
        }
        if let Some(hash) = expected {
            let previous = open_journal(path, deadline)?
                .ok_or_else(|| error("SE Code custody update", "original journal absent"))?;
            previous
                .replace(hash, &bytes)
                .map_err(|e| error("SE Code custody update", e))?;
        } else {
            let mut staging = files
                .create_staging(directory)
                .map_err(|e| error("SE Code custody staging", e))?;
            staging
                .file
                .write_all(&bytes)
                .and_then(|()| staging.file.sync_all())
                .map_err(|e| error("SE Code custody sync", e))?;
            drop(staging.file);
            files
                .publish_no_replace(&staging.path, path)
                .map_err(|e| error("SE Code custody publication", e))?;
        }
        let observed = Self::read(path, deadline)?
            .ok_or_else(|| error("SE Code custody readback", "journal absent"))?;
        if serde_json::to_vec(&observed).map_err(|e| error("SE Code custody readback", e))? != bytes
        {
            return Err(error("SE Code custody readback", "journal differs"));
        }
        Ok(wanted)
    }
    pub fn checkpoint(&self, kind: CheckpointKind) -> Result<Checkpoint> {
        let (lifecycle, publication) = match &kind {
            CheckpointKind::Reservation(v) => {
                (v.lifecycle.clone(), RootPublication::NoChildCreated)
            }
            CheckpointKind::Scope(v) => (
                v.reservation.lifecycle.clone(),
                RootPublication::Unpublished,
            ),
            CheckpointKind::Root(v) => (
                v.scope.reservation.lifecycle.clone(),
                RootPublication::Identified,
            ),
            CheckpointKind::Process(v) => (v.lifecycle.clone(), RootPublication::Identified),
            CheckpointKind::Exit { witness, .. } => (
                witness.lifecycle.clone(),
                match witness.root {
                    se_proc::RootWitness::NoChildCreated => RootPublication::NoChildCreated,
                    se_proc::RootWitness::UnpublishedScope
                    | se_proc::RootWitness::PinnedUnpublished { .. } => {
                        RootPublication::Unpublished
                    }
                    se_proc::RootWitness::Identified { .. } => RootPublication::Identified,
                },
            ),
            CheckpointKind::Released { .. }
            | CheckpointKind::FailedReservation { .. }
            | CheckpointKind::Historical(_) => {
                return Err(error(
                    "SE Code checkpoint",
                    "a native reservation, scope, root, process or exit is required",
                ));
            }
        };
        Ok(Checkpoint {
            format_version: 1,
            lifecycle,
            principal: CheckpointPrincipal::Agent(self.agent.clone()),
            session: Some(self.session.clone()),
            root_identity: publication,
            checkpoint: kind,
        })
    }
}

pub(super) fn source(checkpoint: &Checkpoint) -> Result<se_proc::RecoverySource> {
    Ok(match &checkpoint.checkpoint {
        CheckpointKind::Reservation(v) => se_proc::RecoverySource::Reservation(Box::new(v.clone())),
        CheckpointKind::Scope(v) => se_proc::RecoverySource::Prepared(Box::new(v.clone())),
        CheckpointKind::Root(v) => se_proc::RecoverySource::RootPrepared(Box::new(v.clone())),
        CheckpointKind::Process(v) => se_proc::RecoverySource::Record(Box::new(v.clone())),
        _ => {
            return Err(error(
                "SE Code native recovery",
                "terminal or unsupported checkpoint",
            ));
        }
    })
}

// OwnedFile locks the parent as well as the leaf. Independent service journals
// share that parent, so a sibling publication can briefly contend. Reopen after
// dropping every failed pin; retry only measured native contention, within the
// original request's cancellation and deadline bounds.
fn open_journal(path: &std::path::Path, deadline: &Deadline) -> Result<Option<se_proc::OwnedFile>> {
    use crate::state_files::{Acquisition, AcquisitionRetry};
    let mut retry = AcquisitionRetry::new(deadline.at());
    deadline.remaining()?;
    loop {
        match retry
            .acquire(|| se_proc::OwnedFile::open(path))
            .map_err(|failure| failure.into_public(|native| error("SE Code custody", native)))?
        {
            Acquisition::Ready(file) => {
                deadline.remaining()?;
                return Ok(file);
            }
            Acquisition::Wait(delay) => {
                deadline.remaining()?;
                std::thread::sleep(delay);
            }
        }
    }
}
