//! Durable custody for the private service and its finite initializer. The
//! journal is product recovery state, independent of client launch cleanup.
use super::*;
use se_proc::{Checkpoint, CheckpointKind, CheckpointPrincipal, RootPublication};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};
use std::{io::Write, result::Result as StdResult};

/// Whether initial input intent has been durably recorded before native launch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(from = "bool", into = "bool")]
pub enum InitialInputIntent {
    #[default]
    Unrecorded,
    Recorded,
}
impl From<bool> for InitialInputIntent {
    fn from(v: bool) -> Self {
        if v { Self::Recorded } else { Self::Unrecorded }
    }
}
impl From<InitialInputIntent> for bool {
    fn from(v: InitialInputIntent) -> Self {
        v == InitialInputIntent::Recorded
    }
}

/// Whether the qualified SE Code server supports input-free resume.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(from = "bool", into = "bool")]
pub enum ResumeSupport {
    #[default]
    Unavailable,
    Supported,
}
impl From<bool> for ResumeSupport {
    fn from(v: bool) -> Self {
        if v {
            Self::Supported
        } else {
            Self::Unavailable
        }
    }
}
impl From<ResumeSupport> for bool {
    fn from(v: ResumeSupport) -> Self {
        v == ResumeSupport::Supported
    }
}
/// Durable custody for a service superseded by a credential restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestartJournal {
    pub key: String,
    pub effect: Option<se_store::RecordId>,
    pub reply_sent: bool,
    pub settled: bool,
}
// `deny_unknown_fields` lives here so `#[serde(flatten)]` on `Journal::restart`
// rejects any unknown field in the entire v1 flat JSON object.
mod restart_wire {
    use super::*;
    type Restart = Option<RestartJournal>;
    #[derive(Default, Serialize, Deserialize)]
    #[serde(default, deny_unknown_fields)]
    struct Wire {
        restart_key: Option<String>,
        restart_effect: Option<se_store::RecordId>,
        restart_settled: bool,
        restart_reply_sent: bool,
        superseded_by_restart: bool,
    }
    pub fn serialize<S: Serializer>(v: &Restart, s: S) -> StdResult<S::Ok, S::Error> {
        v.as_ref()
            .map_or_else(Wire::default, |r| Wire {
                restart_key: Some(r.key.clone()),
                restart_effect: r.effect,
                restart_settled: r.settled,
                restart_reply_sent: r.reply_sent,
                superseded_by_restart: true,
            })
            .serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> StdResult<Restart, D::Error> {
        let w = Wire::deserialize(d)?;
        let empty = w.restart_effect.is_none() && !w.restart_settled && !w.restart_reply_sent;
        match (w.restart_key, w.superseded_by_restart) {
            (None, false) if empty => Ok(None),
            (Some(key), true) => Ok(Some(RestartJournal {
                key,
                effect: w.restart_effect,
                reply_sent: w.restart_reply_sent,
                settled: w.restart_settled,
            })),
            _ => Err(D::Error::custom(
                "inconsistent SE Code restart custody fields",
            )),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Journal {
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
    pub initial_offered: InitialInputIntent,
    pub session_create_attempted: bool,
    pub policy_sha256: Option<se_types::Sha256>,
    #[serde(default)]
    pub previous_policy_sha256: Option<se_types::Sha256>,
    #[serde(default)]
    pub client_closed: Option<ClientClosed>,
    #[serde(default)]
    pub resume_release: Option<ResumeRelease>,
    #[serde(default)]
    pub input_free_resume: ResumeSupport,
    pub notice: Option<Notice>,
    #[serde(flatten, with = "restart_wire")]
    pub restart: Option<RestartJournal>,
    pub bootstrap: Option<Checkpoint>,
    pub service: Option<Checkpoint>,
    #[serde(default)]
    pub retirement: Option<Checkpoint>,
    #[serde(default)]
    pub registration: Option<Vec<u8>>,
    #[serde(default)]
    pub server_sha256: Option<se_types::Sha256>,
    pub endpoint: Option<String>,
    pub identity: Option<se_harness::secode_process::ServiceIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_repair: Option<se_harness::secode_process::CapabilityRepair>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientClosed {
    pub witness: se_proc::StopWitness,
    pub capture_complete: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeRelease {
    pub session: se_types::SessionId,
    pub binding: se_harness::secode_process::NoticeBinding,
    pub completed: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notice {
    #[serde(default)]
    pub effect: Option<se_store::RecordId>,
    pub input: String,
    pub binding: se_harness::secode_process::NoticeBinding,
    pub messages: Vec<String>,
}
impl Journal {
    pub(crate) fn unprovisioned(&self) -> bool {
        self.identity.is_none() && self.initial_offered == InitialInputIntent::Unrecorded
    }

    pub(crate) fn require_registration(&self, current: &[u8]) -> Result<()> {
        let matches = if let Some(repair) = self
            .capability_repair
            .as_ref()
            .filter(|repair| repair.owned_binding().is_some())
        {
            se_harness::secode_process::CapabilityRepair::fingerprint(
                current,
                &repair.before.service,
            ) == repair.registration
        } else {
            self.registration.as_deref() == Some(current)
        };
        if !matches {
            return Err(error(
                "SE Code registration custody",
                "current registration differs from retained qualified custody",
            ));
        }
        Ok(())
    }
    pub(crate) fn auxiliary(&self, auxiliary: Auxiliary) -> &Option<Checkpoint> {
        match auxiliary {
            Auxiliary::Bootstrap => &self.bootstrap,
            Auxiliary::Service => &self.service,
            Auxiliary::Retirement => &self.retirement,
        }
    }
    pub(crate) fn auxiliary_mut(&mut self, auxiliary: Auxiliary) -> &mut Option<Checkpoint> {
        match auxiliary {
            Auxiliary::Bootstrap => &mut self.bootstrap,
            Auxiliary::Service => &mut self.service,
            Auxiliary::Retirement => &mut self.retirement,
        }
    }
    pub(crate) fn checkpoint_lifecycle(
        &self,
        auxiliary: Auxiliary,
    ) -> Result<se_types::LifecycleId> {
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
            se_harness::secode_process::service_key(project, agent)
        ))
    }
    pub fn profile(
        home: &std::path::Path,
        project: &se_types::ProjectId,
        agent: &se_types::AgentId,
    ) -> PathBuf {
        se_harness::secode_process::private_profile(home, project, agent)
    }
    pub fn read<H: crate::HostPort>(
        path: &std::path::Path,
        deadline: &Deadline,
    ) -> Result<Option<Self>> {
        Ok(Self::read_with_digest::<H>(path, deadline)?.map(|(value, _)| value))
    }
    pub fn read_with_digest<H: crate::HostPort>(
        path: &std::path::Path,
        deadline: &Deadline,
    ) -> Result<Option<(Self, [u8; 32])>> {
        let Some(mut file) = H::open_owned_file(path, "SE Code custody", deadline)? else {
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
    pub fn save<H: crate::HostPort>(
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
        if let Some(mut observed) = H::open_owned_file(path, "SE Code custody", deadline)?
            && observed
                .sha256()
                .map_err(|e| error("SE Code custody reconciliation", e))?
                == wanted
        {
            return Ok(wanted);
        }
        if let Some(hash) = expected {
            let previous = H::open_owned_file(path, "SE Code custody", deadline)?
                .ok_or_else(|| error("SE Code custody update", "original journal absent"))?;
            previous
                .replace(hash, &bytes)
                .map_err(|e| error("SE Code custody update", e))?;
        } else {
            let mut staging = files
                .create_staging(directory)
                .map_err(|e| error("SE Code custody staging", e))?;
            // Publication flushes the staged data before moving its name.
            staging
                .file
                .write_all(&bytes)
                .map_err(|e| error("SE Code custody write", e))?;
            drop(staging.file);
            files
                .publish_no_replace(&staging.path, path)
                .map_err(|e| error("SE Code custody publication", e))?;
        }
        let observed = Self::read::<H>(path, deadline)?
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

pub(crate) fn source(checkpoint: &Checkpoint) -> Result<se_proc::RecoverySource> {
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
