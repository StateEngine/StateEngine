//! Version-1 native-custody codec (§20). Data can be decoded, never converted
//! into an owned native handle. Store and host bind these facts to their indices.
use crate::*;
use se_types::{AgentId, EventId, HumanId, Read, SessionId};
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf};
pub(crate) mod decimal;
pub(crate) mod native_path;
mod validation;
pub(crate) mod optional_native_path {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &Option<PathBuf>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .as_ref()
            .map(|p| native_path::encoded(p))
            .transpose()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<PathBuf>, D::Error> {
        Option::<se_types::PathEncoding>::deserialize(deserializer)?
            .map(native_path::local)
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}
const LIMIT: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootPublication {
    NoChildCreated,
    Unpublished,
    Identified,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CheckpointPrincipal {
    Human(HumanId),
    Agent(AgentId),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub format_version: u16,
    pub lifecycle: LifecycleId,
    pub principal: CheckpointPrincipal,
    pub session: Option<SessionId>,
    pub root_identity: RootPublication,
    pub checkpoint: CheckpointKind,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum CheckpointKind {
    Reservation(LaunchReservation),
    Scope(ScopeCheckpoint),
    Root(RootCheckpoint),
    Process(ProcessRecord),
    Exit {
        source: Box<CheckpointSource>,
        witness: StopWitness,
    },
    FailedReservation {
        reservation: LaunchReservation,
        error: ProcError,
        observation: EventId,
        no_scope_created: bool,
    },
    Historical(HistoricalCheckpoint),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CheckpointSource {
    Reservation(LaunchReservation),
    Scope(ScopeCheckpoint),
    Root(RootCheckpoint),
    Process(ProcessRecord),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalCheckpoint {
    pub root: Read<ProcessIdentity>,
    pub scope: Read<ScopeIdentity>,
    pub reason: String,
}
#[derive(Debug)]
pub struct CheckpointError {
    pub reason: String,
}
impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}
impl std::error::Error for CheckpointError {}
fn invalid(reason: impl ToString) -> CheckpointError {
    CheckpointError {
        reason: reason.to_string(),
    }
}
impl Checkpoint {
    /// Published records can be passed directly to observe_owner_self. Explicit
    /// terminal/historical outcomes produce None; unresolved pre-root custody
    /// refuses instead of being laundered into an empty owner inventory.
    pub fn owner_guard_record(&self) -> Result<Option<&ProcessRecord>, CheckpointError> {
        validation::checkpoint(self)?;
        match &self.checkpoint {
            CheckpointKind::Process(record) => Ok(Some(record)),
            CheckpointKind::Exit { .. }
            | CheckpointKind::FailedReservation { .. }
            | CheckpointKind::Historical(_) => Ok(None),
            _ => Err(invalid(
                "unresolved reservation/scope/root requires native reconciliation before owner admission",
            )),
        }
    }
}
pub fn decode_checkpoint(format_version: u16, bytes: &[u8]) -> Result<Checkpoint, CheckpointError> {
    if format_version != 1 || bytes.is_empty() || bytes.len() > LIMIT {
        return Err(invalid(
            "unsupported native custody version or bounded record size",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = Checkpoint::deserialize(&mut deserializer).map_err(invalid)?;
    deserializer.end().map_err(invalid)?;
    // Internally tagged shared DTOs may otherwise ignore fields while buffering
    // their contents. Compare object keys with the typed serialization as well;
    // ordinary optional omissions and object order remain legal.
    let input: serde_json::Value = serde_json::from_slice(bytes).map_err(invalid)?;
    let typed: serde_json::Value =
        serde_json::from_slice(&serde_json::to_vec(&value).map_err(invalid)?).map_err(invalid)?;
    known_fields(&input, &typed)?;
    validation::checkpoint(&value)?;
    Ok(value)
}
pub fn encode_checkpoint(value: &Checkpoint) -> Result<Vec<u8>, CheckpointError> {
    validation::checkpoint(value)?;
    struct Buffer(Vec<u8>);
    impl io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > LIMIT.saturating_sub(self.0.len()) {
                return Err(io::Error::other("native custody exceeds 1 MiB"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut buffer = Buffer(Vec::new());
    serde_json::to_writer(&mut buffer, value).map_err(invalid)?;
    Ok(buffer.0)
}

fn known_fields(
    input: &serde_json::Value,
    typed: &serde_json::Value,
) -> Result<(), CheckpointError> {
    match (input, typed) {
        (serde_json::Value::Object(input), serde_json::Value::Object(typed)) => {
            for (key, value) in input {
                if let Some(known) = typed.get(key) {
                    known_fields(value, known)?;
                } else if !(key == "error"
                    && value.is_null()
                    && typed.get("state").and_then(|v| v.as_str()) == Some("unreadable"))
                {
                    return Err(invalid("unknown field in native custody checkpoint"));
                }
            }
        }
        (serde_json::Value::Array(input), serde_json::Value::Array(typed)) => {
            if input.len() != typed.len() {
                return Err(invalid("native custody array shape changed"));
            }
            for (input, typed) in input.iter().zip(typed) {
                known_fields(input, typed)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(any(target_os = "linux", windows))]
pub(crate) fn validate_recovery(source: &RecoverySource) -> Result<(), CheckpointError> {
    match source {
        RecoverySource::Reservation(value) => validation::reservation(value, &value.lifecycle),
        RecoverySource::Prepared(value) => {
            validation::prepared(value, &value.reservation.lifecycle)
        }
        RecoverySource::RootPrepared(value) => {
            validation::root(value, &value.scope.reservation.lifecycle)
        }
        RecoverySource::Record(value) => validation::process(value, &value.lifecycle),
    }
}
