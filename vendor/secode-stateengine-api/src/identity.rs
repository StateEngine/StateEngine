// SPDX-License-Identifier: MIT OR Apache-2.0
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostSessionId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEventId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostPendingId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSessionId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyKey(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoticeId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cursor(pub String);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Generation(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostGeneration(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Per-entity counter; creation is one, every committed change adds one.
pub struct Revision(pub std::num::NonZeroU64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixMicros(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha256(pub [u8; 32]);
pub type NativePath = PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartIdentity {
    Windows {
        creation_filetime: u64,
    },
    Linux {
        start_ticks: u64,
    },
    Macos {
        start_seconds: u64,
        start_micros: u32,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessInstance {
    pub machine: String,
    pub boot: String,
    pub pid: u32,
    pub started: StartIdentity,
    pub executable: PathBuf,
    pub argv_sha256: Sha256,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEpoch {
    pub owner: ProcessInstance,
    pub generation: HostGeneration,
}
