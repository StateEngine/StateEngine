use crate::{BootId, HostGeneration, MachineId, Result, Sha256};
use std::{
    num::{NonZeroU32, NonZeroU64},
    path::PathBuf,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePath(PathEncoding);
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathEncoding {
    UnixBytes(Vec<u8>),
    WindowsUtf16(Vec<u16>),
}
pub trait NativePathValue: Sized {
    fn from_local(path: PathBuf) -> Result<Self>;
    fn from_encoded(path: PathEncoding) -> Result<Self>;
    fn encoded(&self) -> &PathEncoding;
    fn to_local(&self) -> Result<PathBuf>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartIdentity {
    Windows {
        creation_filetime: NonZeroU64,
    },
    Linux {
        start_ticks: u64,
    },
    Macos {
        start_seconds: u64,
        start_micros: u32,
    },
}
/// This is an observation, never a handle granting permission to signal a PID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessFields {
    pub machine: MachineId,
    pub boot: BootId,
    pub pid: NonZeroU32,
    pub started: StartIdentity,
    pub executable: NativePath,
    pub argv_sha256: Sha256,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessInstance(ProcessFields);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityMatch {
    Same,
    Different,
}
pub trait ProcessIdentity: Sized {
    fn from_observation(fields: ProcessFields) -> Result<Self>;
    fn fields(&self) -> &ProcessFields;
    fn compare(&self, other: &Self) -> IdentityMatch;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEpoch {
    pub owner: ProcessInstance,
    pub generation: HostGeneration,
}
