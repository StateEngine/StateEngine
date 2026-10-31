use crate::{BootId, HostGeneration, MachineId, Result, SeError, Sha256};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    num::{NonZeroU32, NonZeroU64},
    path::PathBuf,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "encoding", content = "units", rename_all = "snake_case")]
pub enum PathEncoding {
    UnixBytes(Vec<u8>),
    WindowsUtf16(Vec<u16>),
}

fn windows_drive_absolute(units: &[u16]) -> bool {
    matches!(units, [drive, 58, 47 | 92, ..] if *drive <= 127 && (*drive as u8).is_ascii_alphabetic())
}

fn complete_unc(units: &[u16]) -> bool {
    let mut parts = units.split(|unit| matches!(unit, 47 | 92));
    matches!((parts.next(), parts.next()), (Some(server), Some(share)) if !server.is_empty() && !share.is_empty())
}

fn windows_absolute(units: &[u16]) -> bool {
    if windows_drive_absolute(units) {
        return true;
    }
    let Some(tail) = units.strip_prefix(&[92, 92]) else {
        return false;
    };
    if let Some(verbatim) = tail.strip_prefix(&[63, 92]) {
        if matches!(verbatim, [85 | 117, 78 | 110, 67 | 99, 92, ..]) {
            return complete_unc(&verbatim[4..]);
        }
        if matches!(verbatim, [_, 58, ..]) {
            return windows_drive_absolute(verbatim);
        }
        // Other verbatim roots (for example Volume{GUID}) need their root slash.
        return verbatim
            .iter()
            .position(|unit| *unit == 92)
            .is_some_and(|end| end > 0);
    }
    if let Some(device) = tail.strip_prefix(&[46, 92]) {
        return !device.is_empty();
    }
    complete_unc(tail)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "PathEncoding", into = "PathEncoding")]
pub struct NativePath(PathEncoding);
impl NativePath {
    pub fn from_encoded(path: PathEncoding) -> Result<Self> {
        let valid = match &path {
            PathEncoding::UnixBytes(bytes) => {
                !bytes.is_empty() && bytes.len() <= 32768 && bytes[0] == b'/' && !bytes.contains(&0)
            }
            PathEncoding::WindowsUtf16(units) => {
                units.len() <= 32768 && !units.contains(&0) && windows_absolute(units)
            }
        };
        if !valid {
            return Err(SeError::invalid(
                "path",
                "a bounded absolute native path without NUL",
            ));
        }
        Ok(Self(path))
    }
    pub fn encoded(&self) -> &PathEncoding {
        &self.0
    }
    pub fn from_local(path: PathBuf) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Self::from_encoded(PathEncoding::UnixBytes(
                path.as_os_str().as_bytes().to_vec(),
            ))
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            Self::from_encoded(PathEncoding::WindowsUtf16(
                path.as_os_str().encode_wide().collect(),
            ))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err(SeError::invalid("platform", "Windows, Linux or macOS"))
        }
    }
    pub fn to_local(&self) -> Result<PathBuf> {
        match &self.0 {
            #[cfg(unix)]
            PathEncoding::UnixBytes(bytes) => {
                use std::os::unix::ffi::OsStringExt;
                Ok(std::ffi::OsString::from_vec(bytes.clone()).into())
            }
            #[cfg(windows)]
            PathEncoding::WindowsUtf16(units) => {
                use std::os::windows::ffi::OsStringExt;
                Ok(std::ffi::OsString::from_wide(units).into())
            }
            _ => Err(SeError::invalid(
                "path encoding",
                "the current platform's native encoding",
            )),
        }
    }
}
impl TryFrom<PathEncoding> for NativePath {
    type Error = SeError;
    fn try_from(path: PathEncoding) -> Result<Self> {
        Self::from_encoded(path)
    }
}
impl From<NativePath> for PathEncoding {
    fn from(path: NativePath) -> Self {
        path.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "os", rename_all = "snake_case")]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessFields {
    pub machine: MachineId,
    pub boot: BootId,
    pub pid: NonZeroU32,
    pub started: StartIdentity,
    pub executable: NativePath,
    pub argv_sha256: Sha256,
}
/// Representation of an observation, not the se-proc owned/pinned custody handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "ProcessFields", into = "ProcessFields")]
pub struct ProcessInstance(ProcessFields);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMatch {
    Same,
    Different,
}
impl ProcessInstance {
    pub fn from_observation(fields: ProcessFields) -> Result<Self> {
        let valid = match (&fields.started, fields.executable.encoded()) {
            (StartIdentity::Windows { .. }, PathEncoding::WindowsUtf16(_)) => true,
            (StartIdentity::Linux { .. }, PathEncoding::UnixBytes(_)) => true,
            (StartIdentity::Macos { start_micros, .. }, PathEncoding::UnixBytes(_)) => {
                *start_micros < 1000000
            }
            _ => false,
        };
        if !valid {
            return Err(SeError::invalid(
                "process identity",
                "matching OS/path and valid native start identity",
            ));
        }
        Ok(Self(fields))
    }
    pub fn fields(&self) -> &ProcessFields {
        &self.0
    }
    pub fn compare(&self, other: &Self) -> IdentityMatch {
        if self == other {
            IdentityMatch::Same
        } else {
            IdentityMatch::Different
        }
    }
}
impl TryFrom<ProcessFields> for ProcessInstance {
    type Error = SeError;
    fn try_from(value: ProcessFields) -> Result<Self> {
        Self::from_observation(value)
    }
}
impl From<ProcessInstance> for ProcessFields {
    fn from(value: ProcessInstance) -> Self {
        value.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HostEpoch {
    pub owner: ProcessInstance,
    pub generation: HostGeneration,
}
