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

const BACKSLASH: u16 = b'\\' as u16;
const FORWARD_SLASH: u16 = b'/' as u16;
const COLON: u16 = b':' as u16;
const QUESTION_MARK: u16 = b'?' as u16;
const DOT: u16 = b'.' as u16;

fn windows_separator(unit: u16, verbatim: bool) -> bool {
    unit == BACKSLASH || (!verbatim && unit == FORWARD_SLASH)
}

fn windows_drive_absolute(units: &[u16], verbatim: bool) -> bool {
    matches!(units, [drive, COLON, separator, ..]
        if u8::try_from(*drive).is_ok_and(|letter| letter.is_ascii_alphabetic())
            && windows_separator(*separator, verbatim))
}

fn complete_unc(units: &[u16], verbatim: bool) -> bool {
    let mut parts = units.split(|unit| windows_separator(*unit, verbatim));
    matches!((parts.next(), parts.next()), (Some(server), Some(share)) if !server.is_empty() && !share.is_empty())
}

fn unc_tail(units: &[u16]) -> Option<&[u16]> {
    let prefix = units.get(..4)?;
    (prefix[3] == BACKSLASH
        && prefix[..3].iter().zip(b"UNC").all(|(unit, letter)| {
            u8::try_from(*unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(letter))
        }))
    .then_some(&units[4..])
}

fn windows_absolute(units: &[u16]) -> bool {
    if let Some(verbatim) = units.strip_prefix(&[BACKSLASH, BACKSLASH, QUESTION_MARK, BACKSLASH]) {
        if let Some(unc) = unc_tail(verbatim) {
            return complete_unc(unc, true);
        }
        if matches!(verbatim, [_, COLON, ..]) {
            return windows_drive_absolute(verbatim, true);
        }
        // Verbatim roots need a literal backslash; forward slash stays data.
        return verbatim
            .iter()
            .position(|unit| *unit == BACKSLASH)
            .is_some_and(|end| end > 0);
    }
    if let Some(device) = units.strip_prefix(&[BACKSLASH, BACKSLASH, DOT, BACKSLASH]) {
        return match unc_tail(device) {
            Some(unc) => complete_unc(unc, false),
            None => device
                .first()
                .is_some_and(|unit| !windows_separator(*unit, false)),
        };
    }
    if windows_drive_absolute(units, false) {
        return true;
    }
    matches!(units, [first, second, tail @ ..]
        if windows_separator(*first, false) && windows_separator(*second, false)
            && complete_unc(tail, false))
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
