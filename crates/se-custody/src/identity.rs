use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A query selector, never custody or a legal stop target by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcessId(pub u32);
pub use se_types::{HostGeneration as GenerationId, LifecycleId, MachineId};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostInstanceId(pub [u8; 16]);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum BootIdentity {
    Linux {
        boot_id: [u8; 16],
    },
    MacOs {
        seconds: i64,
        microseconds: i32,
    },
    /// FILETIME is an absolute creation clock; the held host/process handle,
    /// not a guessed boot time, supplies Windows object continuity.
    WindowsAbsoluteCreationClock,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum StartIdentity {
    Linux {
        #[serde(with = "crate::checkpoint::decimal::u64")]
        start_ticks: u64,
    },
    Windows {
        #[serde(with = "crate::checkpoint::decimal::u64")]
        creation_filetime: u64,
    },
    MacOs {
        #[serde(with = "crate::checkpoint::decimal::u64")]
        seconds: u64,
        microseconds: u32,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub machine: MachineId,
    pub boot: BootIdentity,
    pub pid: ProcessId,
    pub start: StartIdentity,
    /// Exact native path, not display text, a basename, or executable-name filter.
    #[serde(with = "crate::checkpoint::native_path")]
    pub image: PathBuf,
}
impl ProcessIdentity {
    /// The same process instance: one birth on this machine and boot. The
    /// image is a recorded fact, not identity, because an in-place update or
    /// rename of the executable changes the path a running process reports.
    pub fn same_birth(&self, other: &Self) -> bool {
        self.machine == other.machine
            && self.boot == other.boot
            && self.pid == other.pid
            && self.start == other.start
    }
    /// The canonical instance for this native birth, recorded image and
    /// argument digest. It reads nothing; image content is proved separately.
    pub fn instance(
        &self,
        boot: &se_types::BootId,
        argv_sha256: se_types::Sha256,
    ) -> se_types::Result<se_types::ProcessInstance> {
        use se_types::{NativePath, ProcessFields, ProcessInstance, SeError};
        use std::num::{NonZeroU32, NonZeroU64};
        let started = match self.start {
            StartIdentity::Linux { start_ticks } => se_types::StartIdentity::Linux { start_ticks },
            StartIdentity::Windows { creation_filetime } => se_types::StartIdentity::Windows {
                creation_filetime: NonZeroU64::new(creation_filetime)
                    .ok_or_else(|| SeError::invalid("native creation time", "nonzero"))?,
            },
            StartIdentity::MacOs {
                seconds,
                microseconds,
            } => se_types::StartIdentity::Macos {
                start_seconds: seconds,
                start_micros: microseconds,
            },
        };
        ProcessInstance::from_observation(ProcessFields {
            machine: self.machine.clone(),
            boot: boot.clone(),
            pid: NonZeroU32::new(self.pid.0)
                .ok_or_else(|| SeError::invalid("native PID", "nonzero"))?,
            started,
            executable: NativePath::from_local(self.image.clone())?,
            argv_sha256,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum NativeState {
    Running,
    Stopped,
    /// A real kernel record which cannot execute; not synonymous with absence.
    ExitedAwaitingReap,
    Exited,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveObservation {
    pub identity: ProcessIdentity,
    pub state: NativeState,
    pub parent: Option<ProcessId>,
    #[serde(with = "crate::checkpoint::decimal::u128")]
    pub observed_at_unix_ns: u128,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExitEvidence {
    KernelHandleSignalled,
    NativeExitedRecord {
        state: NativeState,
    },
    Absent,
    Replaced {
        observed: ProcessIdentity,
    },
    BootChanged {
        previous: se_types::BootId,
        observed: se_types::BootId,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ProcessObservation {
    Live(LiveObservation),
    /// Includes the original expected instance, even when its image is no
    /// longer readable from an exited procfs record.
    Exited {
        expected: ProcessIdentity,
        evidence: ExitEvidence,
        status: ExitStatus,
        #[serde(with = "crate::checkpoint::decimal::u128")]
        observed_at_unix_ns: u128,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ProcessRead {
    Present(LiveObservation),
    Absent {
        pid: ProcessId,
        #[serde(with = "crate::checkpoint::decimal::u128")]
        observed_at_unix_ns: u128,
    },
    /// A cold PID query found a zombie without a readable executable. A stop
    /// with custody can join this native start to its original expected image.
    ExitedRecord {
        pid: ProcessId,
        boot: BootIdentity,
        start: StartIdentity,
        state: NativeState,
        status: ExitStatus,
        #[serde(with = "crate::checkpoint::decimal::u128")]
        observed_at_unix_ns: u128,
    },
}

/// Native status is independent of proof that an instance exited.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExitStatus {
    Code(u32),
    Signal { number: u32, core_dumped: bool },
    Unavailable { reason: ExitStatusUnavailable },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExitStatusUnavailable {
    NotOurChild,
    ReapedBeforeRecovery,
    NativeAccessDenied,
    NotRecorded,
}
