use std::path::PathBuf;

/// A query selector, never custody or a legal stop target by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessId(pub u32);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachineId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostInstanceId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationId(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartIdentity {
    Linux { start_ticks: u64 },
    Windows { creation_filetime: u64 },
    MacOs { seconds: u64, microseconds: u32 },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub machine: MachineId,
    pub boot: BootIdentity,
    pub pid: ProcessId,
    pub start: StartIdentity,
    /// Exact native path, not display text, a basename, or executable-name filter.
    pub image: PathBuf,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeState {
    Running,
    Stopped,
    /// A real kernel record which cannot execute; not synonymous with absence.
    ExitedAwaitingReap,
    Exited,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveObservation {
    pub identity: ProcessIdentity,
    pub state: NativeState,
    pub parent: Option<ProcessId>,
    pub observed_at_unix_ns: u128,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExitEvidence {
    KernelHandleSignalled,
    NativeExitedRecord { state: NativeState },
    Absent,
    Replaced { observed: ProcessIdentity },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessObservation {
    Live(LiveObservation),
    /// Includes the original expected instance, even when its image is no
    /// longer readable from an exited procfs record.
    Exited {
        expected: ProcessIdentity,
        evidence: ExitEvidence,
        status: ExitStatus,
        observed_at_unix_ns: u128,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessRead {
    Present(LiveObservation),
    Absent {
        pid: ProcessId,
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
        observed_at_unix_ns: u128,
    },
}

/// Native status is independent of proof that an instance exited.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExitStatus {
    Code(u32),
    Signal { number: u32, core_dumped: bool },
    Unavailable { reason: ExitStatusUnavailable },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitStatusUnavailable {
    NotOurChild,
    ReapedBeforeRecovery,
    NativeAccessDenied,
    NotRecorded,
}
