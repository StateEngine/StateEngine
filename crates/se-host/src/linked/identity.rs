use se_types as core;
use secode_stateengine_api as api;

/// Decode an API value through the canonical validated type, including its
/// documented legacy grammar. This conversion never grants authority.
pub trait FromLinked<T>: Sized {
    fn from_linked(value: T) -> core::Result<Self>;
}
pub trait ToLinked {
    type Linked;
    fn to_linked(&self) -> Self::Linked;
}
macro_rules! ids {
    ($($name:ident),+ $(,)?) => {$(
        impl FromLinked<api::$name> for core::$name {
            fn from_linked(value: api::$name) -> core::Result<Self> {
                Self::try_from(value.0)
            }
        }
        impl ToLinked for core::$name {
            type Linked = api::$name;
            fn to_linked(&self) -> Self::Linked {
                api::$name(self.as_str().to_owned())
            }
        }
    )+};
}
ids!(
    ProjectId,
    AgentId,
    SessionId,
    MessageId,
    EventId,
    StoreId,
    HostSessionId,
    HostEventId,
    HostPendingId,
    ProviderSessionId,
    IdempotencyKey,
    NoticeId,
    Cursor
);

impl FromLinked<api::ProcessInstance> for core::ProcessInstance {
    fn from_linked(value: api::ProcessInstance) -> core::Result<Self> {
        use std::num::{NonZeroU32, NonZeroU64};
        let invalid = || {
            core::SeError::invalid(
                "native process identity",
                "a nonzero PID and valid OS birth identity",
            )
        };
        let started = match value.started {
            api::StartIdentity::Windows { creation_filetime } => core::StartIdentity::Windows {
                creation_filetime: NonZeroU64::new(creation_filetime).ok_or_else(invalid)?,
            },
            api::StartIdentity::Linux { start_ticks } => core::StartIdentity::Linux { start_ticks },
            api::StartIdentity::Macos {
                start_seconds,
                start_micros,
            } => core::StartIdentity::Macos {
                start_seconds,
                start_micros,
            },
        };
        Self::from_observation(core::ProcessFields {
            machine: core::MachineId::new(value.machine)?,
            boot: core::BootId::new(value.boot)?,
            pid: NonZeroU32::new(value.pid).ok_or_else(invalid)?,
            started,
            executable: core::NativePath::from_local(value.executable)?,
            argv_sha256: core::Sha256::from_bytes(value.argv_sha256.0),
        })
    }
}
impl FromLinked<api::HostEpoch> for core::HostEpoch {
    fn from_linked(value: api::HostEpoch) -> core::Result<Self> {
        Ok(Self {
            owner: core::ProcessInstance::from_linked(value.owner)?,
            generation: core::HostGeneration::new(value.generation.0)?,
        })
    }
}

pub fn host_epoch(value: &core::HostEpoch) -> core::Result<api::HostEpoch> {
    let fields = value.owner.fields();
    let started = match fields.started {
        core::StartIdentity::Windows { creation_filetime } => api::StartIdentity::Windows {
            creation_filetime: creation_filetime.get(),
        },
        core::StartIdentity::Linux { start_ticks } => api::StartIdentity::Linux { start_ticks },
        core::StartIdentity::Macos {
            start_seconds,
            start_micros,
        } => api::StartIdentity::Macos {
            start_seconds,
            start_micros,
        },
    };
    Ok(api::HostEpoch {
        owner: api::ProcessInstance {
            machine: fields.machine.as_str().to_owned(),
            boot: fields.boot.as_str().to_owned(),
            pid: fields.pid.get(),
            started,
            executable: fields.executable.to_local()?,
            argv_sha256: api::Sha256(*fields.argv_sha256.as_bytes()),
        },
        generation: api::HostGeneration(value.generation.get()),
    })
}
