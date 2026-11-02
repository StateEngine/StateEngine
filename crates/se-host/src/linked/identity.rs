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
