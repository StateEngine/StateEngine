#[cfg(not(all(feature = "listener", any(target_os = "linux", windows))))]
pub struct LaunchCoordinator {
    pub(crate) _private: (),
}
#[cfg(all(feature = "listener", any(target_os = "linux", windows)))]
pub use crate::process::LaunchCoordinator;

#[cfg(all(feature = "listener", target_os = "linux", target_env = "gnu"))]
mod memory;
#[cfg(feature = "listener")]
pub(crate) mod pool;
#[cfg(feature = "listener")]
pub use pool::*;
#[cfg(feature = "listener")]
mod call;
#[cfg(feature = "listener")]
pub use call::*;
#[cfg(feature = "listener")]
pub(crate) mod start;
#[cfg(feature = "listener")]
pub use start::*;

#[cfg(feature = "listener")]
mod endpoint;
#[cfg(all(feature = "listener", unix))]
pub use endpoint::runtime_endpoint_address;
#[cfg(feature = "listener")]
pub use endpoint::{HostedListener, RetainedEndpoint, endpoint_recovery_error};
#[cfg(feature = "listener")]
mod recovery;
#[cfg(feature = "listener")]
pub use recovery::{EndpointRoute, retain_at as retain_endpoint_at, route_endpoint};
#[cfg(feature = "listener")]
mod activation;
#[cfg(feature = "listener")]
mod admission;
#[cfg(feature = "listener")]
mod admission_reads;

#[cfg(feature = "listener")]
mod drain;
#[cfg(feature = "listener")]
pub use drain::StorageDrainReport;
#[cfg(feature = "listener")]
mod route;
#[cfg(feature = "listener")]
pub use route::{
    AcceptedPeer, AdmittedExchange, AuthorizedStop, HostedConnection, HostedRouter, RoutedCall,
};

mod inventory;
pub use inventory::decode_owner_inventory;

#[cfg(feature = "listener")]
pub(crate) mod executor;
#[cfg(feature = "listener")]
mod history_import;
#[cfg(feature = "listener")]
pub(crate) mod mail;
#[cfg(feature = "listener")]
pub use mail::MailRecipient;
#[cfg(feature = "runtime")]
mod submit;
#[cfg(feature = "listener")]
mod timings;
#[cfg(feature = "listener")]
pub use executor::execute;

#[cfg(feature = "secode")]
mod embedded;
#[cfg(feature = "secode")]
pub use embedded::{EmbeddedFactory, embedded_factory};
#[cfg(feature = "listener")]
mod serve;
#[cfg(feature = "listener")]
pub use serve::{HostServeExit, LocalStop};

#[cfg(feature = "listener")]
mod capture;
#[cfg(feature = "listener")]
pub use capture::{CaptureHandle, CaptureRestoreReport, CaptureUnavailable, TranscriptBindings};

#[cfg(feature = "listener")]
mod failure;
#[cfg(feature = "listener")]
mod live;
#[cfg(feature = "listener")]
pub(crate) mod tasks;
#[cfg(feature = "listener")]
pub(crate) use failure::{PendingWrites, WriteIdentity};
#[cfg(feature = "listener")]
mod shutdown;
#[cfg(feature = "listener")]
pub use shutdown::HostShutdown;

#[cfg(test)]
mod failure_tests;

#[cfg(test)]
mod pool_tests;

#[cfg(all(test, feature = "listener"))]
#[path = "../tests/support/wave2_host_fixture.rs"]
pub(crate) mod test_support;
#[cfg(all(feature = "listener", target_os = "linux"))]
mod atlas_owner;
#[cfg(all(feature = "listener", target_os = "linux"))]
pub use atlas_owner::NativeAtlasQualification;
