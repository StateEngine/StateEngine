//! Protected machine sessions over the existing host writer.
#[cfg(feature = "remote")]
mod permissions;
#[cfg(feature = "remote")]
mod store;
#[cfg(feature = "remote")]
pub use permissions::SetSourcePermission;
#[cfg(feature = "remote")]
pub(crate) use se_remote::entropy;
#[cfg(feature = "remote")]
pub use store::SecurityStore;
#[cfg(feature = "remote")]
pub(crate) use store::{event_id, now};
#[cfg(feature = "remote")]
pub(crate) mod control;
#[cfg(feature = "remote")]
pub use control::*;
