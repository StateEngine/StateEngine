//! Shared store value contracts; database custody and execution remain in the store.
pub mod channel;
#[doc(hidden)]
pub mod error;
mod event;
mod identity;
pub mod imports;
pub mod mail;
mod model;
mod query;
pub mod remote;
mod timings;
pub use error::{StoreDetail, StoreError, StoreErrorCode, StoreIoStage, StoreResult};
pub use event::*;
pub use model::*;
pub use query::*;
pub use timings::*;

/// Value types re-exported by the store without exposing implementation modules.
pub mod values {
    pub use crate::{
        StoreDetail, StoreError, StoreErrorCode, StoreIoStage, StoreResult, event::*, model::*,
        query::*, timings::*,
    };
}
