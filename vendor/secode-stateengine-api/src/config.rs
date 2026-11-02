// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{Generation, NativePath};
use std::future::Future;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiVersion {
    pub major: u16,
    pub minor: u16,
}
pub const API_VERSION: ApiVersion = ApiVersion { major: 2, minor: 0 };

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreVersion {
    pub application_id: u32,
    pub schema: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKind {
    EmbeddedSecode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Feature {
    NativeMail,
    LocalListener,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Negotiated {
    pub api: ApiVersion,
    pub store: StoreVersion,
    pub generation: Generation,
    pub features: Vec<Feature>,
    pub limits: Limits,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Limits {
    pub page_items: NonZeroU32,
    pub payload_bytes: NonZeroU32,
    pub notice_ids: NonZeroU32,
}
#[derive(Clone, Debug)]
pub struct HostConfig {
    pub state_home: NativePath,
    /// Installed native se image, supplied by the trusted composition root.
    pub helper_executable: NativePath,
    pub linux_delegation: LinuxDelegation,
    pub api: ApiVersion,
    pub kind: HostKind,
    pub features: Vec<Feature>,
    pub limits: Limits,
}
/// Agent-scope policy; never a way to move the embedding host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinuxDelegation {
    /// Lazy per-agent manager scope when shipped; wave 1 uses uncontained groups.
    AutoUserManager,
    /// Current delegated scope only; never search an arbitrary ancestor.
    CurrentScope,
    /// Trusted composition-root selection, not model input.
    ExplicitRoot(NativePath),
}
pub trait Cancellation: Send + Sync + std::fmt::Debug {
    fn is_cancelled(&self) -> bool;
    fn cancelled(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}
#[derive(Clone, Debug)]
pub struct OpenOptions {
    pub expected_generation: Option<Generation>,
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}
#[derive(Clone, Debug)]
pub struct CallOptions {
    pub generation: Generation,
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}
#[derive(Clone, Debug)]
pub struct ServiceOptions {
    pub generation: Generation,
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}
