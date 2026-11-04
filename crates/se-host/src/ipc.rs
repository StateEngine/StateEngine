use crate::ClaudeHookInput;
use se_types::{ApiVersion, Generation, HostEpoch, IdempotencyKey, NativePath, Secret};
use std::num::NonZeroU32;
#[cfg(unix)]
pub type BorrowedChannel<'a> = std::os::fd::BorrowedFd<'a>;
#[cfg(windows)]
pub type BorrowedChannel<'a> = std::os::windows::io::BorrowedHandle<'a>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpcEndpoint {
    UnixSocket(NativePath),
    WindowsPipe(String),
}
#[derive(Clone, Debug)]
pub struct EndpointRecord {
    pub schema: u16,
    pub address: IpcEndpoint,
    pub epoch: HostEpoch,
    pub generation: Generation,
    pub kind: crate::HostKind,
    pub listener_port: Option<u16>,
    pub api: ApiVersion,
    pub package_version: String,
    pub image_sha256: se_types::Sha256,
}
pub struct PeerProof {
    pub(crate) native: se_proc::native_ipc::NativeIpcPeer,
}
impl PeerProof {
    pub fn native(&self) -> &se_proc::native_ipc::NativeIpcPeer {
        &self.native
    }
}
pub struct NativeIpcPlatform;
impl NativeIpcPlatform {
    pub fn peer_bounded(
        &self,
        channel: BorrowedChannel<'_>,
        bound: &se_proc::native_ipc::IpcIoBound,
    ) -> se_types::Result<PeerProof> {
        se_proc::native_ipc::observe_ipc_peer_bounded(
            channel,
            se_proc::native_ipc::IpcPeerSide::Client,
            bound,
        )
        .map(|native| PeerProof { native })
        .map_err(crate::client::lease::native_error)
    }
    pub fn verify_server_bounded(
        &self,
        channel: BorrowedChannel<'_>,
        endpoint: &EndpointRecord,
        bound: &se_proc::native_ipc::IpcIoBound,
    ) -> se_types::Result<PeerProof> {
        let native = se_proc::native_ipc::observe_ipc_peer_bounded(
            channel,
            se_proc::native_ipc::IpcPeerSide::Server,
            bound,
        )
        .map_err(crate::client::lease::native_error)?;
        native
            .verify_instance(&endpoint.epoch.owner, endpoint.image_sha256)
            .map_err(crate::client::lease::native_error)?;
        Ok(PeerProof { native })
    }
}
impl IpcPlatform for NativeIpcPlatform {
    fn peer(&self, channel: BorrowedChannel<'_>) -> se_types::Result<PeerProof> {
        se_proc::native_ipc::observe_ipc_peer(channel, se_proc::native_ipc::IpcPeerSide::Client)
            .map(|native| PeerProof { native })
            .map_err(crate::client::lease::native_error)
    }
    fn verify_server(
        &self,
        channel: BorrowedChannel<'_>,
        endpoint: &EndpointRecord,
    ) -> se_types::Result<PeerProof> {
        let native = se_proc::native_ipc::observe_ipc_peer(
            channel,
            se_proc::native_ipc::IpcPeerSide::Server,
        )
        .map_err(crate::client::lease::native_error)?;
        native
            .verify_instance(&endpoint.epoch.owner, endpoint.image_sha256)
            .map_err(crate::client::lease::native_error)?;
        Ok(PeerProof { native })
    }
}
#[derive(Clone, Debug)]
pub struct ServerChallenge {
    pub version: ApiVersion,
    pub epoch: HostEpoch,
    pub nonce: [u8; 32],
    pub image_sha256: se_types::Sha256,
}
/// Safe port to native credential acquisition. No caller-supplied uid/PID/SID
/// is proof; the implementation obtains it from this already-open channel.
pub trait IpcPlatform: Send + Sync {
    fn peer(&self, channel: BorrowedChannel<'_>) -> se_types::Result<PeerProof>;
    fn verify_server(
        &self,
        channel: BorrowedChannel<'_>,
        endpoint: &EndpointRecord,
    ) -> se_types::Result<PeerProof>;
}
pub struct ClientHello {
    pub version: ApiVersion,
    pub expected_generation: Option<Generation>,
    pub maximum_reply_bytes: NonZeroU32,
    pub authority: PresentedAuthority,
}
pub enum PresentedAuthority {
    OwnerProof { nonce: [u8; 32], mac: Secret },
    Session(Secret),
    Launch(Secret),
}
#[derive(Clone, Debug)]
pub struct ServerHello {
    pub version: ApiVersion,
    pub epoch: HostEpoch,
    pub generation: Generation,
    pub maximum_reply_bytes: NonZeroU32,
}
pub struct AuthorizedConnection {
    pub(crate) _private: (),
}
pub struct RawOperation {
    pub name: String,
    pub arguments: serde_json::Value,
    /// Raw ingress only: the registry decoder requires this for every public
    /// mutation before admission; None is legal only for reads or the closed
    /// natural-key capture/marker exception, never an admitted keyless write.
    pub key: Option<IdempotencyKey>,
}
pub struct OperationOutput {
    pub schema: String,
    pub value: serde_json::Value,
    pub window: Option<se_types::Window>,
}
pub enum IpcRequest {
    Operation(RawOperation),
    Hook(ClaudeHookInput),
}
pub struct IpcEnvelope {
    pub version: ApiVersion,
    pub request_id: u64,
    pub generation: Generation,
    pub authority: Option<PresentedAuthority>,
    /// Native CLI console observation. Owner MAC plus a matching native peer
    /// check are required before it can establish human presence.
    pub presence: Option<crate::client::presence::OwnerPresence>,
    /// Raw CLI route metadata, decoded by the core's sole CliSelections DTO
    /// inside the admitted snapshot. Never merged into MCP operation inputs;
    /// hooks carry None and a supplied filter never widens authority.
    pub cli_selections: Option<serde_json::Value>,
    pub request: IpcRequest,
}
pub struct IpcResponse {
    pub version: ApiVersion,
    pub request_id: u64,
    pub generation: Generation,
    pub result: IpcResult,
}
pub enum IpcResult {
    Output(Box<OperationOutput>),
    Error(se_types::ErrorEnvelope),
}

#[cfg(feature = "listener")]
#[path = "ipc/listener.rs"]
mod listener;
#[cfg(feature = "listener")]
pub use listener::*;
