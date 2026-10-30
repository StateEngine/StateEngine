use crate::{BoundSession, CallContext, ClaudeHookInput, HostFuture, HostStatus, VerifiedCaller};
use se_types::{ApiVersion, Generation, HostEpoch, IdempotencyKey, NativePath, Secret};
use std::{fs::File, num::NonZeroU32};

#[derive(Clone, Debug)]
pub enum IpcEndpoint {
    UnixSocket(NativePath),
    WindowsPipe(String),
}
#[derive(Clone, Debug)]
pub struct EndpointRecord {
    pub schema: u16,
    pub address: IpcEndpoint,
    pub epoch: HostEpoch,
    pub api: ApiVersion,
    pub package_version: String,
    pub image_sha256: se_types::Sha256,
}
pub struct PeerProof {
    pub(crate) _private: (),
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
    fn peer(&self, channel: &File) -> se_types::Result<PeerProof>;
    fn verify_server(
        &self,
        channel: &File,
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
    pub key: Option<IdempotencyKey>,
}
/// Only the core registry decoder can construct this admitted operation.
pub struct AdmittedOperation {
    pub(crate) _private: (),
}
pub struct OperationOutput {
    pub schema: String,
    pub value: serde_json::Value,
    pub window: Option<se_types::Window>,
}
pub enum IpcRequest {
    Operation(RawOperation),
    Hook(ClaudeHookInput),
    Nudge { through: se_types::Sequence },
}
pub struct IpcEnvelope {
    pub version: ApiVersion,
    pub request_id: u64,
    pub generation: Generation,
    pub authority: Option<PresentedAuthority>,
    pub request: IpcRequest,
}
pub trait LocalAdmission: Send + Sync {
    fn connect<'a>(
        &'a self,
        peer: PeerProof,
        hello: ClientHello,
        cx: CallContext,
    ) -> HostFuture<'a, (AuthorizedConnection, ServerHello)>;
    fn caller<'a>(
        &'a self,
        connection: &'a AuthorizedConnection,
        authority: Option<PresentedAuthority>,
        cx: CallContext,
    ) -> HostFuture<'a, VerifiedCaller>;
    fn session<'a>(
        &'a self,
        caller: &'a VerifiedCaller,
        cx: CallContext,
    ) -> HostFuture<'a, BoundSession>;
}
pub trait OperationDispatcher: Send + Sync {
    fn decode(
        &self,
        caller: &VerifiedCaller,
        operation: RawOperation,
    ) -> se_types::Result<AdmittedOperation>;
    fn dispatch<'a>(
        &'a self,
        operation: AdmittedOperation,
        cx: CallContext,
    ) -> HostFuture<'a, OperationOutput>;
}
#[derive(Clone, Debug)]
pub struct HttpRequestHead {
    pub method: String,
    pub target: String,
    pub host: String,
    pub origin: Option<String>,
    pub content_type: Option<String>,
    pub accept: Option<String>,
    pub declared_bytes: Option<u64>,
}
pub struct HttpChannel {
    pub(crate) _private: (),
}
pub trait LocalListener: Send + Sync {
    fn admit_head(&self, head: HttpRequestHead) -> se_types::Result<HttpChannel>;
    fn authenticate<'a>(
        &'a self,
        channel: &'a HttpChannel,
        authority: PresentedAuthority,
        cx: CallContext,
    ) -> HostFuture<'a, VerifiedCaller>;
    fn status(&self) -> HostStatus;
    fn stop<'a>(&'a self, cx: CallContext) -> HostFuture<'a, ()>;
}
