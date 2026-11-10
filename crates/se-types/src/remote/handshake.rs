use super::{RemoteHostId, RemoteScope};
use crate::{ApiVersion, Generation, RemoteDeviceId, RemoteGrantId, UnixMicros};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct RemoteInstanceId(pub [u8; 16]);

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteHello {
    pub protocol: ApiVersion,
    pub host: RemoteHostId,
    pub grant: RemoteGrantId,
    pub device: RemoteDeviceId,
    pub authority_revision: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteReady {
    pub protocol: ApiVersion,
    pub host: RemoteHostId,
    pub instance: RemoteInstanceId,
    pub generation: Generation,
    pub grant: RemoteGrantId,
    pub authority_revision: u64,
    pub scope: RemoteScope,
    pub expires_at: UnixMicros,
}
