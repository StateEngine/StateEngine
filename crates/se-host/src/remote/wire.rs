//! Closed JSON envelopes with phase-specific byte and nesting bounds (45 §5/7).
use super::*;
use se_types::{ErrorBody, Result, SeError};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{io::Write, num::NonZeroU64};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub NonZeroU64);

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ClientFrame {
    Request {
        id: RequestId,
        invocation: Box<RemoteInvocation>,
    },
    Cancel {
        id: RequestId,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "result",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Reply {
    List(Box<RemoteListResult>),
    Watch(Box<RemoteWatchBatch>),
    Send(Box<RemoteSendResult>),
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ServerFrame {
    Open {
        channel: [u8; 32],
    },
    Ready(RemoteReady),
    Response {
        id: RequestId,
        result: Reply,
    },
    WatchEvent {
        id: RequestId,
        batch: Box<RemoteWatchBatch>,
    },
    Gap {
        id: RequestId,
        target: RemoteTarget,
        reason: String,
        reset_required: bool,
    },
    Error {
        id: Option<RequestId>,
        error: ErrorBody,
    },
}

/// One budget spans HTTP Upgrade and native authorization framing in both directions.
/// The socket wrapper accounts actual wire bytes; this also bounds JSON in memory.
#[derive(Clone, Copy, Debug)]
pub enum Phase {
    PreAuth,
    Authenticated,
}
impl Phase {
    pub fn limit(self) -> usize {
        match self {
            Self::PreAuth => REMOTE_PREAUTH_BYTES,
            Self::Authenticated => REMOTE_FRAME_BYTES,
        }
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(std::io::Error::other("remote frame byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub fn encode<T: Serialize>(value: &T, phase: Phase) -> Result<String> {
    let mut writer = BoundedWriter {
        bytes: Vec::with_capacity(1024),
        limit: phase.limit(),
        exceeded: false,
    };
    if serde_json::to_writer(&mut writer, value).is_err() {
        return Err(if writer.exceeded {
            SeError::too_large("remote encoded message", phase.limit(), phase.limit() + 1)
        } else {
            SeError::invalid("remote message", "a serializable closed protocol value")
        });
    }
    // serde_json produces UTF-8, but retain an honest refusal rather than unchecked conversion.
    String::from_utf8(writer.bytes).map_err(|_| SeError::invalid("remote message", "UTF-8 JSON"))
}
pub fn decode<T: DeserializeOwned>(bytes: &[u8], phase: Phase) -> Result<T> {
    if bytes.len() > phase.limit() {
        return Err(SeError::too_large(
            "remote encoded message",
            phase.limit(),
            bytes.len(),
        ));
    }
    check_depth(bytes)?;
    serde_json::from_slice(bytes).map_err(|_| {
        SeError::invalid(
            "remote message",
            "the closed stateengine.client/v1 JSON schema; check both client and host versions",
        )
    })
}
fn check_depth(bytes: &[u8]) -> Result<()> {
    let (mut depth, mut quoted, mut escape) = (0u32, false, false);
    for byte in bytes {
        if quoted {
            if escape {
                escape = false;
            } else if *byte == b'\\' {
                escape = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > 64 {
                        return Err(SeError::invalid(
                            "remote JSON depth",
                            "at most64 nested objects/arrays",
                        ));
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => (),
            }
        }
    }
    Ok(())
}
