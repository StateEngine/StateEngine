//! App-server JSON lines, without a JSON-RPC version header. Framing retains
//! partial lines across transport reads and never silently discards a suffix.
use crate::client::wire::{MAX_FRAME_BYTES, decode_json, encode_json};
use se_types::{Result, SeError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

/// A smaller, explicit bound than the provider's 4-MiB ceiling. The host's
/// shared strict decoder also rejects duplicate keys and depth above 64.
pub const MAX_LINE_BYTES: usize = MAX_FRAME_BYTES;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    Number(i64),
    Text(String),
}

pub struct RpcFailure {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

pub enum Message {
    Response {
        id: RequestId,
        result: std::result::Result<Value, RpcFailure>,
    },
    Request {
        id: RequestId,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
        params: Value,
    },
}

fn invalid(expected: &str) -> SeError {
    SeError::invalid("Codex app-server protocol", expected)
}

fn request_id(value: Value) -> Result<RequestId> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .map(RequestId::Number)
            .ok_or_else(|| invalid("a signed 64-bit or bounded string request ID")),
        Value::String(text) if !text.is_empty() && text.len() <= 256 => Ok(RequestId::Text(text)),
        _ => Err(invalid("a signed 64-bit or bounded string request ID")),
    }
}

/// Decode the envelope before interpreting any provider-specific payload.
/// Requests requiring approval remain requests; they are never auto-accepted.
pub fn decode(line: &[u8]) -> Result<Message> {
    let value: Value = decode_json(line, MAX_LINE_BYTES)?;
    let Value::Object(mut fields) = value else {
        return Err(invalid("one JSON object per line"));
    };
    let id = fields.remove("id").map(request_id).transpose()?;
    let method = fields.remove("method");
    let result = fields.remove("result");
    let error = fields.remove("error");
    if let Some(method) = method {
        let Value::String(method) = method else {
            return Err(invalid("a string method"));
        };
        if method.is_empty() || method.len() > 256 || result.is_some() || error.is_some() {
            return Err(invalid("a bounded method with no result or error"));
        }
        let params = fields.remove("params").unwrap_or(Value::Null);
        return Ok(match id {
            Some(id) => Message::Request { id, method, params },
            None => Message::Notification { method, params },
        });
    }
    let id = id.ok_or_else(|| invalid("a response correlated to a request ID"))?;
    let result = match (result, error) {
        (Some(value), None) => Ok(value),
        (None, Some(Value::Object(mut failure))) => {
            let code = failure
                .remove("code")
                .and_then(|value| value.as_i64())
                .ok_or_else(|| invalid("an integer provider error code"))?;
            let message = failure
                .remove("message")
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(|| invalid("a provider error message"))?;
            Err(RpcFailure {
                code,
                message,
                data: failure.remove("data"),
            })
        }
        _ => return Err(invalid("exactly one response result or error")),
    };
    Ok(Message::Response { id, result })
}

/// A single retained frame. Callers advance by the returned consumed count,
/// then dispatch the message before feeding the unconsumed transport suffix.
#[derive(Default)]
pub struct Lines {
    pending: Zeroizing<Vec<u8>>,
    poisoned: bool,
}
impl Lines {
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(usize, Option<Message>)> {
        if self.poisoned {
            return Err(invalid("a new transport after a framing failure"));
        }
        let newline = bytes.iter().position(|byte| *byte == b'\n');
        let count = newline.unwrap_or(bytes.len());
        if count > MAX_LINE_BYTES.saturating_sub(self.pending.len()) {
            self.poisoned = true;
            return Err(invalid("an app-server line at most 1 MiB"));
        }
        self.pending.extend_from_slice(&bytes[..count]);
        if newline.is_none() {
            return Ok((count, None));
        }
        let message = decode(&self.pending);
        // Discard malformed framing only after recording an unrecoverable
        // error. The caller cannot continue against a shifted stream.
        if message.is_err() {
            self.poisoned = true;
        }
        self.pending.zeroize();
        Ok((count + 1, Some(message?)))
    }

    pub fn finish(&self) -> Result<()> {
        if self.poisoned || !self.pending.is_empty() {
            return Err(invalid("EOF only between complete app-server lines"));
        }
        Ok(())
    }
}

/// IDs are never reused within a provider binding, including failed writes.
#[derive(Default)]
pub struct Requests {
    next: i64,
}
impl Requests {
    pub(super) fn issued(&self, id: i64) -> bool {
        id > 0 && id <= self.next
    }
    pub fn request(&mut self, method: &str, params: Value) -> Result<(RequestId, Vec<u8>)> {
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| invalid("an unexhausted per-binding request sequence"))?;
        let id = RequestId::Number(self.next);
        let frame = frame(&json!({"id": id, "method": method, "params": params}))?;
        Ok((id, frame))
    }
}

pub fn notification(method: &str, params: Value) -> Result<Vec<u8>> {
    frame(&json!({"method": method, "params": params}))
}

/// Refuse unsupported approval/input requests explicitly. An RPC error is
/// protocol completion only; it is neither a turn-completed nor an exit fact.
pub fn refusal(id: &RequestId, message: &str) -> Result<Vec<u8>> {
    frame(&json!({"id": id, "error": {"code": -32601, "message": message}}))
}

fn frame(value: &Value) -> Result<Vec<u8>> {
    let encoded = encode_json(value, MAX_LINE_BYTES)?;
    let mut bytes = Vec::with_capacity(encoded.as_bytes().len() + 1);
    bytes.extend_from_slice(encoded.as_bytes());
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_frames_preserve_the_next_message() -> Result<()> {
        let mut lines = Lines::default();
        let first = br#"{"id":1,"res"#;
        assert_eq!(lines.feed(first)?.0, first.len());
        assert!(lines.finish().is_err());
        let remaining = b"ult\":{}}\n{\"method\":\"turn/completed\",\"params\":{}}\n";
        let (used, message) = lines.feed(remaining)?;
        assert!(matches!(
            message,
            Some(Message::Response {
                id: RequestId::Number(1),
                result: Ok(_)
            })
        ));
        let (tail, message) = lines.feed(&remaining[used..])?;
        assert_eq!(used + tail, remaining.len());
        assert!(
            matches!(message, Some(Message::Notification { method, .. }) if method == "turn/completed")
        );
        lines.finish()
    }

    #[test]
    fn malformed_and_over_budget_frames_cannot_shift_the_stream() -> Result<()> {
        for bytes in [
            b"{\"id\":1,\"id\":2,\"result\":{}}\n".to_vec(),
            vec![b'x'; MAX_LINE_BYTES + 1],
        ] {
            let mut lines = Lines::default();
            assert!(lines.feed(&bytes).is_err());
            assert!(lines.feed(b"{\"id\":1,\"result\":{}}\n").is_err());
            assert!(lines.finish().is_err());
        }
        Ok(())
    }

    #[test]
    fn failed_encoding_consumes_its_request_identity() -> Result<()> {
        let mut requests = Requests::default();
        assert!(
            requests
                .request("turn/start", json!("x".repeat(MAX_LINE_BYTES)))
                .is_err()
        );
        let (id, bytes) = requests.request("turn/interrupt", json!({}))?;
        assert_eq!(id, RequestId::Number(2));
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| invalid("a serialized outbound request"))?;
        assert!(value.get("jsonrpc").is_none());
        assert!(
            matches!(decode(&bytes)?, Message::Request { method, .. } if method == "turn/interrupt")
        );
        Ok(())
    }
}
