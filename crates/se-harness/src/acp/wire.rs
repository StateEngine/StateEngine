//! Bounded newline framing and unambiguous JSON-RPC envelopes.
use super::failure;
use se_types::Result;
use serde_json::Value;

pub(super) const MAX_FRAME: usize = 1024 * 1024;
pub(super) enum Envelope {
    Response {
        id: u64,
        outcome: Result<Value>,
    },
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Update(Value),
    OtherNotification,
}

#[derive(Default)]
pub(super) struct Frames(Vec<u8>);
impl Frames {
    // Preserve completed frames even when the same read ends with invalid output.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Result<Envelope>> {
        let mut result = Vec::new();
        for byte in bytes {
            if *byte == b'\n' {
                if self.0.last() == Some(&b'\r') {
                    self.0.pop();
                }
                if self.0.is_empty() {
                    result.push(Err(failure("ACP frame", "empty protocol frame")));
                    break;
                }
                let decoded = decode(&self.0);
                self.0.clear();
                let failed = decoded.is_err();
                result.push(decoded);
                if failed {
                    break;
                }
            } else {
                if self.0.len() == MAX_FRAME {
                    result.push(Err(failure(
                        "ACP frame",
                        "one-MiB frame bound exceeded; incomplete frame not accepted",
                    )));
                    break;
                }
                self.0.push(*byte);
            }
        }
        result
    }
    pub fn eof(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(failure("ACP stream", "EOF inside a protocol frame"))
        }
    }
}

pub(super) fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|_| failure("ACP request", "JSON encoding failed"))?;
    if bytes.len() >= MAX_FRAME {
        return Err(failure(
            "ACP request",
            "one-MiB frame bound exceeded before write",
        ));
    }
    bytes.push(b'\n');
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<Envelope> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| {
        failure(
            "ACP frame",
            "invalid UTF-8 or JSON; stdout must contain protocol only",
        )
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| failure("ACP envelope", "one object required"))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(failure("ACP envelope", "JSON-RPC version differs"));
    }
    if let Some(method) = object.get("method") {
        let method = method
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 256)
            .ok_or_else(|| failure("ACP method", "bounded method name required"))?;
        if object.contains_key("result") || object.contains_key("error") {
            return Err(failure(
                "ACP envelope",
                "request and response fields overlap",
            ));
        }
        let params = object.get("params").cloned().unwrap_or(Value::Null);
        if let Some(id) = object.get("id") {
            if !(id.as_str().is_some_and(|v| !v.is_empty() && v.len() <= 512)
                || id.is_i64()
                || id.is_u64())
            {
                return Err(failure(
                    "ACP request",
                    "string or numeric request identity required",
                ));
            }
            return Ok(Envelope::Request {
                id: id.clone(),
                method: method.into(),
                params,
            });
        }
        return Ok(if method == "session/update" {
            Envelope::Update(params)
        } else {
            Envelope::OtherNotification
        });
    }
    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| failure("ACP response", "original numeric request identity required"))?;
    let outcome = match (object.get("result"), object.get("error")) {
        (Some(result), None) => Ok(result.clone()),
        (None, Some(error)) => {
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .ok_or_else(|| failure("ACP response", "error code absent"))?;
            // An agent can echo credentials from a rejected MCP request in its
            // message/data. Public diagnostics retain only its numeric code.
            Err(failure(
                "ACP operation",
                format!("agent returned protocol error {code}; original request is not replayed"),
            ))
        }
        _ => {
            return Err(failure(
                "ACP response",
                "exactly one result or error required",
            ));
        }
    };
    Ok(Envelope::Response { id, outcome })
}
