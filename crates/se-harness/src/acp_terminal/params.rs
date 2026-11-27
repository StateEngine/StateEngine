//! JSON-RPC parameter validation and response-shaping helpers for ACP `terminal/*`.
use crate::acp::client::{RESPONSE_BYTES, Refusal};
use se_proc::ContainedExit;
use serde_json::{Value, json};
use std::ffi::OsString;

/// Default retained tail output bytes per terminal.
const DEFAULT_OUTPUT_BYTES: usize = 256 * 1024;
/// Hard ceiling on retained tail output bytes per terminal (fits inside one reply).
const MAX_OUTPUT_BYTES: usize = {
    let reply_room = RESPONSE_BYTES.saturating_sub(1024);
    let one_mib = 1024 * 1024;
    if reply_room < one_mib {
        reply_room
    } else {
        one_mib
    }
};
/// Maximum arguments accepted by `terminal/create`.
const MAX_ARGS: usize = 256;
/// Maximum environment overrides accepted by `terminal/create`.
const MAX_ENV: usize = 128;

pub(super) fn exit_json(exit: ContainedExit) -> Value {
    json!({
        "exitCode": exit.exit_code,
        "signal": exit.signal,
    })
}

pub(super) fn fit_response(mut text: String, truncated: &mut bool) -> Result<String, Refusal> {
    let limit = RESPONSE_BYTES.saturating_sub(256);
    while serde_json::to_string(&text)
        .map_err(|_| Refusal::failed("terminal output could not be encoded"))?
        .len()
        > limit
    {
        *truncated = true;
        let drop_bytes = (text.len() / 4).max(1);
        let mut cut = drop_bytes.min(text.len());
        while cut < text.len() && !text.is_char_boundary(cut) {
            cut += 1;
        }
        text.drain(..cut);
    }
    Ok(text)
}

pub(super) fn required_str<'a>(
    params: &'a Value,
    field: &str,
    max_len: usize,
) -> Result<&'a str, Refusal> {
    params
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= max_len && !s.contains('\0'))
        .ok_or_else(|| {
            Refusal::invalid(format!(
                "`{field}` must be a non-empty string (<= {max_len} bytes, no NUL)"
            ))
        })
}

pub(super) fn optional_str<'a>(
    params: &'a Value,
    field: &str,
    max_len: usize,
) -> Result<Option<&'a str>, Refusal> {
    match params.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.is_empty() && s.len() <= max_len && !s.contains('\0') => {
            Ok(Some(s.as_str()))
        }
        _ => Err(Refusal::invalid(format!(
            "`{field}` must be a non-empty string (<= {max_len} bytes, no NUL)"
        ))),
    }
}

pub(super) fn parse_args(params: &Value) -> Result<Vec<OsString>, Refusal> {
    let Some(value) = params.get("args") else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let arr = value
        .as_array()
        .ok_or_else(|| Refusal::invalid("`args` must be an array of strings"))?;
    if arr.len() > MAX_ARGS {
        return Err(Refusal::invalid(format!(
            "`args` exceeds maximum of {MAX_ARGS} entries"
        )));
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .filter(|s| s.len() <= 65536 && !s.contains('\0'))
            .ok_or_else(|| Refusal::invalid("each element of `args` must be a valid string"))?;
        out.push(OsString::from(s));
    }
    Ok(out)
}

fn is_forbidden_env_key(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("SE_")
        || upper.starts_with("STATEENGINE_")
        || upper.starts_with("LD_")
        || upper.starts_with("DYLD_")
}

pub(super) fn parse_env(params: &Value) -> Result<Vec<(OsString, OsString)>, Refusal> {
    let Some(value) = params.get("env") else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let arr = value
        .as_array()
        .ok_or_else(|| Refusal::invalid("`env` must be an array of {name, value} objects"))?;
    if arr.len() > MAX_ENV {
        return Err(Refusal::invalid(format!(
            "`env` exceeds maximum of {MAX_ENV} entries"
        )));
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 256 && !s.contains('=') && !s.contains('\0'))
            .ok_or_else(|| Refusal::invalid("`env[].name` must be a valid environment key"))?;
        if is_forbidden_env_key(name) {
            return Err(Refusal::invalid(format!(
                "`env[].name` '{name}' is reserved and cannot be overridden by terminal/create"
            )));
        }
        let val = item
            .get("value")
            .and_then(Value::as_str)
            .filter(|s| s.len() <= 65536 && !s.contains('\0'))
            .ok_or_else(|| Refusal::invalid("`env[].value` must be a valid string"))?;
        out.push((OsString::from(name), OsString::from(val)));
    }
    Ok(out)
}

pub(super) fn parse_output_limit(params: &Value) -> Result<usize, Refusal> {
    match params.get("outputByteLimit") {
        None | Some(Value::Null) => Ok(DEFAULT_OUTPUT_BYTES),
        Some(value) => {
            let requested = value.as_u64().ok_or_else(|| {
                Refusal::invalid("`outputByteLimit` must be a nonnegative integer")
            })?;
            let clamped = usize::try_from(requested)
                .unwrap_or(MAX_OUTPUT_BYTES)
                .min(MAX_OUTPUT_BYTES);
            Ok(clamped)
        }
    }
}
