//! Bounded native provider framing. Claimed conversation/path fields are data;
//! only the host's protected binding and pinned reader can authorize capture.
use se_core::ops::{HookEvent, HookResult};
use se_host::{ClaudeHookInput, ClaudeHookKind};
use se_types::{Result, SeError};
use std::{
    io::{Read, Write},
    path::PathBuf,
};

pub fn read_native(event: HookEvent, input: &mut dyn Read) -> Result<ClaudeHookInput> {
    let limit = se_host::client::wire::MAX_FRAME_BYTES;
    let mut bytes = Vec::new();
    input
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| se_core::scope::unreadable("native hook stdin", &error.to_string()))?;
    if bytes.len() > limit {
        return Err(SeError::too_large("hook stdin", limit, bytes.len()));
    }
    // This common decoder refuses duplicate keys/depth before interpreting data.
    // Never echo provider payloads or a decoder's copied source in a diagnostic.
    let payload: serde_json::Value =
        se_host::client::wire::decode_json(&bytes, limit).map_err(|_| {
            SeError::invalid(
                "hook stdin",
                "one bounded provider JSON object with unique fields",
            )
        })?;
    let field = |name| {
        payload
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SeError::invalid("hook stdin", "string session_id and transcript_path fields")
            })
    };
    let conversation = se_types::ProviderSessionId::new(field("session_id")?.to_owned())?;
    let path = PathBuf::from(field("transcript_path")?);
    if !path.is_absolute() {
        return Err(SeError::invalid(
            "claimed transcript",
            "an absolute native provider path; the host still checks its pinned source",
        ));
    }
    let claimed_transcript = se_types::NativePath::from_local(path)?;
    Ok(ClaudeHookInput {
        kind: match event {
            HookEvent::SessionStart => ClaudeHookKind::SessionStart,
            HookEvent::Prompt => ClaudeHookKind::Prompt,
            HookEvent::Stop => ClaudeHookKind::Stop,
            HookEvent::StopFailure => ClaudeHookKind::StopFailure,
        },
        conversation,
        claimed_transcript,
        payload,
    })
}

/// The process wrapper keeps the provider's required zero exit even after a
/// capture failure, and must print the diagnostic. Zero is never a capture proof.
pub fn write_native(
    event: HookEvent,
    result: &HookResult,
    output: &mut dyn Write,
    diagnostic: &mut dyn Write,
) -> std::io::Result<()> {
    if matches!(event, HookEvent::Stop | HookEvent::StopFailure) && !result.stdout.is_empty() {
        return Err(std::io::Error::other(
            "capture-only hook returned unexpected stdout",
        ));
    }
    if let Some(failure) = &result.failure {
        writeln!(diagnostic, "capture failed: {failure}")?;
    } else if matches!(
        result.captured,
        se_types::Read::Unreadable { .. } | se_types::Read::Unknown { .. }
    ) {
        writeln!(
            diagnostic,
            "capture is unconfirmed; read se status for the source failure"
        )?;
    }
    diagnostic.flush()?;
    output.write_all(result.stdout.as_bytes())?;
    output.flush()
}
