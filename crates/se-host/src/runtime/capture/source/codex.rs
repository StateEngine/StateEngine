//! Incremental canonical completions from the already validated Codex rollout.
use super::*;
use se_core::ops::hook::CaptureRequest;

pub(super) fn next(
    source: &mut BoundTranscript,
    revision: se_store::Revision,
    offset: u64,
    deadline: &Deadline,
    final_capture: bool,
) -> Result<Option<TrustedCapture>> {
    let mut position = offset;
    let mut consumed = offset;
    let mut line = Vec::new();
    let mut digest = Sha256::new();
    loop {
        deadline.remaining()?;
        let chunk = source.pin.read_at(position, CHUNK).map_err(native_error)?;
        for byte in chunk.bytes {
            consumed = consumed.checked_add(1).ok_or_else(|| {
                SeError::invalid("Codex capture offset", "a representable native range")
            })?;
            line.push(byte);
            if line.len() > LINE {
                return Err(SeError::too_large("Codex rollout line", LINE, line.len()));
            }
            if byte != b'\n' {
                continue;
            }
            digest.update(&line);
            let tool =
                crate::harness::tool_capture::codex::decode(&line, &source.binding.conversation)?;
            let completed = match tool {
                Some(fact) => Some(crate::codex_capture::Completed {
                    vendor: fact.vendor(&source.binding.identity.session),
                    role: se_store::Role::System,
                    text: fact
                        .record(
                            &source.binding.identity,
                            se_store::Provider::Codex,
                            source.source,
                            se_core::ops::transcript::Position {
                                offset: consumed - line.len() as u64,
                                length: line.len() as u64,
                            },
                        )?
                        .body()?,
                }),
                None => crate::codex_capture::decode(&line, &source.binding.conversation)?,
            };
            if let Some(record) = completed {
                let mut allocated = facts()?;
                allocated.turn = crate::codex_capture::turn_id(
                    &source.binding.identity.session,
                    &record.vendor,
                )?;
                return Ok(Some(TrustedCapture {
                    request: CaptureRequest {
                        source: source.source,
                        expected: revision,
                        conversation: source.binding.conversation.clone(),
                        provider: se_store::Provider::Codex,
                        vendor_turn: record.vendor,
                        role: record.role,
                        text: record.text,
                        metadata: Vec::new(),
                        evidence: se_store::SourceEvidence {
                            path: Some(source.binding.path.clone()),
                            incarnation: source.pin.identity().to_vec(),
                            offset,
                            length: consumed - offset,
                            sha256: Some(digest.finalize().into()),
                        },
                        new_offset: consumed,
                    },
                    facts: allocated,
                }));
            }
            line.clear();
        }
        position = chunk.next_offset;
        if chunk.end_of_file {
            if final_capture && !line.is_empty() {
                return Err(SeError::invalid(
                    "Codex rollout framing",
                    "a complete final newline after native exit; preserve the cursor",
                ));
            }
            return Ok(None);
        }
    }
}
