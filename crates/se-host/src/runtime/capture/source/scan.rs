//! Count frequent bookkeeping while scanning one raw range, then publish it
//! atomically with its next chat/continuity record. Live tails remain pending.
use super::super::claude::{self, TextRecord};
use super::*;
use se_core::ops::{
    hook::{CaptureMetadata, CaptureRequest},
    transcript::{Position, Record},
};
use std::collections::BTreeMap;

pub(super) fn next(
    source: &mut BoundTranscript,
    revision: se_store::Revision,
    offset: u64,
    provider: se_store::Provider,
    deadline: &Deadline,
    final_capture: bool,
) -> Result<Option<TrustedCapture>> {
    if provider == se_store::Provider::Codex {
        return super::codex::next(source, revision, offset, deadline, final_capture);
    }
    let mut position = offset;
    let mut consumed = offset;
    let mut complete = offset;
    let mut line = Vec::new();
    let mut digest = Sha256::new();
    let mut noise = BTreeMap::<String, Record>::new();
    loop {
        deadline.remaining()?;
        let chunk = source.pin.read_at(position, CHUNK).map_err(native_error)?;
        for byte in chunk.bytes {
            consumed = consumed.checked_add(1).ok_or_else(|| {
                SeError::invalid("capture offset", "a representable source range")
            })?;
            line.push(byte);
            if line.len() > LINE {
                return Err(SeError::too_large(
                    "provider transcript line",
                    LINE,
                    line.len(),
                ));
            }
            if byte != b'\n' {
                continue;
            }
            digest.update(&line);
            complete = consumed;
            if let Some(mut record) = claude::decode(&line, &source.binding.conversation)? {
                if record.role == se_store::Role::System {
                    let mut notice = Record::decode(record.text.as_str())?;
                    notice.position = Position {
                        offset: consumed - line.len() as u64,
                        length: line.len() as u64,
                    };
                    if claude::noise_kind(&notice.kind) {
                        count(&mut noise, notice)?;
                        line.clear();
                        continue;
                    }
                    record.vendor_turn = identity(
                        source,
                        if notice.is_compaction() {
                            "compact"
                        } else {
                            "record"
                        },
                        notice.position.offset,
                        "",
                    );
                    record.text = notice.body()?;
                }
                return finish(
                    source,
                    revision,
                    offset,
                    consumed,
                    digest,
                    noise,
                    Some(record),
                )
                .map(Some);
            }
            line.clear();
        }
        position = chunk.next_offset;
        if chunk.end_of_file || position == consumed && position == offset {
            if final_capture && !line.is_empty() {
                return Err(SeError::invalid(
                    "pinned Claude transcript framing",
                    "a newline-terminated final record after the native writer has exited; preserve the source and committed cursor",
                ));
            }
            if final_capture && !noise.is_empty() {
                return finish(source, revision, offset, complete, digest, noise, None).map(Some);
            }
            return Ok(None);
        }
    }
}
fn count(noise: &mut BTreeMap<String, Record>, mut notice: Record) -> Result<()> {
    if let Some(prior) = noise.get_mut(&notice.kind) {
        prior.count = Some(
            prior
                .count
                .and_then(|n| n.checked_add(1))
                .ok_or_else(|| SeError::invalid("metadata count", "a representable count"))?,
        );
        prior.position = notice.position.clone();
        prior.last_position = Some(notice.position);
    } else {
        notice.count = Some(1);
        notice.first_position = Some(notice.position.clone());
        notice.last_position = Some(notice.position.clone());
        notice.subtype = None;
        notice.subtype_truncated = false;
        noise.insert(notice.kind.clone(), notice);
    }
    Ok(())
}
fn identity(source: &BoundTranscript, category: &str, offset: u64, kind: &str) -> String {
    format!(
        "{}{category}/{offset}/{kind}/{}",
        se_store::TRANSCRIPT_EVENT_PREFIX,
        se_types::hex_lower(&source.pin.identity())
    )
}
fn finish(
    source: &BoundTranscript,
    revision: se_store::Revision,
    offset: u64,
    end: u64,
    digest: Sha256,
    mut noise: BTreeMap<String, Record>,
    main: Option<TextRecord>,
) -> Result<TrustedCapture> {
    let main = match main {
        Some(main) => main,
        None => {
            let (_, record) = noise.pop_first().ok_or_else(|| {
                SeError::invalid("final metadata", "at least one complete counted record")
            })?;
            TextRecord {
                vendor_turn: identity(source, "noise", offset, &record.kind),
                role: se_store::Role::System,
                text: record.body()?,
            }
        }
    };
    let mut metadata = Vec::with_capacity(noise.len());
    for record in noise.into_values() {
        let allocated = facts()?;
        metadata.push(CaptureMetadata {
            vendor_turn: identity(source, "noise", offset, &record.kind),
            record,
            turn: allocated.turn,
            event: allocated.turn_event,
        });
    }
    Ok(TrustedCapture {
        request: CaptureRequest {
            source: source.source,
            expected: revision,
            conversation: source.binding.conversation.clone(),
            provider: se_store::Provider::Claude,
            vendor_turn: main.vendor_turn,
            role: main.role,
            text: main.text,
            metadata,
            evidence: se_store::SourceEvidence {
                path: Some(source.binding.path.clone()),
                incarnation: source.pin.identity().to_vec(),
                offset,
                length: end - offset,
                sha256: Some(digest.finalize().into()),
            },
            new_offset: end,
        },
        facts: facts()?,
    })
}
