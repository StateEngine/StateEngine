//! Count frequent bookkeeping while scanning one raw range, then publish it
//! atomically with its next chat/continuity record. Live tails remain pending.
use super::super::claude::{self, TextRecord};
use super::*;
#[cfg(test)]
use crate::test_directory as cleanup_directory;
use se_core::ops::{
    hook::{CaptureMetadata, CaptureRequest},
    transcript::{Position, Record},
};
use std::collections::BTreeMap;

// Commit counted progress even without a following turn once either bound is
// reached. An ordinary short live tail still waits for the next real record.
const TAIL_RECORDS: usize = 1024;
const TAIL_BYTES: u64 = 4 * 1024 * 1024;

struct ScanState {
    revision: se_store::Revision,
    offset: u64,
    consumed: u64,
    complete: u64,
    digest: Sha256,
    noise: BTreeMap<String, Record>,
    noise_records: usize,
    tracker: super::queue::Tracker,
    tool_tracker: crate::harness::tool_capture::claude::Tracker,
}

enum LineDecision {
    Continue,
    Emit {
        end: u64,
        main: Option<TextRecord>,
        queued: Vec<Record>,
    },
}

impl ScanState {
    fn process_line(&mut self, source: &BoundTranscript, line: &[u8]) -> Result<LineDecision> {
        let decoded = claude::decode(line, &source.binding.conversation)?;
        let native = if decoded
            .as_ref()
            .is_some_and(|r| r.role == se_store::Role::System)
            || line.iter().all(u8::is_ascii_whitespace)
        {
            None
        } else {
            Some(
                serde_json::from_slice::<serde_json::Value>(line)
                    .map_err(|_| SeError::invalid("native tool record", "complete JSON"))?,
            )
        };
        let tool_count = native
            .as_ref()
            .map_or(0, crate::harness::tool_capture::claude::Tracker::count);
        if tool_count > 32 {
            return Err(SeError::invalid(
                "native tools per record",
                "at most 32 tool facts; preserve the source cursor",
            ));
        }
        if tool_count + self.noise.len() > 32 {
            return Ok(LineDecision::Emit {
                end: self.complete,
                main: None,
                queued: Vec::new(),
            });
        }
        self.digest.update(line);
        self.complete = self.consumed;
        let line_position = Position {
            offset: self.consumed - line.len() as u64,
            length: line.len() as u64,
        };
        let mut queued = self.tracker.observe(line, line_position.clone())?;
        if let Some(value) = native {
            for fact in self.tool_tracker.observe(&value)? {
                queued.push(fact.record(
                    &source.binding.identity,
                    se_store::Provider::Claude,
                    source.source,
                    line_position.clone(),
                )?);
            }
        }
        if queued.len() + self.noise.len() > 32 {
            return Err(SeError::invalid(
                "native metadata per record",
                "at most 32 metadata facts; preserve the source cursor",
            ));
        }
        if let Some(mut record) = decoded {
            if record.role == se_store::Role::System {
                let mut notice = if queued.is_empty() {
                    Record::decode(record.text.as_str())?
                } else {
                    queued.remove(0)
                };
                notice.position = line_position;
                if notice.queued_input.is_none() && claude::noise_kind(&notice.kind) {
                    count(&mut self.noise, notice)?;
                    self.noise_records += 1;
                    if self.noise_records >= TAIL_RECORDS
                        || self.consumed - self.offset >= TAIL_BYTES
                    {
                        return Ok(LineDecision::Emit {
                            end: self.consumed,
                            main: None,
                            queued,
                        });
                    }
                    return Ok(LineDecision::Continue);
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
            return Ok(LineDecision::Emit {
                end: self.consumed,
                main: Some(record),
                queued,
            });
        }
        if !queued.is_empty() {
            return Ok(LineDecision::Emit {
                end: self.consumed,
                main: None,
                queued,
            });
        }
        Ok(LineDecision::Continue)
    }

    fn finish(
        self,
        source: &mut BoundTranscript,
        end: u64,
        main: Option<TextRecord>,
        queued: Vec<Record>,
    ) -> Result<TrustedCapture> {
        finish(
            source,
            self.revision,
            self.offset,
            end,
            self.digest,
            main,
            Pending {
                noise: self.noise,
                queued,
                tracker: self.tracker,
                tool_tracker: self.tool_tracker,
            },
        )
    }
}

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
    let mut state = ScanState {
        revision,
        offset,
        consumed: offset,
        complete: offset,
        digest: Sha256::new(),
        noise: BTreeMap::new(),
        noise_records: 0,
        tracker: super::queue::restore(source, offset, deadline)?,
        tool_tracker: super::tools::restore(source, offset, deadline)?,
    };
    let mut position = offset;
    let mut line = Vec::new();
    loop {
        deadline.remaining()?;
        let chunk = source.pin.read_at(position, CHUNK).map_err(native_error)?;
        for byte in chunk.bytes {
            state.consumed = state.consumed.checked_add(1).ok_or_else(|| {
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
            match state.process_line(source, &line)? {
                LineDecision::Continue => line.clear(),
                LineDecision::Emit { end, main, queued } => {
                    return state.finish(source, end, main, queued).map(Some);
                }
            }
        }
        position = chunk.next_offset;
        if chunk.end_of_file || position == state.consumed && position == offset {
            if final_capture && !line.is_empty() {
                return Err(SeError::invalid(
                    "pinned Claude transcript framing",
                    "a newline-terminated final record after the native writer has exited; preserve the source and committed cursor",
                ));
            }
            if final_capture && !state.noise.is_empty() {
                let end = state.complete;
                return state.finish(source, end, None, Vec::new()).map(Some);
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
struct Pending {
    noise: BTreeMap<String, Record>,
    queued: Vec<Record>,
    tracker: super::queue::Tracker,
    tool_tracker: crate::harness::tool_capture::claude::Tracker,
}
fn finish(
    source: &mut BoundTranscript,
    revision: se_store::Revision,
    offset: u64,
    end: u64,
    digest: Sha256,
    main: Option<TextRecord>,
    pending: Pending,
) -> Result<TrustedCapture> {
    let Pending {
        mut noise,
        mut queued,
        tracker,
        tool_tracker,
    } = pending;
    let main = match main {
        Some(main) => main,
        None => {
            let record = if !noise.is_empty() {
                noise
                    .pop_first()
                    .ok_or_else(|| SeError::invalid("final metadata", "the counted record"))?
                    .1
            } else if !queued.is_empty() {
                queued.remove(0)
            } else {
                return Err(SeError::invalid(
                    "final metadata",
                    "at least one complete native metadata record",
                ));
            };
            TextRecord {
                vendor_turn: identity(source, "noise", offset, &record.kind),
                role: se_store::Role::System,
                text: record.body()?,
            }
        }
    };
    let mut metadata = Vec::with_capacity(noise.len() + queued.len());
    for (index, record) in noise.into_values().chain(queued).enumerate() {
        let allocated = facts()?;
        metadata.push(CaptureMetadata {
            vendor_turn: identity(
                source,
                "notice",
                record.position.offset,
                &if record.captured_tool.is_some() {
                    format!("captured-tool:{index}")
                } else {
                    format!(
                        "{}:{}",
                        record.kind,
                        record
                            .queued_input
                            .as_ref()
                            .and_then(|q| q.enqueue.as_ref())
                            .map_or(0, |p| p.offset)
                    )
                },
            ),
            record,
            turn: allocated.turn,
            event: allocated.turn_event,
        });
    }
    super::tools::retain(source, end, tool_tracker);
    if let Some((_, cached)) = source.queue.iter_mut().find(|(at, _)| *at == end) {
        *cached = tracker;
    } else {
        source.queue.push_back((end, tracker));
        if source.queue.len() > 2 {
            source.queue.pop_front();
        }
    }
    Ok(TrustedCapture {
        request: CaptureRequest {
            recovery_owner: None,
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

#[cfg(test)]
mod tool_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use se_store::RecordIdentity;

    #[test]
    fn long_live_noise_tail_commits_a_bounded_prefix()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!("se-noise-unit-{}", std::process::id()));
        std::fs::create_dir(&directory)?;
        let _root_owner = cleanup_directory::PrivateDirectory::for_case(directory.clone());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        }
        let path = directory.join("transcript.jsonl");
        let line = b"{\"type\":\"file-history-snapshot\",\"snapshot\":{}}\n";
        std::fs::write(&path, line.repeat(TAIL_RECORDS + 1))?;
        let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("missing unit source")?;
        let mut source = BoundTranscript {
            binding: crate::TranscriptPin {
                identity: crate::SessionIdentity {
                    project: se_types::ProjectId::from_parts(1_700_000_000_000, [3; 10])?,
                    agent: se_types::AgentId::from_parts(1_700_000_000_000, [4; 10])?,
                    session: se_types::SessionId::from_parts(1_700_000_000_000, [1; 10])?,
                },
                conversation: "noise-unit".parse()?,
                path: se_types::NativePath::from_local(path.clone())?,
                file_identity: se_types::Sha256::from_bytes(pin.identity()),
            },
            queue: Default::default(),
            tools: Default::default(),
            source: se_store::RecordId::from_parts(1_700_000_000_000, [2; 10])?,
            pin,
        };
        let revision = se_store::Revision {
            value: std::num::NonZeroU64::new(1).ok_or("zero revision")?,
        };
        let deadline = Deadline::idle()?.stage(std::time::Duration::from_secs(10))?;
        let batch = next(
            &mut source,
            revision,
            0,
            se_store::Provider::Claude,
            &deadline,
            false,
        )?
        .ok_or("no bounded progress")?;
        let end = (TAIL_RECORDS * line.len()) as u64;
        assert_eq!(batch.request.new_offset, end);
        let record = Record::decode(batch.request.text.as_str())?;
        assert_eq!(record.count, Some(TAIL_RECORDS as u64));
        assert!(
            next(
                &mut source,
                revision,
                end,
                se_store::Provider::Claude,
                &deadline,
                false
            )?
            .is_none()
        );
        let final_batch = next(
            &mut source,
            revision,
            end,
            se_store::Provider::Claude,
            &deadline,
            true,
        )?
        .ok_or("final tail lost")?;
        assert_eq!(
            Record::decode(final_batch.request.text.as_str())?.count,
            Some(1)
        );
        next(
            &mut source,
            revision,
            end,
            se_store::Provider::Claude,
            &deadline,
            true,
        )?
        .ok_or("final retry lost")?;
        assert_eq!(source.queue.len(), 2);
        assert!(source.queue.iter().any(|(at, _)| *at == end));
        drop(source);
        std::fs::remove_file(path)?;

        _root_owner.finish(Ok(()))
    }
}
