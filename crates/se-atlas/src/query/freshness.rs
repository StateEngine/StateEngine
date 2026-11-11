//! Verify emitted cached revisions without scheduling parsing or modifying SQL.
use super::*;
use std::io::Read as _;
mod output;
pub(super) use output::Verified;

pub(super) fn finish<'a, 'r, 'c, 'x, T: Verified + Serialize>(
    reader: &'a QueryReader<'r, 'c, 'x>,
    mut answer: Answer<Read<T>>,
    budget: QueryBudget,
    end: Instant,
) -> AtlasResult<Answer<Read<T>>> {
    let mut verifier = Verifier {
        reader,
        end,
        reasons: Vec::new(),
    };
    answer.data = match answer.data {
        Read::Present { value } => Read::Present {
            value: value.verify(&mut verifier)?,
        },
        other => other,
    };
    for reason in verifier.reasons {
        if matches!(answer.index.state, IndexState::Current) {
            answer.index.state = IndexState::VerificationNeeded { reason };
        }
        if !answer.index.coverage.reasons.contains(&reason) {
            answer.index.coverage.reasons.push(reason);
        }
    }
    check_output(answer, budget)
}

pub(super) struct Verifier<'a, 'r, 'c, 'x> {
    reader: &'a QueryReader<'r, 'c, 'x>,
    end: Instant,
    reasons: Vec<CoverageReason>,
}
impl Verifier<'_, '_, '_, '_> {
    fn pointer(&mut self, pointer: &mut CodePointer) -> AtlasResult<Option<CoverageReason>> {
        if pointer.freshness != SnapshotFreshness::Current {
            return Ok(None);
        }
        let reason = self.observe(pointer)?;
        if let Some(reason) = reason {
            pointer.freshness = SnapshotFreshness::Stale;
            if !self.reasons.contains(&reason) {
                self.reasons.push(reason);
            }
        }
        Ok(reason)
    }
    fn observe(&self, pointer: &mut CodePointer) -> AtlasResult<Option<CoverageReason>> {
        let (Some(source), Some(expected)) = (self.reader.ctx.source, pointer.content_hash) else {
            return Ok(Some(CoverageReason::StaleSnapshot));
        };
        if Instant::now() >= self.end {
            return Ok(Some(CoverageReason::TimeLimit));
        }
        let Some(mut file) = source.open_stream(&pointer.path)? else {
            return Ok(Some(CoverageReason::StaleSnapshot));
        };
        let before = file.identity()?;
        // The same whole-file ceiling as live Text and full-body verification.
        if before.size > 64 * 1024 * 1024 {
            return Ok(Some(CoverageReason::SourceBytesLimit));
        }
        let mut hash = blake3::Hasher::new();
        let mut scratch = [0; 16_384];
        let mut bytes = 0u64;
        let mut line = 1;
        let mut column = 0;
        loop {
            if Instant::now() >= self.end {
                return Ok(Some(CoverageReason::TimeLimit));
            }
            let count = file
                .read(&mut scratch)
                .map_err(|e| super::body::source_error(&pointer.path, e))?;
            if count == 0 {
                break;
            }
            bytes += count as u64;
            if bytes > before.size {
                return Ok(Some(CoverageReason::ChangedDuringRead));
            }
            hash.update(&scratch[..count]);
            if pointer.span.is_none() {
                for byte in &scratch[..count] {
                    if *byte == b'\n' {
                        line += 1;
                        column = 0;
                    } else {
                        column += 1;
                    }
                }
            }
        }
        if bytes != before.size || file.identity()? != before || !file.validate_path()? {
            return Ok(Some(CoverageReason::ChangedDuringRead));
        }
        if ContentHash(*hash.finalize().as_bytes()) != expected {
            return Ok(Some(CoverageReason::StaleSnapshot));
        }
        if Instant::now() >= self.end {
            return Ok(Some(CoverageReason::TimeLimit));
        }
        // A file pointer gains an extent only for the revision just verified.
        // Symbol/reference spans continue to describe their indexed revision.
        if pointer.span.is_none() {
            pointer.span = Some(Span {
                start: Position {
                    line: 1,
                    byte_column: 0,
                },
                end: Position {
                    line,
                    byte_column: column,
                },
                start_byte: 0,
                end_byte: bytes,
            });
        }
        Ok(None)
    }
}
