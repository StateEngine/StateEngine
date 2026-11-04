//! Recover finite call/result joins from this exact native pin, not a floor scan.
use super::*;
use crate::harness::tool_capture::claude::Tracker;

pub(super) fn restore(
    source: &mut BoundTranscript,
    offset: u64,
    deadline: &Deadline,
) -> Result<Tracker> {
    if let Some((_, state)) = source.tools.iter().find(|(at, _)| *at == offset) {
        return Ok(state.clone());
    }
    let mut state = Tracker::default();
    let mut position = 0;
    let mut line = Vec::new();
    while position < offset {
        deadline.remaining()?;
        let chunk = source
            .pin
            .read_at(position, (offset - position).min(CHUNK as u64) as usize)
            .map_err(native_error)?;
        if chunk.bytes.is_empty() {
            return Err(SeError::invalid(
                "native tool recovery",
                "the original complete captured prefix",
            ));
        }
        for byte in chunk.bytes {
            position += 1;
            line.push(byte);
            if line.len() > LINE {
                return Err(SeError::too_large(
                    "native tool recovery line",
                    LINE,
                    line.len(),
                ));
            }
            if byte == b'\n' {
                observe(&mut state, &line)?;
                line.clear();
            }
        }
    }
    if !line.is_empty() {
        return Err(SeError::invalid(
            "native tool recovery",
            "a committed newline boundary",
        ));
    }
    Ok(state)
}
pub(super) fn observe(
    state: &mut Tracker,
    line: &[u8],
) -> Result<Vec<crate::harness::tool_capture::Fact>> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let value = serde_json::from_slice(line)
        .map_err(|_| SeError::invalid("native tool record", "a complete JSON record"))?;
    state.observe(&value)
}
pub(super) fn retain(source: &mut BoundTranscript, end: u64, state: Tracker) {
    if let Some((_, cached)) = source.tools.iter_mut().find(|(at, _)| *at == end) {
        *cached = state;
    } else {
        source.tools.push_back((end, state));
        if source.tools.len() > 2 {
            source.tools.pop_front();
        }
    }
}
