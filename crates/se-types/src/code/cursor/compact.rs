//! Bounded position wire: raw hashes and UUIDs, variable-length ordering numbers.
//! Version-one canonical JSON remains readable in the parent codec.
use super::*;

fn number(mut value: u64, out: &mut Vec<u8>) {
    while value >= 128 {
        out.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}
fn bytes(value: &[u8], out: &mut Vec<u8>) {
    number(value.len() as u64, out);
    out.extend_from_slice(value);
}
macro_rules! id {
    ($write:ident, $read:ident, $kind:ty) => {
        fn $write(value: &$kind, out: &mut Vec<u8>) -> AtlasResult<()> {
            if let Some(value) = value.canonical_bytes().map_err(cursor_invalid)? {
                out.push(0);
                out.extend_from_slice(&value);
            } else {
                out.push(1);
                bytes(value.as_str().as_bytes(), out);
            }
            Ok(())
        }
        fn $read(input: &mut Input<'_>) -> AtlasResult<$kind> {
            match input.take(1)?[0] {
                0 => <$kind>::from_bytes(input.array()?).map_err(cursor_invalid),
                1 => <$kind>::try_from(input.text(512)?).map_err(cursor_invalid),
                _ => Err(cursor_invalid("invalid cursor identity encoding")),
            }
        }
    };
}
id!(project, read_project, crate::ProjectId);
id!(root, read_root, RootId);
id!(epoch, read_epoch, CacheEpoch);

pub(super) fn encode(value: &CodeCursorPosition) -> AtlasResult<Vec<u8>> {
    value.last_key.validate()?;
    if value.version != 1 || value.mode.is_empty() || value.mode.len() > 32 {
        return Err(cursor_invalid("invalid query mode"));
    }
    let mut out = vec![2];
    bytes(value.mode.as_bytes(), &mut out);
    project(&value.project, &mut out)?;
    root(&value.root, &mut out)?;
    epoch(&value.epoch, &mut out)?;
    out.extend_from_slice(&value.query_digest);
    number(value.generation_hint.0, &mut out);
    let clock = value.ranking_clock.as_ref().and_then(|c| c.now_unix_ms);
    let flags = u8::from(value.change_fence.is_some())
        | (u8::from(value.ranking_clock.is_some()) << 1)
        | (u8::from(clock.is_some()) << 2)
        | (u8::from(value.text_window.is_some()) << 3)
        | (u8::from(value.text_window.as_ref().is_some_and(|w| w.has_more)) << 4);
    out.push(flags);
    if let Some(fence) = value.change_fence {
        number(fence.0, &mut out);
    }
    if let Some(clock) = clock {
        out.extend_from_slice(&clock.to_be_bytes());
    }
    if let Some(window) = &value.text_window {
        out.extend_from_slice(&window.last_touch_unix_ms.to_be_bytes());
        out.extend_from_slice(&window.file);
    }
    number(value.last_key.integers.len() as u64, &mut out);
    for integer in &value.last_key.integers {
        number(*integer, &mut out);
    }
    bytes(&value.last_key.bytes, &mut out);
    Ok(out)
}

pub(super) fn decode(value: &[u8]) -> AtlasResult<CodeCursorPosition> {
    let mut input = Input(value);
    if input.take(1)? != [2] {
        return Err(cursor_invalid("unsupported compact cursor version"));
    }
    let mode = input.text(32)?;
    let project = read_project(&mut input)?;
    let root = read_root(&mut input)?;
    let epoch = read_epoch(&mut input)?;
    let query_digest = input.array()?;
    let generation_hint = Generation(input.number()?);
    let flags = input.take(1)?[0];
    let change_fence = (flags & 1 != 0)
        .then(|| input.number().map(Generation))
        .transpose()?;
    let ranking_clock = if flags & 2 != 0 {
        Some(RankingClock {
            now_unix_ms: (flags & 4 != 0)
                .then(|| input.array().map(i64::from_be_bytes))
                .transpose()?,
        })
    } else {
        None
    };
    let text_window = if flags & 8 != 0 {
        Some(TextWindow {
            last_touch_unix_ms: i64::from_be_bytes(input.array()?),
            file: input.array()?,
            has_more: flags & 16 != 0,
        })
    } else {
        None
    };
    let count = input.number()?;
    if count > 8 {
        return Err(cursor_invalid("oversized ordering key"));
    }
    let integers = (0..count)
        .map(|_| input.number())
        .collect::<AtlasResult<Vec<_>>>()?;
    let bytes = input.bytes(512)?.to_vec();
    if !input.0.is_empty() {
        return Err(cursor_invalid("trailing compact cursor bytes"));
    }
    Ok(CodeCursorPosition {
        version: 1,
        mode,
        project,
        root,
        epoch,
        query_digest,
        last_key: CursorKey { integers, bytes },
        generation_hint,
        change_fence,
        ranking_clock,
        text_window,
    })
}

struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, count: usize) -> AtlasResult<&'a [u8]> {
        let (value, rest) = self
            .0
            .split_at_checked(count)
            .ok_or_else(|| cursor_invalid("truncated compact cursor"))?;
        self.0 = rest;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> AtlasResult<[u8; N]> {
        self.take(N)?.try_into().map_err(cursor_invalid)
    }
    fn number(&mut self) -> AtlasResult<u64> {
        let mut value = 0;
        for shift in (0..70).step_by(7) {
            let byte = self.take(1)?[0];
            if shift == 63 && byte > 1 {
                return Err(cursor_invalid("oversized compact cursor number"));
            }
            value |= u64::from(byte & 127) << shift;
            if byte & 128 == 0 {
                return Ok(value);
            }
        }
        Err(cursor_invalid("oversized compact cursor number"))
    }
    fn bytes(&mut self, maximum: usize) -> AtlasResult<&'a [u8]> {
        let count = usize::try_from(self.number()?).map_err(cursor_invalid)?;
        if count > maximum {
            return Err(cursor_invalid("oversized compact cursor field"));
        }
        self.take(count)
    }
    fn text(&mut self, maximum: usize) -> AtlasResult<String> {
        String::from_utf8(self.bytes(maximum)?.to_vec()).map_err(cursor_invalid)
    }
}
