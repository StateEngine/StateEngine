use crate::{
    errors::{AtlasResult, capacity},
    model::*,
};
use std::{
    mem::size_of,
    sync::atomic::{AtomicBool, Ordering},
};
/// One parser/tree across all roots. The measured working set includes grammar
/// pages and retained allocator high-water marks; there is no default profile.
static PARSING: AtomicBool = AtomicBool::new(false);
pub(super) struct Lease;
impl Lease {
    pub fn take() -> AtlasResult<Self> {
        if PARSING.swap(true, Ordering::AcqRel) {
            return Err(capacity("Atlas global parser/tree", 1, 0));
        }
        Ok(Self)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        PARSING.store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParserPlacement {
    Incremental,
    ColdChild,
}
#[derive(Clone, Copy, Debug)]
pub struct ParserProfile {
    pub language: Language,
    pub placement: ParserPlacement,
    pub max_source_bytes: u32,
    pub max_rows: u32,
    pub measured_parser_bytes: u32,
    pub extraction_bytes: u32,
}
impl ParserProfile {
    /// Native qualification supplies the actual grammar/platform bounds. This
    /// constructor checks arithmetic; it does not replace outside measurement.
    pub fn from_qualified_measurement(
        language: Language,
        placement: ParserPlacement,
        source: u32,
        rows: u32,
        parser_bytes: u32,
        extraction: u32,
    ) -> AtlasResult<Self> {
        let ceiling = match placement {
            ParserPlacement::Incremental => 1_000_000,
            ParserPlacement::ColdChild => 60_000_000,
        };
        let total = u64::from(source) + u64::from(parser_bytes) + u64::from(extraction);
        if source == 0
            || source > 524288
            || rows == 0
            || rows > 65536
            || parser_bytes == 0
            || extraction == 0
            || total > ceiling
        {
            return Err(capacity("Atlas qualified parser profile", total, ceiling));
        }
        Ok(Self {
            language,
            placement,
            max_source_bytes: source,
            max_rows: rows,
            measured_parser_bytes: parser_bytes,
            extraction_bytes: extraction,
        })
    }
}
pub(super) struct Arena {
    left: usize,
    rows: u32,
    maximum: u32,
}
impl Arena {
    pub fn new(bytes: u32, rows: u32) -> Self {
        Self {
            left: bytes as usize,
            rows: 0,
            maximum: rows,
        }
    }
    pub fn charge(&mut self, bytes: usize) -> AtlasResult<()> {
        if bytes > self.left {
            return Err(capacity(
                "Atlas extraction arena",
                bytes as u64,
                self.left as u64,
            ));
        }
        self.left -= bytes;
        Ok(())
    }
    pub fn row<T>(&mut self, into: &mut Vec<T>, value: T) -> AtlasResult<()> {
        if self.rows >= self.maximum {
            return Err(capacity("Atlas extracted rows", 1, 0));
        }
        self.rows += 1;
        self.push(into, value)
    }
    pub fn push<T>(&mut self, into: &mut Vec<T>, value: T) -> AtlasResult<()> {
        if into.len() == into.capacity() {
            let count = into.capacity().max(4);
            self.charge(count * size_of::<T>())?;
            into.try_reserve_exact(count)
                .map_err(|_| capacity("Atlas extraction allocator", count as u64, 0))?;
        }
        into.push(value);
        Ok(())
    }
    pub fn text(&mut self, text: &str) -> AtlasResult<String> {
        self.charge(text.len())?;
        Ok(text.to_owned())
    }
}
