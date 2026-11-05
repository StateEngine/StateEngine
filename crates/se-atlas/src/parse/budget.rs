use crate::{
    errors::{AtlasResult, capacity},
    model::*,
};
use std::{
    mem::size_of,
    sync::atomic::{AtomicBool, Ordering},
};
/// One parser/tree across all roots. Anonymous reservations include retained
/// allocator pages; shared file-backed grammar pages are reported separately.
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
    pub parser_reservation_bytes: u32,
    pub extraction_bytes: u32,
    pub shared_grammar_pages: Option<GrammarPages>,
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
            ParserPlacement::Incremental => u64::from(PARSER_BYTES),
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
            parser_reservation_bytes: parser_bytes,
            extraction_bytes: extraction,
            shared_grammar_pages: None,
        })
    }
    pub fn with_shared_grammar_pages(mut self, observed: u32, reserved: u32) -> AtlasResult<Self> {
        if observed == 0 || reserved < observed {
            return Err(capacity(
                "Atlas shared grammar page profile",
                u64::from(observed),
                u64::from(reserved),
            ));
        }
        self.shared_grammar_pages = Some(GrammarPages {
            observed_bytes: observed,
            reserved_bytes: reserved,
        });
        Ok(self)
    }
    pub fn anonymous_bytes(&self) -> u64 {
        u64::from(self.max_source_bytes)
            + u64::from(self.parser_reservation_bytes)
            + u64::from(self.extraction_bytes)
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
        let mut copy = String::new();
        copy.try_reserve_exact(text.len())
            .map_err(|_| capacity("Atlas extraction allocator", text.len() as u64, 0))?;
        copy.push_str(text);
        Ok(copy)
    }
}
