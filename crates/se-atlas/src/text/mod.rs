//! Streaming live-source matching. Source custody is supplied by the native port.
pub(crate) mod lexical;
mod stream;
use crate::{errors::AtlasResult, model::*, source::SourceFile};
use grep_matcher::Matcher;
use grep_regex::{RegexMatcher, RegexMatcherBuilder};
use grep_searcher::{SearcherBuilder, Sink, SinkMatch};
use se_types::code::*;
use std::{
    io::{self, Read, SeekFrom},
    time::Instant,
};

pub struct TextRequest<'a> {
    pub pointer: &'a CodePointer,
    pub query: &'a str,
    pub regex: bool,
    pub full: bool,
    pub deadline: Instant,
    pub max_matches: usize,
}
pub struct TextFileResult {
    pub hits: Vec<(CodeHit, HitBody)>,
    pub omitted_matches: u64,
    pub complete: bool,
    pub binary: bool,
    pub non_utf8: bool,
    pub oversized: bool,
    pub changed: bool,
    /// Stable live bytes differ from the indexed revision, rather than changing during IO.
    pub stale_index: bool,
    pub time_limited: bool,
    pub line_limited: bool,
    pub(crate) lexical: Option<lexical::Document>,
}
pub fn search_file(
    file: Box<dyn SourceFile + '_>,
    request: TextRequest<'_>,
) -> AtlasResult<TextFileResult> {
    let matcher = compile_pattern(request.query, request.regex, !request.regex)?;
    search_with_matcher(file, request, &matcher)
}
/// A bounded query compiles its expression once, then reuses it across files.
/// Compiling per file can consume the entire source-scan deadline before IO.
pub(crate) fn compile_pattern(
    query: &str,
    regex: bool,
    smart_case: bool,
) -> AtlasResult<RegexMatcher> {
    RegexMatcherBuilder::new()
        .fixed_strings(!regex)
        .case_smart(smart_case)
        .size_limit(16_384)
        .dfa_size_limit(16_384)
        .build(query)
        .map_err(|e| {
            se_types::SeError::invalid("Atlas text query", &format!("a bounded expression: {e}"))
        })
}
pub(crate) fn search_with_matcher(
    file: Box<dyn SourceFile + '_>,
    request: TextRequest<'_>,
    matcher: &RegexMatcher,
) -> AtlasResult<TextFileResult> {
    search_with_terms(file, request, matcher, None)
}
pub(crate) fn search_with_terms(
    mut file: Box<dyn SourceFile + '_>,
    request: TextRequest<'_>,
    matcher: &RegexMatcher,
    terms: Option<&lexical::Terms>,
) -> AtlasResult<TextFileResult> {
    if request.max_matches > 3 {
        return Err(se_types::SeError::invalid(
            "Atlas text file matches",
            "at most three per page",
        ));
    }
    let before = file.identity()?;
    let mut output = TextFileResult {
        hits: Vec::new(),
        omitted_matches: 0,
        complete: true,
        binary: false,
        non_utf8: false,
        oversized: before.size > 64 * 1024 * 1024,
        changed: false,
        stale_index: false,
        time_limited: false,
        line_limited: false,
        lexical: None,
    };
    if output.oversized {
        return Ok(output);
    }
    let mut reader = stream::Observed::new(&mut *file, request.deadline, terms);
    let mut sink = Matches {
        request: &request,
        matcher,
        items: Vec::with_capacity(3),
        omitted: 0,
    };
    let result = SearcherBuilder::new()
        .line_number(true)
        .heap_limit(Some(32_768))
        .encoding(None)
        .bom_sniffing(false)
        .build()
        .search_reader(matcher, &mut reader, &mut sink);
    output.binary = reader.binary;
    output.non_utf8 = reader.non_utf8 || reader.tail_len > 0;
    output.complete = result.is_ok() && reader.eof;
    let hash = reader
        .eof
        .then(|| ContentHash(*reader.hash.finalize().as_bytes()));
    let lexical = reader.lexical.take().map(lexical::Counter::finish);
    drop(reader);
    output.stale_index = hash
        .zip(request.pointer.content_hash)
        .is_some_and(|(live, indexed)| live != indexed);
    let after = file.identity()?;
    output.changed = before != after || !file.validate_path()?;
    if let Err(error) = result {
        output.time_limited = error.kind() == io::ErrorKind::TimedOut;
        output.line_limited = error.to_string().contains("configured allocation limit")
            || error.to_string().contains("heap limit");
        // Work/line-buffer limits are explicit incompleteness; actual source IO
        // remains a typed source failure instead of a successful empty result.
        if error.kind() != io::ErrorKind::TimedOut
            && !error.to_string().contains("configured allocation limit")
            && !error.to_string().contains("heap limit")
        {
            return Err(se_types::SeError::new(
                se_types::Detail::AtlasSourceUnreadable(se_types::details::AtlasSourceUnreadable {
                    path: request.pointer.path.as_str().into(),
                    reason: error.to_string(),
                }),
            ));
        }
    }
    if output.binary || output.non_utf8 || output.changed {
        output.complete = false;
        return Ok(output);
    }
    // Only complete, stable text files contribute corpus statistics. Partial
    // matches remain labelled incomplete and carry no invented lexical score.
    output.lexical = output.complete.then_some(lexical).flatten();
    output.omitted_matches = sink.omitted;
    for (span, text, _) in &sink.items {
        file.seek(SeekFrom::Start(span.start_byte))
            .map_err(|e| se_types::SeError::invalid("Atlas source verification", &e.to_string()))?;
        let mut again = vec![0; text.len()];
        file.read_exact(&mut again)
            .map_err(|e| se_types::SeError::invalid("Atlas source verification", &e.to_string()))?;
        if again != text.as_bytes() || file.identity()? != before || !file.validate_path()? {
            output.changed = true;
            output.complete = false;
            return Ok(output);
        }
    }
    for (span, text, complete) in sink.items {
        let mut pointer = request.pointer.clone();
        pointer.span = Some(span);
        pointer.content_hash = hash;
        pointer.freshness = if output.stale_index {
            SnapshotFreshness::Stale
        } else {
            SnapshotFreshness::Unknown
        };
        let body = HitBody::new(
            BodyOrigin::LiveSource {
                file: pointer.file,
                path: pointer.path.clone(),
                span,
                range_hash: ContentHash(*blake3::hash(text.as_bytes()).as_bytes()),
                content_hash: hash,
                matches_index: hash.zip(request.pointer.content_hash).map(|(a, b)| a == b),
            },
            text.clone(),
            complete,
        )?;
        output.hits.push((
            CodeHit {
                pointer,
                symbol: None,
                name: excerpt(&text, 160),
                kind: None,
                method: FindMethod::Text,
                accuracy: None,
            },
            body,
        ));
    }
    Ok(output)
}
struct Matches<'a, 'b> {
    request: &'a TextRequest<'b>,
    matcher: &'a RegexMatcher,
    items: Vec<(Span, String, bool)>,
    omitted: u64,
}
impl Sink for Matches<'_, '_> {
    type Error = io::Error;
    fn matched(&mut self, _: &grep_searcher::Searcher, found: &SinkMatch<'_>) -> io::Result<bool> {
        if Instant::now() >= self.request.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Atlas text deadline",
            ));
        }
        if self.items.len() == self.request.max_matches {
            self.omitted += 1;
            return Ok(true);
        }
        let text = match std::str::from_utf8(found.bytes()) {
            Ok(v) => v.trim_end_matches(['\r', '\n']),
            Err(_) => return Ok(true),
        };
        let matched = self
            .matcher
            .find(text.as_bytes())
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::other("matched source line no longer matches"))?;
        let mut start = matched.start().saturating_sub(40);
        while !text.is_char_boundary(start) {
            start -= 1;
        }
        let mut end = text
            .len()
            .min(start + if self.request.full { 12 * 1024 } else { 160 });
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let complete = start == 0 && end == text.len();
        let text = &text[start..end];
        let line = u32::try_from(found.line_number().unwrap_or(1))
            .map_err(|_| io::Error::other("source line exceeds position range"))?;
        let span = Span {
            start: Position {
                line,
                byte_column: start as u32,
            },
            end: Position {
                line,
                byte_column: (start + text.len()) as u32,
            },
            start_byte: found.absolute_byte_offset() + start as u64,
            end_byte: found.absolute_byte_offset() + (start + text.len()) as u64,
        };
        self.items.push((span, text.into(), complete));
        Ok(true)
    }
}

fn excerpt(text: &str, limit: usize) -> String {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].into()
}
