//! Fit verified search results and their continuations as one response.
use super::*;

// Verification can add pointer spans before fitting. This limit belongs only
// to the temporary producer window; the final page restores the caller's limit.
pub(super) fn staging_budget(budget: QueryBudget) -> QueryBudget {
    QueryBudget {
        max_bytes: u32::MAX,
        ..budget
    }
}

pub(super) struct SearchPage {
    pub answer: Answer<Read<SearchResults>>,
    /// One full continuation key per hit, in the emitted order.
    pub keys: Vec<Key>,
    pub continuation: Option<PositionCursor>,
}
impl SearchPage {
    pub fn finish(
        self,
        reader: &QueryReader<'_, '_, '_>,
        query: &FindQuery,
        end: Instant,
    ) -> AtlasResult<Answer<Read<SearchResults>>> {
        let mut answer = super::freshness::verify(reader, self.answer, end)?;
        let mut keys = self.keys;
        let mut continuation = self.continuation;
        let budget = QueryBudget {
            max_bytes: if query.full {
                query.budget.max_bytes.min(12 * 1024)
            } else {
                query.budget.max_bytes
            },
            ..query.budget
        };
        loop {
            let bytes = embedded_size(&answer)?;
            let compact_fits = reader.ctx.compact.is_none_or(|(bytes, explain)| {
                crate::render::search(&answer, bytes.saturating_sub(256), explain)
                    .and_then(|text| size(&text))
                    .is_ok_and(|size| size <= bytes.saturating_sub(192))
            });
            if bytes <= budget.max_bytes as usize && compact_fits {
                if let Read::Present { mut value } = answer.data {
                    let mut fields = value
                        .page
                        .window()
                        .fields()
                        .cloned()
                        .ok_or_else(|| cache_error("query producer window is absent"))?;
                    fields.max_bytes = NonZeroU32::new(budget.max_bytes)
                        .ok_or_else(|| cache_error("zero byte limit"))?;
                    let next = value.page.next().cloned();
                    value.page = Page::new(value.page.into_items(), Window::new(fields)?, next)?;
                    value.validate()?;
                    answer.data = Read::Present { value };
                }
                return check_output(answer, budget);
            }
            let Read::Present { value: mut output } = answer.data else {
                return Err(cache_error("search response lost its observed results"));
            };
            let mut fields = output
                .page
                .window()
                .fields()
                .cloned()
                .ok_or_else(|| cache_error("query producer window is absent"))?;
            let mut items = output.page.into_items();
            if !shrink(&mut items, &mut keys, &mut output.bodies_omitted) {
                return Err(capacity(
                    "Atlas search response bytes",
                    bytes as u64,
                    u64::from(budget.max_bytes),
                ));
            }
            let position = continuation
                .as_mut()
                .ok_or_else(|| cache_error("missing search continuation"))?;
            position.last_key = keys
                .last()
                .cloned()
                .ok_or_else(|| cache_error("missing search continuation key"))?;
            let next = Some(wire_cursor(&position.encode()?)?);
            fields.end_cursor = next.clone();
            fields.stop_reason = StopReason::ByteLimit;
            if !matches!(
                fields.omitted_after,
                Omission::Unknown {
                    reason: OmissionReason::SourceIncomplete
                }
            ) {
                fields.omitted_after = Omission::Unknown {
                    reason: OmissionReason::Budget,
                };
            }
            fields.returned = items.len() as u64;
            fields.bytes = items.iter().try_fold(0usize, |sum, hit| {
                Ok::<_, se_types::SeError>(sum + size(hit)?)
            })? as u64;
            output.page = Page::new(items, Window::new(fields)?, next)?;
            answer.data = Read::Present { value: output };
        }
    }
}

fn shrink(items: &mut Vec<SearchHit>, keys: &mut Vec<Key>, omitted: &mut u16) -> bool {
    let single = items.len() == 1;
    if let Some(hit) = items.iter_mut().rev().find(|hit| hit.body.is_some()) {
        if single && hit.body.as_mut().is_some_and(clip_body) {
            return true;
        }
        hit.body = None;
        *omitted += 1;
        return true;
    }
    if items.len() > 1 {
        items.pop();
        keys.pop();
        return true;
    }
    items.first_mut().is_some_and(clip_hit)
}

// JSON transports embed the answer in a string. Count those escapes without
// allocating a second copy; JSON's writer already escapes literal controls.
fn embedded_size(value: &impl Serialize) -> AtlasResult<usize> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len()
                + bytes
                    .iter()
                    .filter(|&&byte| matches!(byte, b'"' | b'\\'))
                    .count();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(2);
    serde_json::to_writer(&mut counter, value).map_err(cache_error)?;
    Ok(counter.0)
}
fn clip_hit(hit: &mut SearchHit) -> bool {
    let text = match &mut hit.target {
        HitTarget::Code(code) => &mut code.name,
        HitTarget::Record(record) => {
            record.body_truncated = true;
            &mut record.line
        }
        HitTarget::Commit(commit) => {
            if !clip_text(&mut commit.subject) {
                return clip_text(&mut commit.author);
            }
            return true;
        }
    };
    clip_text(text)
}
fn clip_text(text: &mut String) -> bool {
    const MARKER: &str = " [truncated]";
    if text.len() <= MARKER.len() {
        return false;
    }
    let mut end =
        (text.strip_suffix(MARKER).unwrap_or(text).len() / 2).min(text.len() - MARKER.len() - 1);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push_str(MARKER);
    true
}
fn clip_body(body: &mut HitBody) -> bool {
    if body.text.is_empty() {
        return false;
    }
    let mut end = body.text.len() / 2;
    while !body.text.is_char_boundary(end) {
        end -= 1;
    }
    body.text.truncate(end);
    body.complete = false;
    if let BodyOrigin::LiveSource {
        span, range_hash, ..
    } = &mut body.origin
    {
        let lines = body.text.bytes().filter(|byte| *byte == b'\n').count() as u32;
        span.end.line = span.start.line + lines;
        span.end.byte_column = if lines == 0 {
            span.start.byte_column + body.text.len() as u32
        } else {
            body.text.rsplit('\n').next().map_or(0, |line| line.len()) as u32
        };
        span.end_byte = span.start_byte + body.text.len() as u64;
        *range_hash = ContentHash(*blake3::hash(body.text.as_bytes()).as_bytes());
    }
    true
}
