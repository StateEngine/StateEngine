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
            let bytes = size(&answer)?;
            let compact_fits = reader.ctx.compact.is_none_or(|(bytes, explain)| {
                crate::render::search(&answer, bytes, explain).is_ok()
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
            let mut next = output.page.next().cloned();
            let mut items = output.page.into_items();
            if let Some(hit) = items.iter_mut().rev().find(|hit| hit.body.is_some()) {
                hit.body = None;
                output.bodies_omitted += 1;
            } else {
                if items.len() <= 1 {
                    return Err(capacity(
                        "Atlas search response bytes",
                        bytes as u64,
                        u64::from(budget.max_bytes),
                    ));
                }
                items.pop();
                keys.pop();
                let position = continuation
                    .as_mut()
                    .ok_or_else(|| cache_error("missing search continuation"))?;
                position.last_key = keys
                    .last()
                    .cloned()
                    .ok_or_else(|| cache_error("missing search continuation key"))?;
                next = Some(wire_cursor(&position.encode()?)?);
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
