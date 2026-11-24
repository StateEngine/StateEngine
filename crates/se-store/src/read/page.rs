use super::*;
pub(super) struct PageFacts {
    pub h: u64,
    pub after: u64,
    pub last: u64,
    pub bytes: u64,
    pub stop: StopReason,
    pub remaining: Option<u64>,
}
pub(super) struct PageCollect<'a> {
    pub budget: &'a ReadBudget,
    pub binding: &'a str,
    pub h: u64,
    pub after: u64,
    pub deadline: Instant,
    pub oversize_cause: &'static str,
}
pub(super) fn collect_page_rows<R, T, F>(
    rows: Vec<R>,
    budget: &ReadBudget,
    after: u64,
    deadline: Instant,
    oversize_cause: &'static str,
    mut load: F,
) -> StoreResult<(Vec<T>, u64, u64, StopReason)>
where
    F: FnMut(R) -> StoreResult<(T, u64, u64)>,
{
    let mut items = Vec::new();
    let mut bytes = 0u64;
    let mut last = after;
    let mut stop = StopReason::Exhausted;
    for row in rows {
        query::check_deadline(deadline)?;
        if items.len() == budget.page.limit.get() as usize {
            stop = StopReason::ItemLimit;
            break;
        }
        let (item, cost, cursor) = load(row)?;
        if bytes + cost > u64::from(budget.page.max_bytes.get()) {
            if items.is_empty() {
                return Err(query::budget_failure(budget, cost, oversize_cause));
            }
            stop = StopReason::ByteLimit;
            break;
        }
        bytes += cost;
        last = cursor;
        items.push(item);
    }
    query::check_deadline(deadline)?;
    Ok((items, bytes, last, stop))
}
impl SqliteSnapshot {
    pub(super) fn collect_page<R, T, F>(
        &self,
        rows: Vec<R>,
        spec: PageCollect<'_>,
        load: F,
    ) -> StoreResult<Page<T>>
    where
        F: FnMut(R) -> StoreResult<(T, u64, u64)>,
    {
        let (items, bytes, last, stop) = collect_page_rows(
            rows,
            spec.budget,
            spec.after,
            spec.deadline,
            spec.oversize_cause,
            load,
        )?;
        self.page(
            items,
            spec.budget,
            spec.binding,
            PageFacts {
                h: spec.h,
                after: spec.after,
                last,
                bytes,
                stop,
                remaining: None,
            },
        )
    }
    /// The window source for rows read from this store and admitted scope.
    pub(super) fn store_source(&self) -> Source {
        let project = match &self.scope.admission.scope {
            Scope::Project(p) => Some(p.clone()),
            _ => None,
        };
        Source::Store {
            store: self.info.id.clone(),
            project,
        }
    }
    pub(super) fn page<T>(
        &self,
        items: Vec<T>,
        budget: &ReadBudget,
        binding: &str,
        facts: PageFacts,
    ) -> StoreResult<Page<T>> {
        self.page_with_unreadable(items, budget, binding, facts, 0)
    }
    pub(super) fn page_with_unreadable<T>(
        &self,
        items: Vec<T>,
        budget: &ReadBudget,
        binding: &str,
        facts: PageFacts,
        unreadable: u64,
    ) -> StoreResult<Page<T>> {
        let PageFacts {
            h,
            after,
            last,
            bytes,
            stop,
            remaining,
        } = facts;
        let more = stop != StopReason::Exhausted;
        let observed = Some(self.cursor(binding, h, last)?);
        let next = if more { observed.clone() } else { None };
        let omission = if !more {
            Omission::None
        } else if let Some(count) = remaining {
            Omission::Known {
                count: std::num::NonZeroU64::new(count).ok_or_else(|| {
                    fail(
                        StoreErrorCode::ProjectionInconsistent,
                        "lookahead found a row but the exact remaining count is zero",
                    )
                })?,
                reason: if stop == StopReason::ItemLimit {
                    OmissionReason::Limit
                } else {
                    OmissionReason::Budget
                },
            }
        } else {
            Omission::Unknown {
                reason: if stop == StopReason::ItemLimit {
                    OmissionReason::Limit
                } else {
                    OmissionReason::Budget
                },
            }
        };
        let window = Window::new(WindowFields {
            source: self.store_source(),
            from: Sequence::new(after).map_err(invalid)?,
            to: Sequence::new(h).map_err(invalid)?,
            start_cursor: budget.page.after.clone(),
            end_cursor: observed,
            returned: items.len() as u64,
            limit: budget.page.limit,
            bytes,
            max_bytes: budget.page.max_bytes,
            omitted_before: Omission::None,
            omitted_after: omission,
            unreadable,
            stop_reason: stop,
        })
        .map_err(invalid)?;
        Page::new(items, window, next).map_err(invalid)
    }
}
