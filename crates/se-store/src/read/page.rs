use super::*;
pub(super) struct PageFacts {
    pub h: u64,
    pub after: u64,
    pub last: u64,
    pub bytes: u64,
    pub stop: StopReason,
    pub remaining: Option<u64>,
}
impl SqliteSnapshot {
    pub(super) fn page<T>(
        &self,
        items: Vec<T>,
        budget: &ReadBudget,
        binding: &str,
        facts: PageFacts,
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
            source: Source::Store {
                store: self.info.id.clone(),
                project: match &self.scope.admission.scope {
                    Scope::Project(p) => Some(p.clone()),
                    _ => None,
                },
            },
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
            unreadable: 0,
            stop_reason: stop,
        })
        .map_err(invalid)?;
        Page::new(items, window, next).map_err(invalid)
    }
}
