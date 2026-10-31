use super::*;
impl SqliteSnapshot {
    pub(super) fn page<T>(
        &self,
        items: Vec<T>,
        budget: &ReadBudget,
        binding: &str,
        h: u64,
        after: u64,
        last: u64,
        more: bool,
        bytes: u64,
        stop: StopReason,
    ) -> StoreResult<Page<T>> {
        let next = if more {
            Some(self.cursor(binding, h, last)?)
        } else {
            None
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
            end_cursor: next.clone(),
            returned: items.len() as u64,
            limit: budget.page.limit,
            bytes,
            max_bytes: budget.page.max_bytes,
            omitted_before: Omission::None,
            omitted_after: if more {
                Omission::Unknown {
                    reason: if stop == StopReason::ItemLimit {
                        OmissionReason::Limit
                    } else {
                        OmissionReason::Budget
                    },
                }
            } else {
                Omission::None
            },
            unreadable: 0,
            stop_reason: stop,
        })
        .map_err(invalid)?;
        Page::new(items, window, next).map_err(invalid)
    }
    pub(super) fn cursor(&self, binding: &str, h: u64, after: u64) -> StoreResult<Cursor> {
        // Encoded internal coordinates have no public numeric interpretation.
        let raw = codec::encode(&(
            self.info.id.as_str(),
            self.info.incarnation,
            binding,
            h,
            after,
        ))?;
        Cursor::new(
            raw.as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
        .map_err(invalid)
    }
    pub(super) fn window(
        &self,
        budget: &ReadBudget,
        binding: &str,
        live: bool,
    ) -> StoreResult<(u64, u64)> {
        if budget.page.limit.get() > 1000
            || budget.page.max_bytes.get() > 2 * 1024 * 1024
            || budget.deadline.is_zero()
        {
            return Err(fail(
                StoreErrorCode::ReadBudgetTooSmall,
                "page needs limit 1..1000, bytes 1..2MiB, and a finite nonzero deadline",
            ));
        }
        let h = self
            .info
            .head
            .as_ref()
            .map(StorePosition::sequence)
            .unwrap_or(0);
        let Some(cursor) = &budget.page.after else {
            return Ok((h, 0));
        };
        let mut bytes = Vec::new();
        for pair in cursor.as_str().as_bytes().chunks(2) {
            if pair.len() != 2 {
                return Err(fail(StoreErrorCode::CursorInvalid, "malformed cursor"));
            }
            let s = std::str::from_utf8(pair).map_err(invalid)?;
            bytes.push(u8::from_str_radix(s, 16).map_err(invalid)?)
        }
        let (store, inc, query, prior, last): (String, u64, String, u64, u64) =
            serde_json::from_slice(&bytes)
                .map_err(|_| fail(StoreErrorCode::CursorInvalid, "cursor cannot be decoded"))?;
        if store != self.info.id.as_str() || inc != self.info.incarnation {
            return Err(fail(
                StoreErrorCode::CursorStale,
                "cursor store/incarnation changed",
            ));
        }
        if query != binding || last > prior || prior > h {
            return Err(fail(
                StoreErrorCode::CursorInvalid,
                "cursor scope/query/window mismatch",
            ));
        }
        Ok((if live { h } else { prior }, last))
    }
}
