//! Search mode selection shares one finite source-scan deadline.
use super::*;
impl QueryReader<'_> {
    pub(super) fn find_text(&self, query: &FindQuery) -> AtlasResult<Answer<Read<SearchResults>>> {
        deadline(query.budget)?;
        let end = Instant::now() + Duration::from_secs(1);
        let initial = query.mode.unwrap_or_else(|| {
            if query.regex || query.kind == SearchKind::Text {
                SearchMode::Literal
            } else {
                super::modes::automatic(query.query.as_str())
            }
        });
        let resumed = query
            .next
            .as_ref()
            .map(PositionCursor::decode)
            .transpose()?;
        let mut mode = resumed
            .as_ref()
            .map(|p| super::modes::from_key(p.last_key.integers.get(5)))
            .transpose()?
            .unwrap_or(initial);
        loop {
            let answer = self.text_mode(query, mode, initial, end)?;
            if let Read::Present { value } = &answer.data {
                if query.mode.is_some()
                    || query.regex
                    || query.next.is_some()
                    || !value.page.items().is_empty()
                    || value.page.next().is_some()
                    || Instant::now() >= end - super::text::FINALIZE_ALLOWANCE
                {
                    return Ok(answer);
                }
            } else {
                return Ok(answer);
            }
            mode = match mode {
                SearchMode::Exact => SearchMode::Literal,
                SearchMode::Literal | SearchMode::Phrase => SearchMode::Broad,
                SearchMode::Broad => SearchMode::Related,
                SearchMode::Related => return Ok(answer),
            };
        }
    }
}
