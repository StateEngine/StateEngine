//! Production streaming reader checks, including response-budget continuations.
use crate::fixture::present;
use se_atlas::query::QueryReader;
use se_types::code::*;
#[expect(
    clippy::cognitive_complexity,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub fn check(
    reader: &QueryReader<'_>,
    late_reader: &QueryReader<'_>,
    query: &FindQuery,
) -> Result<FindQuery, Box<dyn std::error::Error>> {
    let mut text = query.clone();
    text.kind = SearchKind::Text;
    text.mode = Some(SearchMode::Literal);
    text.query = QueryText::new("caller")?;
    let hits = present(reader.find(&text)?.data)?;
    assert_eq!(hits.page.items().len(), 1);
    assert!(hits.page.items()[0].body.is_none());
    let stats = hits.text.as_ref().ok_or("missing text scan counts")?;
    assert_eq!(stats.scanned_files, 40);
    assert_eq!(stats.binary_files, 1);
    assert_eq!(stats.non_utf8_files, 1);
    assert_eq!(stats.oversized_files, 1);
    text.query = QueryText::new("late_line_marker")?;
    let hits = present(reader.find(&text)?.data)?;
    assert_eq!(hits.page.items().len(), 1);
    assert!(
        matches!(&hits.page.items()[0].target,HitTarget::Code(code) if code.pointer.span.is_some_and(|s|s.start_byte>512*1024)&&code.pointer.content_hash.is_some()&&hits.page.items()[0].reason.text_only)
    );
    // The normal mixed/code entry points search source past the parser cap too.
    let mut unified = text.clone();
    unified.mode = None;
    for kind in [SearchKind::All, SearchKind::Code] {
        unified.kind = kind;
        let page = present(reader.find(&unified)?.data)?;
        assert!(page.page.items().iter().any(|hit| matches!(&hit.target, HitTarget::Code(code) if code.pointer.path.as_str() == "large.txt")));
    }
    unified.query = QueryText::new("line_mark")?;
    let fallback = present(reader.find(&unified)?.data)?;
    assert_eq!(fallback.mode, SearchMode::Literal);
    assert_eq!(fallback.fallback_from, Some(SearchMode::Exact));
    text.mode = Some(SearchMode::Broad);
    text.query = QueryText::new("why late_line_marker was emitted")?;
    assert_eq!(present(reader.find(&text)?.data)?.page.items().len(), 1);
    text.mode = Some(SearchMode::Phrase);
    text.query = QueryText::new("fn     alpha")?;
    assert_eq!(present(reader.find(&text)?.data)?.page.items().len(), 1);
    text.mode = Some(SearchMode::Exact);
    text.query = QueryText::new("all")?;
    assert!(present(reader.find(&text)?.data)?.page.items().is_empty());
    text.mode = Some(SearchMode::Literal);
    assert_eq!(present(reader.find(&text)?.data)?.page.items().len(), 1);
    text.query = QueryText::new("alpha")?;
    text.budget = Validate.query_budget(10, 16384)?;
    let lines = present(reader.find(&text)?.data)?;
    assert_eq!(
        lines.page.items().len(),
        3,
        "multiple matching source lines were silently dropped"
    );

    // The full envelope repeats the cursor in several fields. Each bounded
    // page must fit with that overhead and continue without losing a line.
    text.budget = Validate.query_budget(10, 4096)?;
    let mut seen = Vec::new();
    for page in 0..8 {
        // A different host clock on resume must not move time-decayed keys.
        let clock = if page == 0 { reader } else { late_reader };
        let answer = clock.find(&text)?;
        assert!(serde_json::to_vec(&answer)?.len() <= 4096);
        let results = present(answer.data)?;
        for hit in results.page.items() {
            assert!(
                !seen.contains(&hit.target),
                "text continuation repeated a hit"
            );
            seen.push(hit.target.clone());
        }
        let Some(next) = results.page.next() else {
            break;
        };
        text.next = Some(AtlasCursor::new(next.as_str())?);
    }
    assert_eq!(seen.len(), 3, "budget trimming lost a matching source line");
    text.next = None;
    text.budget = Validate.query_budget(10, 16384)?;
    Ok(text)
}
