//! Compact graph/history pages retain coverage and continuation labels.
use super::*;
use se_types::Page;
fn record(value: &RecordHit) -> String {
    format!(
        "{:?} {} \"{}\"",
        value.pointer.kind,
        escape(value.pointer.key.as_str()),
        escape(&value.line)
    )
}
fn coverage(value: &FileCoverage) -> String {
    match value {
        FileCoverage::Indexed => "indexed".into(),
        FileCoverage::Partial { reasons } => format!("partial: {reasons:?}"),
        FileCoverage::Deferred { reason } => format!("deferred: {reason:?}"),
        FileCoverage::Failed { error } => format!("failed: {}", escape(&error.message())),
        FileCoverage::Stale {
            reason,
            last_good_generation,
            diagnostic,
            ..
        } => {
            let mut text = format!(
                "stale: {reason:?}; last good generation {}",
                last_good_generation.0
            );
            if let Some(error) = diagnostic {
                text.push_str(&format!("; {}", escape(&error.message())));
            }
            text
        }
    }
}
fn available<T>(value: &Read<T>) -> std::result::Result<&T, String> {
    match value {
        Read::Present { value } => Ok(value),
        Read::Absent { checked } => Err(format!("absent: {}\n", escape(checked))),
        Read::Unknown { what } => Err(format!("unknown: {}\n", escape(what))),
        Read::Unreadable { source, reason, .. } => Err(format!(
            "unreadable {}: {}\n",
            escape(source),
            escape(reason)
        )),
    }
}
fn finish(
    mut output: String,
    index: &IndexSummary,
    complete: bool,
    next: Option<&AtlasCursor>,
    max: usize,
) -> AtlasResult<String> {
    if output.is_empty() {
        output.push_str(none(complete));
    } else if !complete {
        output.push_str("[partial; inspect coverage or narrow the query]\n");
    }
    if let Some(next) = next {
        output.push_str(&format!("more: {}\n", next.as_str()));
    }
    output.push_str(&footer(index));
    if output.len() > max {
        return Err(capacity(
            "Atlas compact response bytes",
            output.len() as u64,
            max as u64,
        ));
    }
    Ok(output)
}
pub fn refs(answer: &Answer<Read<Page<ReferenceHit>>>, max: usize) -> AtlasResult<String> {
    let mut output = String::new();
    let value = match available(&answer.data) {
        Ok(value) => value,
        Err(text) => {
            output.push_str(&text);
            return finish(output, &answer.index, true, None, max);
        }
    };
    for hit in value.items() {
        let line = match hit {
            ReferenceHit::Code(site) => format!(
                "{} {:?} {} · {:?}",
                pointer(&site.site),
                site.kind,
                escape(&site.spelling),
                site.accuracy
            ),
            ReferenceHit::Record(hit) => record(hit),
        };
        output.push_str(&line);
        output.push('\n');
    }
    finish(
        output,
        &answer.index,
        value.window().complete(),
        value
            .next()
            .map(|c| c.as_str())
            .map(AtlasCursor::new)
            .transpose()?
            .as_ref(),
        max,
    )
}
pub fn impact(answer: &Answer<Read<Impact>>, max: usize) -> AtlasResult<String> {
    let mut output = String::new();
    let value = match available(&answer.data) {
        Ok(value) => value,
        Err(text) => {
            output.push_str(&text);
            return finish(output, &answer.index, true, None, max);
        }
    };
    for (is_test, items) in [(false, &value.dependents), (true, &value.tests)] {
        for dependent in items {
            output.push_str(&format!(
                "{} · {} hop{}{}",
                pointer(&dependent.pointer),
                dependent.hops.len() + dependent.file_hops.len(),
                if dependent.hops.len() + dependent.file_hops.len() == 1 {
                    ""
                } else {
                    "s"
                },
                if is_test { " · possible test" } else { "" }
            ));
            let hops = dependent.hops.iter().map(|h| (&h.site, 0, 0, h.accuracy));
            let files = dependent
                .file_hops
                .iter()
                .map(|h| (&h.site, h.start_byte, h.end_byte, h.accuracy));
            for (site, start, end, accuracy) in hops.chain(files) {
                // A site that only repeats the dependent's own pointer adds nothing.
                if *site != dependent.pointer {
                    output.push_str(&format!(" → {}", pointer(site)));
                }
                if end > start {
                    output.push_str(&format!(" bytes {start}..{end}"));
                }
                output.push_str(&format!(" ({accuracy:?})"));
            }
            output.push('\n');
        }
    }
    for hit in &value.records {
        output.push_str(&record(hit));
        output.push('\n');
    }
    if !value.frontier_count_complete {
        output.push_str("[additional frontier count unknown]\n");
    } else if value.omitted_frontier > 0 {
        output.push_str(&format!(
            "[{} frontier nodes omitted]\n",
            value.omitted_frontier
        ));
    }
    finish(
        output,
        &answer.index,
        value.complete,
        value.next.as_ref(),
        max,
    )
}
pub fn changes(answer: &Answer<Read<Page<CodeChange>>>, max: usize) -> AtlasResult<String> {
    let mut output = String::new();
    let value = match available(&answer.data) {
        Ok(value) => value,
        Err(text) => {
            output.push_str(&text);
            return finish(output, &answer.index, true, None, max);
        }
    };
    for change in value.items() {
        match change {
            CodeChange::Edit(edit) => {
                let author = match &edit.author {
                    AuthorHint::Captured { agent, .. } => format!("captured agent {agent}"),
                    AuthorHint::Mixed { .. } => "mixed attribution".into(),
                    AuthorHint::Unknown => "unattributed".into(),
                };
                output.push_str(&format!(
                    "{} {:?} · {author}{}\n",
                    pointer(&edit.pointer),
                    edit.kind,
                    if edit.baseline_reset {
                        " · baseline reset"
                    } else {
                        ""
                    }
                ));
            }
            CodeChange::Bulk(bulk) => output.push_str(&format!(
                "repository activity: {} files · {:?}{}\n",
                bulk.files,
                bulk.reason,
                if bulk.complete { "" } else { " · incomplete" }
            )),
        }
    }
    finish(
        output,
        &answer.index,
        value.window().complete(),
        value
            .next()
            .map(|c| c.as_str())
            .map(AtlasCursor::new)
            .transpose()?
            .as_ref(),
        max,
    )
}
pub fn outline(answer: &Answer<Read<Outline>>, max: usize) -> AtlasResult<String> {
    let mut output = String::new();
    let value = match available(&answer.data) {
        Ok(value) => value,
        Err(text) => {
            output.push_str(&text);
            return finish(output, &answer.index, true, None, max);
        }
    };
    output.push_str(&format!(
        "{} · {}\n",
        pointer(&value.file),
        coverage(&value.coverage)
    ));
    for symbol in &value.symbols {
        output.push_str(&format!(
            "{} {:?} {}\n",
            location(&value.file.path, Some(symbol.span)),
            symbol.kind,
            escape(&symbol.name)
        ));
    }
    for hit in &value.records {
        output.push_str(&record(hit));
        output.push('\n');
    }
    finish(
        output,
        &answer.index,
        value.complete,
        value.next.as_ref(),
        max,
    )
}
/// Bytes each inspect section reserves for its heading.
pub const INSPECT_HEADING: usize = 48;
/// Inspect's sections in order, each rendered inside its byte share with its
/// own coverage footer and continuation, so a gap in one never hides in
/// another. A section that still overflows its share says so in its place.
pub fn inspect(
    outline_answer: &Answer<Read<Outline>>,
    refs_answer: &Answer<Read<Page<ReferenceHit>>>,
    impact_answer: &Answer<Read<Impact>>,
    changes_answer: &Answer<Read<Page<CodeChange>>>,
    shares: [usize; 4],
) -> AtlasResult<String> {
    let room = |share: usize| share.saturating_sub(INSPECT_HEADING);
    let fitted = |rendered: AtlasResult<String>, share: usize, command: &str| match rendered {
        Err(error)
            if matches!(
                error.body.detail(),
                se_types::Detail::AtlasResourceBudget(_)
            ) =>
        {
            Ok(format!(
                "[over this section's {share}-byte share; page it with se atlas {command}, or raise byte_budget]\n"
            ))
        }
        other => other,
    };
    Ok(format!(
        "# outline\n{}# callers and references\n{}# dependents, tests and linked records\n{}# recent edits, last 7 days\n{}",
        fitted(
            outline(outline_answer, room(shares[0])),
            shares[0],
            "outline"
        )?,
        fitted(refs(refs_answer, room(shares[1])), shares[1], "refs")?,
        fitted(impact(impact_answer, room(shares[2])), shares[2], "impact")?,
        fitted(
            changes(changes_answer, room(shares[3])),
            shares[3],
            "changes"
        )?,
    ))
}
