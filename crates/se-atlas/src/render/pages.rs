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
    complete: bool,
    next: Option<&AtlasCursor>,
    max: usize,
) -> AtlasResult<String> {
    if !complete {
        output.push_str("[partial; inspect coverage or narrow the query]\n");
    }
    if let Some(next) = next {
        output.push_str(&format!("more: {}\n", next.as_str()));
    }
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
    let mut output = state(&answer.index);
    let value = match available(&answer.data) {
        Ok(value) => value,
        Err(text) => {
            output.push_str(&text);
            return finish(output, true, None, max);
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
    let mut output = state(&answer.index);
    let value = match available(&answer.data) {
        Ok(value) => value,
        Err(text) => {
            output.push_str(&text);
            return finish(output, true, None, max);
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
            for hop in &dependent.hops {
                output.push_str(&format!(" → {} ({:?})", pointer(&hop.site), hop.accuracy));
            }
            for hop in &dependent.file_hops {
                output.push_str(&format!(
                    " → {} bytes {}..{} ({:?})",
                    pointer(&hop.site),
                    hop.start_byte,
                    hop.end_byte,
                    hop.accuracy
                ));
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
    finish(output, value.complete, value.next.as_ref(), max)
}
pub fn changes(answer: &Answer<Read<Page<CodeChange>>>, max: usize) -> AtlasResult<String> {
    let mut output = state(&answer.index);
    let value = match available(&answer.data) {
        Ok(value) => value,
        Err(text) => {
            output.push_str(&text);
            return finish(output, true, None, max);
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
    let mut output = state(&answer.index);
    let value = match available(&answer.data) {
        Ok(value) => value,
        Err(text) => {
            output.push_str(&text);
            return finish(output, true, None, max);
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
    finish(output, value.complete, value.next.as_ref(), max)
}
