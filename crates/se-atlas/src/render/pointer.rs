//! Target extents let callers choose a bounded read without embedding source.
use super::*;

pub(super) fn location(path: &RelativePath, span: Option<Span>) -> String {
    let mut output = escape(path.as_str());
    if let Some(span) = span {
        // Ends are exclusive: an end at column zero is on the next line.
        let last = if span.end.byte_column == 0 && span.end.line > span.start.line {
            span.end.line - 1
        } else {
            span.end.line
        };
        output.push_str(&format!(":{}", span.start.line));
        if last > span.start.line {
            output.push_str(&format!("-{last}"));
        }
        output.push_str(&format!(" ({} B)", span.end_byte - span.start_byte));
    } else {
        output.push_str(" (size unavailable)");
    }
    output
}

pub(super) fn pointer(value: &CodePointer) -> String {
    let mut output = location(&value.path, value.span);
    output.push_str(match value.freshness {
        SnapshotFreshness::Current => "",
        SnapshotFreshness::Stale => " [stale]",
        SnapshotFreshness::Unknown => " [unverified revision]",
    });
    output
}
