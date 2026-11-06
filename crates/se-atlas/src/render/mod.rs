//! Compact text is budgeted as UTF-8 and escapes source/record terminal controls.
mod pages;
mod pointer;
use crate::{
    errors::{AtlasResult, capacity},
    model::*,
};
pub use pages::{changes, impact, outline, refs};
use pointer::{location, pointer};
use se_types::{Read, code::*};
pub fn escape(text: &str) -> String {
    let mut output = String::new();
    for c in text.chars() {
        if c.is_control() {
            output.extend(c.escape_default());
        } else {
            output.push(c);
        }
    }
    output
}
pub fn search(
    answer: &Answer<Read<SearchResults>>,
    max_bytes: usize,
    explain: bool,
) -> AtlasResult<String> {
    let mut output = state(&answer.index);
    match &answer.data {
        Read::Present { value } => {
            if let Some(previous) = value.fallback_from {
                output.push_str(&format!(
                    "[{previous:?}: 0 hits → {:?}: {}]\n",
                    value.mode,
                    value.page.items().len()
                ));
            } else {
                output.push_str(&format!("[{:?}]\n", value.mode));
            }
            let mut bodies = 0;
            for hit in value.page.items() {
                output.push_str(&hit_line(hit));
                output.push('\n');
                if let Some(body) = &hit.body {
                    bodies += body.text.len();
                    if bodies > 12 * 1024 {
                        return Err(capacity(
                            "Atlas full-body response",
                            bodies as u64,
                            12 * 1024,
                        ));
                    }
                    output.push_str(&escape(&body.text));
                    output.push('\n');
                    if !body.complete {
                        output.push_str("[body incomplete]\n");
                    }
                }
            }
            if let Some(next) = value.page.next() {
                output.push_str(&format!("more: {}\n", next.as_str()));
            }
            if !value.page.window().complete() {
                output.push_str("[partial; inspect coverage or narrow the query]\n");
            }
            if value.bodies_omitted > 0 {
                output.push_str(&format!(
                    "[{} bodies unavailable or omitted for the response budget]\n",
                    value.bodies_omitted
                ));
            }
            if let Some(stats) = &value.text {
                output.push_str(&format!("[text: {} files scanned; skipped {} binary, {} non-UTF-8, {} oversized, {} changed, {} unavailable; {} matches omitted]\n",stats.scanned_files,stats.binary_files,stats.non_utf8_files,stats.oversized_files,stats.changed_files,stats.unavailable_files,stats.omitted_matches));
            }
            if explain {
                output.push_str(&format!(
                    "rank_version: {}; truncated candidates: {:?}\n",
                    value.page.items().first().map_or(0, |h| h.rank_version),
                    value.truncated_candidates
                ));
            }
        }
        Read::Absent { checked } => output.push_str(&format!("absent: {}\n", escape(checked))),
        Read::Unknown { what } => output.push_str(&format!("unknown: {}\n", escape(what))),
        Read::Unreadable { source, reason, .. } => output.push_str(&format!(
            "unreadable {}: {}\n",
            escape(source),
            escape(reason)
        )),
    }
    if output.len() > max_bytes {
        return Err(capacity(
            "Atlas compact response bytes",
            output.len() as u64,
            max_bytes as u64,
        ));
    }
    Ok(output)
}
pub fn hit_line(hit: &SearchHit) -> String {
    let target = match &hit.target {
        HitTarget::Code(code) => format!(
            "{} {}",
            location(&code.pointer.path, code.pointer.span),
            escape(&code.name)
        ),
        HitTarget::Record(record) => format!(
            "{:?} {} \"{}\"",
            record.pointer.kind,
            escape(record.pointer.key.as_str()),
            escape(&record.line)
        ),
        HitTarget::Commit(commit) => format!(
            "commit {} \"{}\" (Git author time {})",
            oid(&commit.oid),
            escape(&commit.subject),
            commit.author_unix_ms
        ),
    };
    let mut reason = format!("{:?}", hit.reason.mode);
    if let Some(agent) = &hit.reason.edited_by {
        reason.push_str(&format!(" · edited by {agent}"));
    }
    if let Some(time) = hit.reason.last_touch_unix_ms {
        reason.push_str(&format!(" · touched {time}"));
    }
    if hit.reason.cited_messages > 0 {
        reason.push_str(&format!(
            " · cited in {} recent msgs",
            hit.reason.cited_messages
        ));
    }
    if hit.reason.text_only {
        reason.push_str(" · text-only");
    }
    if hit.reason.related {
        reason.push_str(" · related");
    }
    if let HitTarget::Code(code) = &hit.target {
        match code.pointer.freshness {
            SnapshotFreshness::Current => (),
            SnapshotFreshness::Stale => reason.push_str(" · stale"),
            SnapshotFreshness::Unknown => reason.push_str(" · unverified revision"),
        }
    }
    format!("{target} · {reason}")
}
pub fn resume(code: &ResumeCode) -> AtlasResult<String> {
    let mut output = format!("code {:?}", code.state);
    for item in &code.items {
        match item {
            ResumeChange::File {
                pointer,
                kinds,
                changes,
                author,
                late_attribution,
                baseline_reset,
                ..
            } => {
                output.push_str(&format!(
                    "\n{} {:?} ×{}",
                    self::pointer(pointer),
                    kinds,
                    changes
                ));
                if let AuthorHint::Captured { agent, .. } = author {
                    output.push_str(&format!(" by {agent}"));
                }
                if *late_attribution {
                    output.push_str(" [late attribution]");
                }
                if *baseline_reset {
                    output.push_str(" [baseline reset]");
                }
            }
            ResumeChange::Bulk(bulk) => output.push_str(&format!(
                "\nrepository activity: {} files {:?}{}",
                bulk.files,
                bulk.reason,
                if bulk.complete { "" } else { " [incomplete]" }
            )),
        }
    }
    if code.unattributed_omitted.is_some_and(|n| n > 0) {
        output.push_str(&format!(
            "\nunattributed: {}",
            code.unattributed_omitted.unwrap_or(0)
        ));
    }
    if !code.complete {
        output.push_str("\n[summary incomplete]");
    }
    if let Some(cursor) = &code.omitted_since {
        output.push_str(&format!("\natlas changes --since {}", cursor.as_str()));
    }
    if output.len() > 600 {
        return Err(capacity(
            "Atlas resume context bytes",
            output.len() as u64,
            600,
        ));
    }
    Ok(output)
}
fn state(index: &IndexSummary) -> String {
    let label = match &index.state {
        IndexState::Current => "current",
        IndexState::Partial { .. } => "partial",
        IndexState::Disabled => "disabled",
        IndexState::NotBuilt => "not built",
        IndexState::Dormant => "dormant",
        IndexState::Absent => "absent",
        IndexState::Opening => "opening",
        IndexState::ColdIndexing { .. } => "building",
        IndexState::Updating { .. } => "updating",
        IndexState::VerificationNeeded { .. } => "verification needed",
        IndexState::Suspended { .. } => "suspended",
        IndexState::Unreadable { .. } => "unreadable",
        IndexState::Draining => "draining",
        IndexState::Closed => "closed",
    };
    let (anonymous, grammar, qualified) =
        index
            .memory
            .as_ref()
            .map_or((ANONYMOUS_BYTES, None, false), |memory| {
                (
                    memory.anonymous_ceiling_bytes,
                    memory.shared_grammar_pages,
                    memory.joined_qualified,
                )
            });
    let grammar = grammar.map_or_else(
        || "unqualified".into(),
        |pages| {
            format!(
                "{} B observed, {} B reserved",
                pages.observed_bytes, pages.reserved_bytes
            )
        },
    );
    let mut output = format!(
        "[atlas {label}; anonymous cap {anonymous} B; shared grammar pages {grammar}; joined {}]\n",
        if qualified {
            "qualified"
        } else {
            "unqualified"
        }
    );
    if let IndexState::Suspended { reason } = &index.state {
        output.push_str(&format!("reason: {}\n", escape(&reason.message())));
    }
    for reason in &index.coverage.reasons {
        let detail = match reason {
            CoverageReason::StaleSnapshot => {
                "cached declarations lack verified matching live bytes"
            }
            CoverageReason::ChangedDuringRead => "source bytes changed during the read",
            CoverageReason::TimeLimit => "source work reached its time limit",
            CoverageReason::SourceBytesLimit => "source exceeds the admitted byte limit",
            _ => continue,
        };
        output.push_str(&format!("source: {detail} ({reason:?})\n"));
    }
    output
}

fn oid(id: &GitObjectId) -> String {
    let bytes = match id {
        GitObjectId::Sha1(v) => v.as_slice(),
        GitObjectId::Sha256(v) => v.as_slice(),
    };
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
