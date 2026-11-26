//! One line for how full an agent's context window is. A window nobody
//! reported shows the token count alone, never a guessed percentage.
use se_core::ops::ContextWindowView;
use se_types::Read;
use std::io::{self, Write};

pub(crate) fn window(
    context: &Read<ContextWindowView>,
    indent: &str,
    out: &mut impl Write,
) -> io::Result<()> {
    match context {
        Read::Present { value } => writeln!(out, "{indent}Context: {}", summary(value)),
        Read::Absent { checked } => writeln!(out, "{indent}Context: none ({checked})"),
        Read::Unknown { what } => writeln!(out, "{indent}Context: unknown ({what})"),
        Read::Unreadable { source, reason, .. } => {
            writeln!(out, "{indent}Context unreadable at {source}: {reason}")
        }
    }
}

fn summary(value: &ContextWindowView) -> String {
    let used = tokens(value.used_tokens);
    match (value.context_window_tokens, value.fill_percent) {
        (Some(size), Some(fill)) => format!("{used} / {} tokens ({fill:.0}%)", tokens(size)),
        _ => format!("{used} tokens (window size not reported)"),
    }
}

/// `950`, `84.2k`, `200k`, `1.5M`: one decimal, dropped when it is zero.
fn tokens(count: u64) -> String {
    let (scaled, unit) = match count {
        0..=999 => return count.to_string(),
        1_000..=999_949 => (count as f64 / 1_000.0, "k"),
        _ => (count as f64 / 1_000_000.0, "M"),
    };
    let text = format!("{scaled:.1}");
    format!("{}{unit}", text.strip_suffix(".0").unwrap_or(&text))
}
