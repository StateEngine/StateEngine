use se_core::ops::ErasureReceipt;
use std::io::{self, Write};
fn plural(count: usize, one: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {one}s")
    }
}
pub(super) fn output(value: &ErasureReceipt, out: &mut impl Write) -> io::Result<()> {
    let bodies = plural(value.targets.len(), "body");
    match value.outcome.as_str() {
        "planned" => writeln!(
            out,
            "Forget plan: {bodies} will be erased permanently. Nothing has been erased yet."
        )?,
        "forgotten" => writeln!(out, "Forgotten: {bodies} erased permanently.")?,
        _ => writeln!(
            out,
            "Partly forgotten: {bodies} erased, but cleanup is not finished."
        )?,
    }
    for target in &value.targets {
        writeln!(out, "  {} (revision {})", target.event, target.revision)?;
    }
    let tense = if value.outcome == "planned" {
        "will be replaced"
    } else {
        "replaced"
    };
    let backups = match value.backups_replaced {
        0 => "no earlier automatic backup needed replacing".to_string(),
        n => format!("{} {tense}", plural(n, "earlier automatic backup")),
    };
    if value.outcome == "planned" {
        writeln!(
            out,
            "The database will be rewritten without the old pages; {backups}."
        )?;
        writeln!(
            out,
            "Needs about {} MB of free space.",
            value.required_bytes.div_ceil(1_000_000)
        )?;
    } else if value.complete() {
        writeln!(
            out,
            "The database was rewritten without the old pages; {backups}."
        )?;
        if let Some(event) = &value.completed_event {
            writeln!(
                out,
                "Kept: a record that this erasure happened ({event}), without the content."
            )?;
        }
    }
    if !value.residuals.is_empty() {
        writeln!(out, "Copies StateEngine cannot erase:")?;
        for residual in &value.residuals {
            writeln!(out, "  {}: {}", residual.custodian, residual.location)?;
            writeln!(out, "    {}", residual.reason)?;
        }
    }
    writeln!(out, "{}", value.unlisted)?;
    if let Some(next) = &value.next {
        writeln!(out, "{}:", next.text)?;
        writeln!(out, "  {}", next.argv.join(" "))?;
    }
    Ok(())
}
