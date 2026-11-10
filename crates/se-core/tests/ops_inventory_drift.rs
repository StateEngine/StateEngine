//! Drift check for the generated command inventory in `docs/OPS.md`.
//!
//! The inventory block is generated from the `ops!` registry in
//! `crates/se-core/src/ops/mod.rs` together with the design tables of
//! `docs/OPS.md` itself: registered rows render from the catalogue, rows
//! named by the design tables but absent from the registry are listed as
//! planned, and registered rows missing from the design tables are
//! reconciled. This test fails whenever the block drifts from either
//! source. Regenerate with:
//!
//! ```sh
//! SE_OPS_INVENTORY_UPDATE=1 cargo test -p se-core --test ops_inventory_drift
//! ```

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use se_core::ops::CATALOGUE;
use se_core::registry::{Auth, CliExposure, Effect, Feature, McpExposure, OpMeta, Selector};

const BEGIN: &str = "<!-- BEGIN GENERATED: ops-inventory (do not edit between the markers) -->";
const END: &str = "<!-- END GENERATED: ops-inventory -->";
const UPDATE: &str = "SE_OPS_INVENTORY_UPDATE";

fn docs_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/OPS.md")
}

fn auth_name(value: Auth) -> &'static str {
    match value {
        Auth::Owner => "owner",
        Auth::Session => "session",
        Auth::Either => "either",
    }
}

fn effect_name(value: Effect) -> &'static str {
    match value {
        Effect::Read => "read",
        Effect::Write => "write",
        Effect::Custody => "custody",
    }
}

fn cli_cell(meta: &OpMeta) -> String {
    match meta.cli {
        CliExposure::Leaf {
            path,
            hidden,
            select,
        } => {
            let mut cell = path.join(" ");
            if let Selector::Flag(flag) = select {
                cell.push_str(&format!(" --{flag}"));
            }
            if hidden {
                cell.push_str(" (hidden)");
            }
            cell
        }
        CliExposure::RootFlag { flag } => format!("--{flag}"),
        CliExposure::None { reason } => format!("none — {reason}"),
    }
}

fn mcp_cell(meta: &OpMeta) -> String {
    match meta.mcp {
        McpExposure::Tool { name, .. } => format!("`{name}`"),
        McpExposure::None { .. } => "none".to_string(),
    }
}

/// Split a markdown table row body on unescaped `|` characters.
fn split_row(rest: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut current = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'|') => {
                current.push('|');
                chars.next();
            }
            '|' => cells.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    cells.push(current);
    cells
}

/// Operation names and MCP tool names named by the design tables in
/// `docs/OPS.md`. Only rows whose first cell is exactly a backticked
/// dotted name count, so the journeys table and the old-spellings table
/// never contribute.
fn design_tables(md: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut ops = BTreeSet::new();
    let mut tools = BTreeSet::new();
    let mut in_generated = false;
    for line in md.lines() {
        if line.contains(BEGIN) {
            in_generated = true;
        }
        if in_generated {
            if line.contains(END) {
                in_generated = false;
            }
            continue;
        }
        let Some(rest) = line.trim_start().strip_prefix('|') else {
            continue;
        };
        let cells = split_row(rest);
        let Some(name_cell) = cells.first() else {
            continue;
        };
        let Some(inner) = name_cell
            .trim()
            .strip_prefix('`')
            .and_then(|t| t.strip_suffix('`'))
        else {
            continue;
        };
        if !inner.contains('.') {
            continue;
        }
        if inner
            .chars()
            .any(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '.' && c != '_')
        {
            continue;
        }
        ops.insert(inner.to_string());
        if let Some(mcp) = cells.get(2)
            && let Some(start) = mcp.find("stateengine_")
        {
            let tail = &mcp[start + "stateengine_".len()..];
            let name: String = tail
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            if !name.is_empty() {
                tools.insert(format!("stateengine_{name}"));
            }
        }
    }
    (ops, tools)
}

fn join_names(names: &[String]) -> String {
    names
        .iter()
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn unlisted_note(meta: &OpMeta) -> String {
    let no_cli = matches!(meta.cli, CliExposure::None { .. });
    let no_mcp = matches!(meta.mcp, McpExposure::None { .. });
    if no_cli && no_mcp {
        "no CLI or MCP exposure".to_string()
    } else if no_cli {
        "MCP only".to_string()
    } else {
        format!("CLI `{}`", cli_cell(meta))
    }
}

fn render_block(md: &str) -> String {
    let (design_ops, design_tools) = design_tables(md);
    let registry_ops: BTreeSet<String> = CATALOGUE.iter().map(|m| m.name.to_string()).collect();
    let registry_tools: BTreeSet<String> = CATALOGUE
        .iter()
        .filter_map(|m| match m.mcp {
            McpExposure::Tool { name, .. } => Some(name.to_string()),
            McpExposure::None { .. } => None,
        })
        .collect();
    let planned_ops: Vec<String> = design_ops.difference(&registry_ops).cloned().collect();
    let planned_tools: Vec<String> = design_tools.difference(&registry_tools).cloned().collect();
    let unlisted_ops: Vec<&OpMeta> = CATALOGUE
        .iter()
        .copied()
        .filter(|m| !design_ops.contains(m.name))
        .collect();
    let unlisted_tools: Vec<String> = registry_tools.difference(&design_tools).cloned().collect();

    let ops = CATALOGUE.len();
    let atlas_ops = CATALOGUE
        .iter()
        .filter(|m| matches!(m.feature, Feature::Atlas))
        .count();
    let core_ops = ops - atlas_ops;
    let tools = registry_tools.len();
    let atlas_tools = CATALOGUE
        .iter()
        .filter(|m| matches!(m.feature, Feature::Atlas))
        .filter(|m| matches!(m.mcp, McpExposure::Tool { .. }))
        .count();
    let core_tools = tools - atlas_tools;

    let mut out = String::new();
    out.push_str(&format!(
        "Registered: {ops} operations ({core_ops} core, {atlas_ops} Atlas), {tools} MCP tools ({core_tools} core, {atlas_tools} Atlas). Planned: {} operations, {} MCP tools.\n\n",
        planned_ops.len(),
        planned_tools.len()
    ));
    out.push_str("| Operation | CLI | MCP tool | Auth | Effect |\n");
    out.push_str("| --- | --- | --- | --- | --- |\n");
    for meta in CATALOGUE {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            meta.name,
            cli_cell(meta),
            mcp_cell(meta),
            auth_name(meta.auth),
            effect_name(meta.effect)
        ));
    }
    out.push_str(&format!(
        "\nPlanned operations (design tables, not yet registered): {}\n\n",
        if planned_ops.is_empty() {
            "none".to_string()
        } else {
            join_names(&planned_ops)
        }
    ));
    out.push_str(&format!(
        "Planned MCP tools: {}\n",
        if planned_tools.is_empty() {
            "none".to_string()
        } else {
            join_names(&planned_tools)
        }
    ));
    if !unlisted_ops.is_empty() {
        out.push_str("\nRegistered without a design-table row: ");
        let notes = unlisted_ops
            .iter()
            .map(|m| format!("`{}` ({})", m.name, unlisted_note(m)))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("{notes}\n"));
    }
    if !unlisted_tools.is_empty() {
        out.push_str(&format!(
            "\nRegistered MCP tools not named in the design tables: {}\n",
            join_names(&unlisted_tools)
        ));
    }
    out.pop();
    out
}

fn rendered_block(md: &str) -> String {
    let mut block = format!("{BEGIN}\n{}\n{END}", render_block(md));
    if md.contains("\r\n") {
        block = block.replace('\n', "\r\n");
    }
    block
}

#[test]
fn ops_inventory_is_in_sync_with_registry() {
    let path = docs_path();
    let md = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let full = rendered_block(&md);
    let Some(start) = md.find(BEGIN) else {
        panic!("docs/OPS.md is missing the generated ops inventory block; run with {UPDATE}=1");
    };
    let Some(end_offset) = md[start..].find(END) else {
        panic!("docs/OPS.md is missing the END generated marker");
    };
    let end = start + end_offset + END.len();
    if std::env::var_os(UPDATE).is_some() {
        fs::write(&path, format!("{}{}{}", &md[..start], full, &md[end..]))
            .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        eprintln!("regenerated the ops inventory in docs/OPS.md");
        return;
    }
    assert_eq!(
        &md[start..end],
        &full,
        "docs/OPS.md ops inventory drifted from the se-core registry or the design tables; regenerate with {UPDATE}=1 cargo test -p se-core --test ops_inventory_drift"
    );
}
