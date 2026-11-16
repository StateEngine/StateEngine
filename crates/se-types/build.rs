//! Compile the shared registry once; runtime consumers need no parsing or allocation.
use serde::Deserialize;
use std::{env, error::Error, fs, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    variant: String,
    id: String,
    title: String,
    selection_title: Option<String>,
    driver: String,
    command: String,
    selection: Selection,
    omit_default_config: bool,
    seed_profile: bool,
    detached_no_approval: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Selection {
    Default,
    Builtin,
    Configured,
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=src/harness_registry.json");
    let rows: Vec<Entry> = serde_json::from_str(include_str!("src/harness_registry.json"))?;
    let mut source = String::from(
        "#[doc(hidden)]\n#[macro_export]\nmacro_rules! with_harness_registry {\n\
         ($consumer:ident) => { $consumer! {\n",
    );
    for row in rows {
        let default = if matches!(row.selection, Selection::Default) {
            "#[default]"
        } else {
            ""
        };
        let skip = if row.omit_default_config {
            "#[serde(skip_serializing_if = \"is_default_provider\")]"
        } else {
            ""
        };
        source.push_str(&format!(
            "{} {} [{}] [{}] {{ id: {:?}, title: {:?}, selection_title: {:?}, driver: {:?}, command: {:?}, \
             selectable: {}, seed_profile: {}, detached_no_approval: {} }};\n",
            row.variant,
            row.id,
            default,
            skip,
            row.id,
            row.title,
            row.selection_title.as_deref().unwrap_or(&row.title),
            row.driver,
            row.command,
            !matches!(row.selection, Selection::Configured),
            row.seed_profile,
            row.detached_no_approval,
        ));
    }
    source.push_str("} };\n}\n");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?).join("harness_registry.rs"),
        source,
    )?;
    Ok(())
}
