use crate::{Result, measure};
use se_atlas::{
    lifecycle::*,
    model::*,
    parse::{ParserPlacement, ParserProfile, SemanticParser},
    scope::Scope,
};
use se_host::atlas_source::NativeAtlasSource;
use se_types::code::AtlasText;
use std::{
    fs,
    time::{Duration, Instant},
};
fn line(language: Language, pattern: &str, index: usize) -> String {
    match pattern {
        "definitions" => match language {
            Language::Rust => {
                format!("pub fn value_{index}(x: u64) -> u64 {{ x.wrapping_add(2) }}\n")
            }
            Language::Python => format!("def value_{index}(x):\n return x + 2\n"),
            Language::JavaScript => {
                format!("export function value_{index}(x) {{ return x + 2; }}\n")
            }
            Language::Jsx => format!("export const value_{index} = (x) => <span>{{x}}</span>;\n"),
            Language::TypeScript => {
                format!("export function value_{index}(x:number):number {{ return x + 2; }}\n")
            }
            Language::Tsx => {
                format!("export const value_{index} = (x:number) => <span>{{x}}</span>;\n")
            }
        },
        "references" => {
            if language == Language::Rust {
                "fn f(){a();a();a();a();a();a();a();a();}\n".into()
            } else {
                "a;a;a;a;a;a;a;a;a;a;a;a;a;a;a;a;\n".into()
            }
        }
        "comments" => {
            if language == Language::Python {
                "# allocator observation only\n".into()
            } else {
                "/* allocator observation only */\n".into()
            }
        }
        "malformed" => "((({[[[ bad_token = ;\n".into(),
        "nesting" => "((((((((((((((((((((((((((((((((".into(),
        _ => panic!("unknown input pattern"),
    }
}
pub fn run(scope: Scope, language: &str, pattern: &str) -> Result<serde_json::Value> {
    let (language, extension) = match language {
        "rust" => (Language::Rust, "rs"),
        "python" => (Language::Python, "py"),
        "javascript" => (Language::JavaScript, "js"),
        "jsx" => (Language::Jsx, "jsx"),
        "typescript" => (Language::TypeScript, "ts"),
        "tsx" => (Language::Tsx, "tsx"),
        _ => return Err("unknown grammar".into()),
    };
    let path = RelativePath::new(format!("input.{extension}"))?;
    let mut source = String::with_capacity(65_536);
    for index in 0..65_536 {
        let next = line(language, pattern, index);
        if source.len() + next.len() > 65_536 {
            break;
        }
        source.push_str(&next);
    }
    while source.len() < 65_536 {
        source.push('\n');
    }
    fs::write(
        scope.registration.canonical_source_root.join(path.as_str()),
        source.as_bytes(),
    )?;
    drop(source);
    let native = NativeAtlasSource::open(scope.registration.clone(), CaseMode::Sensitive)?;
    let profile = ParserProfile::from_qualified_measurement(
        language,
        ParserPlacement::Incremental,
        65_536,
        32_768,
        8_000_000,
        3_000_000,
    )?;
    let mut parser = SemanticParser::new(scope, vec![profile])?;
    let budget = ParseBudget {
        max_source_bytes: 65_536,
        max_rows: 32_768,
        max_work: Duration::from_millis(200),
        reserved_bytes: 11_065_536,
    };
    let zone_before = measure::zone();
    let physical_before = se_proc::atlas_worker::memory_usage()?;
    let base = measure::reset();
    let SourceRead::Bytes(snapshot) = native.read(&path, budget)? else {
        return Err("native source did not return bytes".into());
    };
    let started = Instant::now();
    let result = parser.parse(&snapshot, language, budget);
    let elapsed_us = started.elapsed().as_micros();
    let peak = measure::peak().saturating_sub(base);
    let zone_after = measure::zone();
    let physical_after = se_proc::atlas_worker::memory_usage()?;
    let outcome = match &result {
        Ok(value) => {
            serde_json::json!({"coverage": format!("{:?}", value.coverage), "symbols": value.symbols.len(), "references": value.references.len(), "imports": value.imports.len(), "scopes": value.scopes.len()})
        }
        Err(error) => serde_json::json!({"error": error.body}),
    };
    drop(result);
    drop(snapshot);
    drop(parser);
    drop(native);
    let zone_closed = measure::zone();
    Ok(
        serde_json::json!({"grammar":format!("{language:?}"),"pattern":pattern,"source_bytes":65_536,"row_allowance":32_768,"elapsed_us":elapsed_us,
        "combined_native_sized_rust_tree_peak_increment":peak,"zone_before":zone_before,"zone_after":zone_after,"zone_closed":zone_closed,
        "physical_peak_before":physical_before,"physical_peak_after":physical_after,"reservation_bytes":11_065_536,"outcome":outcome}),
    )
}
