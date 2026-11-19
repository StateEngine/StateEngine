use super::*;
use se_atlas::{
    lifecycle::{AtlasParser, AtlasSource, SourceRead},
    parse::{ParserPlacement, ParserProfile, SemanticParser},
};
use std::{process::Command, time::Duration};

const SOURCE_BYTES: u32 = 65_536;
const ROWS: u32 = 8_192;
const CASES: &[(&str, Language, &str)] = &[
    (
        "js",
        Language::JavaScript,
        "function sample(v){return v;}\n",
    ),
    (
        "jsx",
        Language::Jsx,
        "function Sample(v){return <Box>{v}</Box>;}\n",
    ),
    (
        "ts",
        Language::TypeScript,
        "function sample(v: number): number {return v;}\n",
    ),
    (
        "tsx",
        Language::Tsx,
        "function Sample(v: number){return <Box>{v}</Box>;}\n",
    ),
    ("rs", Language::Rust, "fn sample(v: u32) -> u32 {v}\n"),
    ("py", Language::Python, "def sample(v):\n    return v\n"),
];
const SHAPES: &[&str] = &[
    "small",
    "limit_typical",
    "limit_dense",
    "limit_nested",
    "over_limit",
];

fn source_text(shape: &str, grammar: &str, typical: &str) -> Observed<String> {
    let limit = SOURCE_BYTES as usize;
    let dense = match grammar {
        "rs" => "fn f(){a();a();a();a();a();a();a();a();}\n",
        "py" => "f();f();f();f();f();f();f();f()\n",
        _ => "a();a();a();a();a();a();a();a();\n",
    };
    let depth = 160;
    let nested = format!(
        "{}{}value{}{}\n",
        if grammar == "rs" {
            "fn f(){let _v="
        } else {
            "x="
        },
        "(".repeat(depth),
        ")".repeat(depth),
        if grammar == "rs" { ";}" } else { "" }
    );
    let unit = match shape {
        "small" => return Ok(typical.to_owned()),
        "limit_typical" | "over_limit" => typical,
        "limit_dense" => dense,
        "limit_nested" => &nested,
        _ => return Err("unknown parser source shape".into()),
    };
    let target = limit + usize::from(shape == "over_limit");
    let mut text = unit.repeat(target / unit.len());
    text.extend(std::iter::repeat_n(' ', target - text.len()));
    assert_eq!(text.len(), target);
    Ok(text)
}

fn once(
    fixture: &Fixture,
    path: &RelativePath,
    profile: ParserProfile,
    budget: ParseBudget,
) -> Observed<Value> {
    let memory_before = native::memory()?;
    let started = Instant::now();
    let mut tracked_peak = None;
    let (outcome, while_result) = match fixture.source.read(path, budget)? {
        SourceRead::Bytes(snapshot) => {
            let mut parser = SemanticParser::new(fixture.source.scope.clone(), vec![profile])?;
            let parsed = parser.parse(&snapshot, profile.language, budget);
            tracked_peak = Some(se_atlas::parse::diagnostic_peak());
            match parsed {
                Ok(parsed) => {
                    let counters = native::commit()?;
                    let rows = parsed.symbols.len()
                        + parsed.imports.len()
                        + parsed.references.len()
                        + parsed.scopes.len();
                    assert!(rows <= ROWS as usize);
                    (
                        json!({"coverage": parsed.coverage, "rows": rows, "source_bytes": snapshot.bytes.len()}),
                        counters,
                    )
                }
                Err(e) => {
                    assert!(
                        matches!(e.body.detail(), se_types::Detail::AtlasResourceBudget(_)),
                        "unexpected parser failure: {e}"
                    );
                    (
                        json!({"budget_error": e.body, "source_bytes": snapshot.bytes.len()}),
                        native::commit()?,
                    )
                }
            }
        }
        SourceRead::Deferred { reason, identity } => {
            assert_eq!(reason, CoverageReason::SourceBytesLimit);
            assert_eq!(identity.size, u64::from(SOURCE_BYTES + 1));
            (
                json!({"coverage": {"Deferred": {"reason": reason}}, "rows": 0, "source_bytes": identity.size}),
                native::commit()?,
            )
        }
        _ => return Err("expected verified source bytes or source-byte deferral".into()),
    };
    let duration_ns = u64::try_from(started.elapsed().as_nanos())?;
    let after_scratch_release = native::memory()?;
    Ok(json!({
        "elapsed_ns": duration_ns,
        "tracked_peak_bytes": tracked_peak,
        "outcome": outcome,
        "before": memory_before,
        "private_commit_while_result": while_result,
        "after_scratch_release": after_scratch_release,
    }))
}

pub fn observe(case: &str) -> Observed<Value> {
    let (extension, shape) = case.split_once(':').ok_or("parser case grammar:shape")?;
    let &(_, language, sample) = CASES
        .iter()
        .find(|case| case.0 == extension)
        .ok_or("parser grammar")?;
    let fixture = Fixture::new()?;
    let filename = format!("fixture.{extension}");
    let path = RelativePath::new(&filename)?;
    let text = source_text(shape, extension, sample)?;
    fs::write(
        fixture
            .source
            .scope
            .registration
            .canonical_source_root
            .join(&filename),
        text,
    )?;
    let profile = ParserProfile::from_qualified_measurement(
        language,
        ParserPlacement::Incremental,
        SOURCE_BYTES,
        ROWS,
        8_000_000,
        3_000_000,
    )?;
    let budget = ParseBudget {
        max_source_bytes: SOURCE_BYTES,
        max_rows: ROWS,
        max_work: Duration::from_millis(200),
        reserved_bytes: PARSER_BYTES,
    };
    let mut iterations = Vec::with_capacity(3);
    for _ in 0..3 {
        let row = once(&fixture, &path, profile, budget)?;
        if shape == "small" {
            assert_eq!(row["outcome"]["coverage"], "Indexed");
            assert!(row["outcome"]["rows"].as_u64().is_some_and(|n| n > 0));
        }
        iterations.push(row);
    }
    fixture.directory.finish(Ok::<(), Box<dyn Error>>(()))?;
    Ok(json!({"case": case, "language": language, "iterations": iterations}))
}

pub fn run() -> Observed<()> {
    let load_before = native::load()?;
    let image = std::env::current_exe()?;
    let mut results = Vec::new();
    for (extension, _, _) in CASES {
        for shape in SHAPES {
            let case = format!("{extension}:{shape}");
            // One process per case gives each grammar/shape an independent
            // native high-water mark. Repetition in that process shows retention.
            let child = Command::new(&image)
                .args(["--exact", "atlas_components_native", "--nocapture"])
                .env("ATLAS_COMPONENT_CASE", &case)
                .output()?;
            let stdout = String::from_utf8(child.stdout)?;
            if !child.status.success() {
                let stderr = String::from_utf8(child.stderr)?;
                return Err(format!("{case} {}: {stdout}\n{stderr}", child.status).into());
            }
            let receipt = stdout
                .lines()
                .find_map(|line| line.strip_prefix("ATLAS_CASE "))
                .ok_or("parser child reported no observation")?;
            let row: Value = serde_json::from_str(receipt)?;
            assert_eq!(row["case"], case);
            results.push(row);
        }
    }
    let load_after = native::load()?;
    output(
        "parser",
        &json!({
            "scope": "native source read, incremental parser source/row bounds and extraction",
            "max_source_bytes": SOURCE_BYTES,
            "max_rows": ROWS,
            "max_work_ms": 200,
            "parser_reservation_bytes": 8_000_000,
            "extraction_reservation_bytes": 3_000_000,
            "total_parser_reservation_bytes": PARSER_BYTES,
            "cases": results,
            "load": [load_before, load_after],
        }),
    )
}
