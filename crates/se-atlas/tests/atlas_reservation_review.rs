//! Consumer check for bounded native parsing and recovery in the same process.
use se_atlas::{
    lifecycle::{AtlasParser, FileIdentity, RevisionTrust, SourceSnapshot},
    model::{
        CacheLocation, ContentHash, Language, ParseBudget, RelativePath, RootId, RootRegistration,
    },
    parse::{ParserPlacement, ParserProfile, SemanticParser},
    scope::Scope,
};
use std::{fs, path::Path, time::Duration};

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SOURCE_LIMIT: u32 = 65_536;
const TOTAL: u32 = 400_000;
const CASES: [(Language, &str, &str); 6] = [
    (
        Language::JavaScript,
        "export function kept() { return 1; }",
        "kept",
    ),
    (Language::Jsx, "export const Kept = () => <Tag />;", "Kept"),
    (
        Language::TypeScript,
        "export function kept(): number { return 2; }",
        "kept",
    ),
    (
        Language::Tsx,
        "export const Kept = (): JSX.Element => <Tag />;",
        "Kept",
    ),
    (Language::Rust, "pub fn kept() -> u32 { 3 }", "kept"),
    (Language::Python, "def kept():\n    return 4\n", "kept"),
];

fn snapshot(text: &str) -> Check<SourceSnapshot> {
    let bytes = text.as_bytes().to_vec();
    Ok(SourceSnapshot {
        path: RelativePath::new("fixture.source")?,
        identity: FileIdentity {
            volume: [0; 16],
            file: [0; 16],
            size: bytes.len() as u64,
            mtime_unix_nanos: 0,
            ctime_unix_nanos: None,
            change_sequence: None,
            sequence_domain: None,
            revision_trust: RevisionTrust::Unverified,
        },
        content_hash: ContentHash(*blake3::hash(&bytes).as_bytes()),
        bytes,
    })
}

#[test]
fn dense_parse_defers_and_six_grammars_recover_in_the_same_process() -> Check {
    let root = std::env::temp_dir().canonicalize()?;
    let scope = Scope::new(
        RootRegistration {
            project: se_types::ProjectId::from_parts(1, [1; 10])?,
            root: RootId::from_parts(1, [2; 10])?,
            canonical_source_root: root.clone(),
            cache: CacheLocation { directory: root },
            git_metadata: None,
        },
        [3; 32],
    )?;
    let profiles = CASES
        .iter()
        .map(|&(language, _, _)| {
            ParserProfile::from_qualified_measurement(
                language,
                ParserPlacement::Incremental,
                SOURCE_LIMIT,
                65_536,
                20_000,
                250_000,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut parser = SemanticParser::new(scope, profiles)?;
    let budget = ParseBudget {
        max_source_bytes: SOURCE_LIMIT,
        max_rows: 65_536,
        max_work: Duration::from_millis(200),
        reserved_bytes: TOTAL,
    };
    let dense = snapshot(&"v=1;".repeat(14_000))?;
    let mut recoveries = Vec::new();
    for round in 0..4 {
        let result = parser.parse(&dense, Language::JavaScript, budget);
        assert!(
            result.is_ok(),
            "dense round {round} did not defer: {result:?}"
        );
        let deferred = result?;
        assert_eq!(
            format!("{:?}", deferred.coverage),
            "Deferred { reason: ParseMemoryLimit }"
        );
        assert!(
            deferred.symbols.is_empty()
                && deferred.references.is_empty()
                && deferred.imports.is_empty()
        );
        for (language, source, expected) in CASES {
            let parsed = parser.parse(&snapshot(source)?, language, budget)?;
            assert_eq!(format!("{:?}", parsed.coverage), "Indexed", "{language:?}");
            assert!(
                parsed.symbols.iter().any(|item| item.name == expected),
                "{language:?}"
            );
            recoveries.push(format!("{language:?}"));
        }
    }
    let output = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics/atlas-reservation-review");
    fs::create_dir_all(&output)?;
    fs::write(
        output.join("review.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "os": std::env::consts::OS,
            "run_id": std::env::var("GITHUB_RUN_ID").ok(),
            "dense_bytes": dense.bytes.len(), "reserved_bytes": TOTAL,
            "memory_deferrals": 4, "successful_grammar_recoveries": recoveries,
        }))?,
    )?;
    Ok(())
}
