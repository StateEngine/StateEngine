//! Parser algorithm inputs only. Capacity values here are NOT native RSS
//! qualification, and never activate an incremental production profile.
use super::*;
use crate::lifecycle::{FileIdentity, RevisionTrust};
fn scope() -> AtlasResult<Scope> {
    let project = se_types::ProjectId::from_parts(1, [1; 10])?;
    let root = RootId::from_parts(1, [2; 10])?;
    Scope::new(
        RootRegistration {
            project,
            root,
            canonical_source_root: std::env::temp_dir(),
            cache: CacheLocation {
                directory: std::env::temp_dir().join("5p-parser-unit"),
            },
            git_metadata: None,
        },
        [3; 32],
    )
}
fn snapshot(text: &str) -> AtlasResult<SourceSnapshot> {
    Ok(SourceSnapshot {
        path: RelativePath::new("sample.file")?,
        identity: FileIdentity {
            volume: [0; 16],
            file: [0; 16],
            size: text.len() as u64,
            mtime_unix_nanos: 0,
            ctime_unix_nanos: None,
            change_sequence: None,
            sequence_domain: None,
            revision_trust: RevisionTrust::Unverified,
        },
        content_hash: ContentHash(*blake3::hash(text.as_bytes()).as_bytes()),
        bytes: text.as_bytes().to_vec(),
    })
}
fn budget() -> ParseBudget {
    ParseBudget {
        max_source_bytes: 524288,
        max_rows: 4096,
        max_work: Duration::from_millis(200),
        reserved_bytes: 16_000_000,
    }
}
#[test]
fn six_grammars_and_stable_signature_body_metadata() -> AtlasResult<()> {
    let scope = scope()?;
    let cases = [
        (
            Language::JavaScript,
            "export default function alpha(value) {return value;} alpha(2);",
            "alpha",
        ),
        (
            Language::Jsx,
            "export const Alpha = () => <Widget />;",
            "Alpha",
        ),
        (
            Language::TypeScript,
            "export interface Shape {draw(): void;} export function alpha(value: Shape): void {}",
            "alpha",
        ),
        (
            Language::Tsx,
            "export const Alpha = (): JSX.Element => <Widget />;",
            "Alpha",
        ),
        (
            Language::Rust,
            "pub fn alpha(value: u32) -> u32 {value} fn caller(){alpha(2);}",
            "alpha",
        ),
        (
            Language::Python,
            "def alpha(value):\n    return value\nalpha(2)\n",
            "alpha",
        ),
    ];
    for (language, source, name) in cases {
        let profile = ParserProfile::from_qualified_measurement(
            language,
            ParserPlacement::ColdChild,
            524288,
            4096,
            4_000_000,
            8_000_000,
        )?;
        let mut parser = SemanticParser::cold_child(scope.clone(), vec![profile])?;
        let parsed = parser.parse(&snapshot(source)?, language, budget())?;
        assert!(
            matches!(parsed.coverage, FileCoverage::Indexed),
            "{language:?}: {:?}",
            parsed.coverage
        );
        let symbol = parsed
            .symbols
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| se_types::SeError::invalid("parser unit", "the expected declaration"))?;
        assert!(symbol.signature_hash.is_some());
        assert!(symbol.body_hash.is_some());
        assert_eq!(parsed.symbols[0].signature_hash, None);
        assert_eq!(parsed.symbols[0].body_hash, None);
        if matches!(language, Language::Jsx | Language::Tsx) {
            assert!(
                parsed
                    .references
                    .iter()
                    .any(|r| r.site.spelling == "Widget")
            );
        }
        if language == Language::JavaScript {
            assert_eq!(symbol.export_alias.as_deref(), Some("default"));
        }
        // Compare JavaScript only; other grammars do not parse JS by accident.
        if language == Language::JavaScript {
            let original = parser.parse(&snapshot("function alpha() {}")?, language, budget())?;
            let body = parser.parse(
                &snapshot("function alpha() {return 1;}")?,
                language,
                budget(),
            )?;
            let a = &original.symbols[1];
            let b = &body.symbols[1];
            assert_eq!(a.id, b.id);
            assert_eq!(a.signature_hash, b.signature_hash);
            assert_ne!(a.body_hash, b.body_hash);
            assert_eq!(
                a.body_hash,
                Some(ContentHash(*blake3::hash(&[]).as_bytes()))
            );
        }
    }
    Ok(())
}
