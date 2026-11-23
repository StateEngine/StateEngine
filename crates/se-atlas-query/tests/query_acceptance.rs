//! Reviewer acceptance tests for target resolution, declared casing, typo
//! suggestions, outline, refs (including custody escape), impact (including
//! restricted ACL and soft deadline), and SQL-only hooks.
mod support;

use se_atlas_index::{
    extract::{SymbolKind, covers::CoverHow, file_key},
    store::{CompactPolicy, PathOutcome},
};
use se_atlas_query::{
    Answer, Resolved, Target,
    hooks::hooks,
    impact::{CallerVia, ImpactRequest, MAX_CALLERS, MAX_CHANGES, MAX_RECORDS, MAX_TESTS, impact},
    outline::{OutlineRequest, outline},
    refs::{MAX_SCAN_FILES, RefAccuracy, RefsRequest, refs},
    resolve,
};
use std::{fs, time::Duration};
use support::{
    RecordSeed, TempDir, TestRepo, TestResult, TouchSeed, seed_mention, seed_record, seed_touch,
};

#[test]
fn target_normalization_policy_refusal_and_allowed_sources() -> TestResult {
    let repo = TestRepo::build(
        "target-policy",
        &[
            ("src/lib.rs", "pub fn entry() {}\n"),
            ("src/id_map.rs", "pub fn map_id() {}\n"),
            ("auth/credentials.py", "def credentials():\n    return 1\n"),
            ("src/secret_store.rs", "pub fn open_store() {}\n"),
            ("config.ts", "export const cfg = 1;\n"),
            (".env", "API_TOKEN=synthetic\n"),
            ("secrets.yaml", "key: synthetic\n"),
            ("credentials", "token=synthetic\n"),
        ],
    )?;
    let reader = repo.reader()?;

    for path in [r".\src\lib.rs", r".\.\src\lib.rs", "src/lib.rs/"] {
        let Resolved::File(file) = resolve(&reader, &Target::Auto(path.into()))? else {
            return Err(format!("{path} must resolve to File").into());
        };
        assert_eq!(file.path, "src/lib.rs");
    }
    let Resolved::Symbols { symbols, .. } =
        resolve(&reader, &Target::Auto(r"src\lib.rs:1".into()))?
    else {
        return Err("Windows path:line must resolve".into());
    };
    assert_eq!(symbols[0].name, "entry");

    for (denied, expected) in [
        (".env", ".env"),
        ("secrets.yaml", "secrets.yaml"),
        ("./credentials", "credentials"),
        (r".\credentials", "credentials"),
        (".env:1", ".env"),
    ] {
        assert_eq!(
            resolve(&reader, &Target::Auto(denied.into()))?,
            Resolved::Refused {
                path: expected.into()
            },
            "{denied} must be refused"
        );
        assert!(matches!(
            outline(&reader, &OutlineRequest::new(Target::Auto(denied.into())))?,
            Answer::Refused { .. }
        ));
        assert!(matches!(
            refs(
                &reader,
                &repo.root,
                &RefsRequest::new(Target::Auto(denied.into()))
            )?,
            Answer::Refused { .. }
        ));
        assert!(matches!(
            impact(&reader, &ImpactRequest::new(Target::Auto(denied.into())))?,
            Answer::Refused { .. }
        ));
        assert!(matches!(
            hooks(&reader, &Target::Auto(denied.into()))?,
            Answer::Refused { .. }
        ));
    }

    // Bare symbol "credentials" resolves to the Python function, while Target::File refuses it.
    let Resolved::Symbols { symbols, .. } = resolve(&reader, &Target::Auto("credentials".into()))?
    else {
        return Err("bare symbol credentials must resolve".into());
    };
    assert_eq!(symbols[0].file.path, "auth/credentials.py");
    assert_eq!(
        resolve(&reader, &Target::File("credentials".into()))?,
        Resolved::Refused {
            path: "credentials".into()
        }
    );

    for allowed in [
        "src/id_map.rs",
        "auth/credentials.py",
        "src/secret_store.rs",
        "config.ts",
    ] {
        let Resolved::File(file) = resolve(&reader, &Target::Auto(allowed.into()))? else {
            return Err(format!("{allowed} must resolve").into());
        };
        assert_eq!(file.path, allowed);
    }
    Ok(())
}

#[test]
fn target_path_line_spans_nesting_equal_span_tiebreak_and_zero() -> TestResult {
    let source = concat!(
        "// header comment outside any symbol\n",
        "pub fn one_liner() {}\n",
        "\n",
        "pub struct Boxed;\n",
        "impl Boxed {\n",
        "    // inside impl, outside method\n",
        "    pub fn work(&self) {\n",
        "        let _ = 1;\n",
        "    }\n",
        "}\n",
        "pub mod inner { pub fn leaf() {} }\n",
    );
    let repo = TestRepo::build("path-line", &[("src/span.rs", source)])?;
    let reader = repo.reader()?;

    let sym_at = |line: u32| -> Result<(String, Option<SymbolKind>), Box<dyn std::error::Error>> {
        let target = Target::Auto(format!("src/span.rs:{line}"));
        let Resolved::Symbols { symbols, capped } = resolve(&reader, &target)? else {
            return Err(format!("line {line} must resolve to symbol").into());
        };
        assert!(!capped && symbols.len() == 1);
        Ok((symbols[0].name.clone(), symbols[0].kind))
    };

    // Outside any symbol -> File.
    assert!(matches!(
        resolve(&reader, &Target::Auto("src/span.rs:1".into()))?,
        Resolved::File(f) if f.path == "src/span.rs"
    ));
    // One-line symbol.
    assert_eq!(sym_at(2)?, ("one_liner".into(), Some(SymbolKind::Function)));
    // Enclosing impl outside method.
    assert_eq!(sym_at(6)?, ("Boxed".into(), Some(SymbolKind::Impl)));
    // Nested method body and closing line (end_line).
    assert_eq!(sym_at(8)?, ("work".into(), Some(SymbolKind::Method)));
    assert_eq!(sym_at(9)?, ("work".into(), Some(SymbolKind::Method)));
    // Closing line of impl.
    assert_eq!(sym_at(10)?, ("Boxed".into(), Some(SymbolKind::Impl)));
    // Equal-span parent & child on line 11: child (`leaf`) wins tie-break.
    assert_eq!(sym_at(11)?, ("leaf".into(), Some(SymbolKind::Function)));
    // `:0` is not a valid line -> NotFound.
    assert!(matches!(
        resolve(&reader, &Target::Auto("src/span.rs:0".into()))?,
        Resolved::NotFound { .. }
    ));
    Ok(())
}

#[test]
fn target_past_64_exact_case_and_capping() -> TestResult {
    let mut owned: Vec<(String, String)> = (0..70)
        .map(|i| (format!("src/a{i:02}.rs"), "pub fn config() {}\n".into()))
        .collect();
    owned.push(("src/z_type.rs".into(), "pub struct Config {}\n".into()));
    let files: Vec<(&str, &str)> = owned
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let repo = TestRepo::build("past-64", &files)?;
    let reader = repo.reader()?;

    let Resolved::Symbols { symbols, capped } = resolve(&reader, &Target::Symbol("Config".into()))?
    else {
        return Err("Config must resolve".into());
    };
    assert!(!capped);
    assert_eq!(symbols.len(), 1);
    assert_eq!(symbols[0].name, "Config");
    assert_eq!(symbols[0].kind, Some(SymbolKind::Struct));
    assert_eq!(symbols[0].file.path, "src/z_type.rs");

    let Resolved::Symbols { symbols, capped } = resolve(&reader, &Target::Symbol("config".into()))?
    else {
        return Err("config must resolve".into());
    };
    assert!(capped);
    assert_eq!(symbols.len(), 64);
    assert!(symbols.iter().all(|s| s.name == "config"));
    Ok(())
}

#[test]
fn display_name_preserves_declared_casing_across_outline_target_and_refs() -> TestResult {
    let repo = TestRepo::build(
        "display-name",
        &[
            ("src/types.rs", "pub type Type = u32;\n"),
            (
                "src/use_type.rs",
                "use crate::types::Type;\npub fn make() -> Type { 1 }\n",
            ),
            (
                "web/iface.ts",
                "export interface Interface { id: number; }\n",
            ),
            (
                "web/use_iface.ts",
                "import { Interface } from './iface';\nexport const x: Interface = { id: 1 };\n",
            ),
            (
                "pkg/store.go",
                "package store\n\ntype Store struct{}\n\nfunc (s *Store) store() {}\n",
            ),
            (
                "pkg/use_store.go",
                "package store\n\nfunc call(s *Store) { s.store() }\n",
            ),
            (
                "cpp/widget.hpp",
                "struct Widget {\n  int id;\n};\n\nWidget widget() {\n  return Widget{1};\n}\n",
            ),
            (
                "cpp/main.cpp",
                "#include \"widget.hpp\"\nint main() { auto w = widget(); return w.id; }\n",
            ),
        ],
    )?;
    let reader = repo.reader()?;

    let cases = [
        ("src/types.rs", "Type", "Type", "src/use_type.rs"),
        ("web/iface.ts", "Interface", "Interface", "web/use_iface.ts"),
        ("pkg/store.go", "Store.store", "store", "pkg/use_store.go"),
        ("cpp/widget.hpp", "widget", "widget", "cpp/main.cpp"),
    ];
    for (file_path, query, expected_name, caller_path) in cases {
        let Answer::Found(out) = outline(
            &reader,
            &OutlineRequest::new(Target::File(file_path.into())),
        )?
        else {
            return Err(format!("outline failed for {file_path}").into());
        };
        assert!(
            out.entries.iter().any(|e| e.name == expected_name),
            "outline of {file_path} must keep declared casing {expected_name}, got {:?}",
            out.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );

        let Resolved::Symbols { symbols, .. } = resolve(&reader, &Target::Symbol(query.into()))?
        else {
            return Err(format!("target {query} must resolve").into());
        };
        assert_eq!(symbols[0].name, expected_name);

        let Answer::Found(found_refs) = refs(
            &reader,
            &repo.root,
            &RefsRequest::new(Target::Symbol(query.into())),
        )?
        else {
            return Err(format!("refs for {query} must resolve").into());
        };
        assert_eq!(found_refs.name, expected_name);
        assert!(
            found_refs.groups.iter().any(|g| g.path == caller_path),
            "refs for {query} must find {caller_path}"
        );
    }
    Ok(())
}

#[test]
fn typo_suggestions_cap_at_three_and_skip_dead_compact_tokens() -> TestResult {
    let mut repo = TestRepo::build(
        "typo-dead",
        &[
            (
                "src/readers.rs",
                "pub struct QueryReader;\npub struct QueryLeader;\npub struct QueryHeader;\npub struct QueryFeeder;\npub struct QueryLoader;\npub fn live_pair() {}\n",
            ),
            ("src/dead.rs", "pub fn dead_pair() {}\n"),
        ],
    )?;
    let reader = repo.reader()?;

    let Resolved::NotFound { suggestions } =
        resolve(&reader, &Target::Symbol("QueryReder".into()))?
    else {
        return Err("QueryReder must not resolve".into());
    };
    assert_eq!(suggestions.len(), 3);
    assert!(
        suggestions.iter().any(|s| s == "QueryReader"),
        "expected QueryReader in {suggestions:?}"
    );

    // Positive control: live_pair matches compact "livepair".
    {
        let snap = reader.snapshot()?;
        let live = se_atlas_search::spellings(&snap, "livepair")?;
        assert!(live.iter().any(|(_, tok)| tok == "live_pair"));
    }

    // Remove src/dead.rs -> dead_pair remains in vocab with zero live postings.
    let removed = repo.remove_and_index("src/dead.rs")?;
    assert!(matches!(removed, PathOutcome::Absent { removed: true }));

    // Before compaction (tombstone in post_delta) and after compaction (df = 0):
    // dead_pair must never pollute fuzzy::spellings or target suggestions.
    for phase in ["post-delta", "post-compaction"] {
        if phase == "post-compaction" {
            repo.store.compact_deltas(&CompactPolicy::default(), true)?;
        }
        let snap = reader.snapshot()?;
        let spellings = se_atlas_search::spellings(&snap, "deadpair")?;
        assert!(
            !spellings.iter().any(|(_, tok)| tok == "dead_pair"),
            "dead compact token polluted spellings in {phase}: {spellings:?}"
        );
        drop(snap);
        let Resolved::NotFound { suggestions } =
            resolve(&reader, &Target::Symbol("deadpair".into()))?
        else {
            return Err("deadpair must not resolve".into());
        };
        assert!(
            !suggestions
                .iter()
                .any(|s| s.eq_ignore_ascii_case("dead_pair"))
        );
    }
    Ok(())
}

#[test]
fn refs_phase_ordering_and_hyphenated_crate_matching() -> TestResult {
    let mut owned: Vec<(String, String)> = (0..MAX_SCAN_FILES + 4)
        .map(|i| (format!("a/noise{i:02}.js"), "dispatch();\n".into()))
        .collect();
    owned.push((
        "lib/core.js".into(),
        "export function dispatch() {}\n".into(),
    ));
    owned.push(("lib/sibling.js".into(), "dispatch();\n".into()));
    owned.push((
        "z/importer.js".into(),
        "import { dispatch } from '../lib/core.js';\ndispatch();\n".into(),
    ));
    owned.push((
        "crates/foo-bar/src/lib.rs".into(),
        "pub fn greet() {}\n".into(),
    ));
    owned.push((
        "crates/app/src/main.rs".into(),
        "use foo_bar::greet;\nfn main() { greet(); }\n".into(),
    ));
    let files: Vec<(&str, &str)> = owned
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let repo = TestRepo::build("refs-order", &files)?;
    let reader = repo.reader()?;

    let Answer::Found(p1) = refs(
        &reader,
        &repo.root,
        &RefsRequest::new(Target::Symbol("dispatch".into())),
    )?
    else {
        return Err("dispatch must resolve".into());
    };
    assert_eq!(p1.imported_candidates, 3);
    assert_eq!(p1.files_read, MAX_SCAN_FILES);
    assert_eq!(p1.next_cursor, Some(MAX_SCAN_FILES));
    assert_eq!(p1.groups[0].path, "z/importer.js");
    assert_eq!(p1.groups[0].accuracy, RefAccuracy::ImportedFile);
    assert_eq!(p1.groups[1].path, "lib/sibling.js");
    assert_eq!(p1.groups[1].accuracy, RefAccuracy::ImportedFile);
    assert!(
        p1.groups[2..]
            .iter()
            .all(|g| g.accuracy == RefAccuracy::NameOnly)
    );

    let mut req2 = RefsRequest::new(Target::Symbol("dispatch".into()));
    req2.cursor = p1.next_cursor;
    let Answer::Found(p2) = refs(&reader, &repo.root, &req2)? else {
        return Err("page 2 must resolve".into());
    };
    assert_eq!(p2.next_cursor, None);
    assert!(
        p2.groups
            .iter()
            .all(|g| g.accuracy == RefAccuracy::NameOnly)
    );

    // Hyphenated crate `crates/foo-bar/src/lib.rs` matches `foo_bar`.
    let Answer::Found(crate_refs) = refs(
        &reader,
        &repo.root,
        &RefsRequest::new(Target::File("crates/foo-bar/src/lib.rs".into())),
    )?
    else {
        return Err("hyphenated crate must resolve".into());
    };
    assert_eq!(crate_refs.name, "foo_bar");
    assert_eq!(crate_refs.groups.len(), 1);
    assert_eq!(crate_refs.groups[0].path, "crates/app/src/main.rs");
    assert_eq!(crate_refs.groups[0].lines[0].line, 1);
    Ok(())
}

#[test]
fn refs_custody_refuses_swapped_link_outside_root() -> TestResult {
    let outside = TempDir::new("refs-outside")?;
    outside.write("swap.js", "probe(); // SYNTHETIC_EXTERNAL_SECRET_MARKER\n")?;
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut custody_repo = TestRepo::build(
        "refs-custody",
        &[
            ("lib/def.js", "export function probe() {}\n"),
            (
                "src/good.js",
                "import { probe } from '../lib/def.js';\nprobe();\n",
            ),
            (
                "src/linked/swap.js",
                "import { probe } from '../../lib/def.js';\nprobe();\n",
            ),
        ],
    )?;
    fs::remove_dir_all(custody_repo.repo.join("src/linked"))?;
    #[cfg(windows)]
    custody_repo
        .repo
        .add_junction("src/linked", outside.path())?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), custody_repo.repo.join("src/linked"))?;

    let custody_reader = custody_repo.reader()?;
    let Answer::Found(found) = refs(
        &custody_reader,
        &custody_repo.root,
        &RefsRequest::new(Target::Symbol("probe".into())),
    )?
    else {
        return Err("probe must resolve".into());
    };
    assert_eq!(found.files_refused, 1);
    assert!(found.groups.iter().any(|g| g.path == "src/good.js"));
    assert!(!found.groups.iter().any(|g| g.path == "src/linked/swap.js"));
    for group in &found.groups {
        for line in &group.lines {
            assert!(!line.text.contains("SYNTHETIC_EXTERNAL_SECRET_MARKER"));
        }
    }
    Ok(())
}

fn seed_impact_acl_rows(repo: &TestRepo, core_file_key: &[u8], compute_key: &[u8]) -> TestResult {
    let conn = repo.store.connection();
    let proj_rec = seed_record(
        conn,
        &RecordSeed {
            record_id: "rec-project-1",
            kind: "decision",
            title: "Project visible decision",
            occurred_unix_ms: 2_000,
            visibility: "project",
        },
    )?;
    let rest_rec = seed_record(
        conn,
        &RecordSeed {
            record_id: "rec-restricted-1",
            kind: "decision",
            title: "SYNTHETIC_RESTRICTED_TITLE",
            occurred_unix_ms: 9_000,
            visibility: "restricted",
        },
    )?;
    seed_mention(conn, proj_rec, "file", core_file_key, "exact")?;
    seed_mention(conn, rest_rec, "file", core_file_key, "exact")?;
    seed_mention(conn, rest_rec, "symbol", compute_key, "exact")?;
    seed_touch(
        conn,
        &TouchSeed {
            target_kind: "file",
            target_key: core_file_key,
            ordinal: 0,
            touch_kind: "note",
            actor: "public-actor",
            at_unix_ms: 5_000,
            source_record: Some(proj_rec),
            restricted_record: None,
        },
    )?;
    seed_touch(
        conn,
        &TouchSeed {
            target_kind: "file",
            target_key: core_file_key,
            ordinal: 1,
            touch_kind: "secret_touch",
            actor: "SYNTHETIC_RESTRICTED_ACTOR",
            at_unix_ms: 9_999_999_999_999,
            source_record: Some(rest_rec),
            restricted_record: Some(rest_rec),
        },
    )?;
    Ok(())
}

#[test]
fn impact_depth2_callers_covering_tests_and_restricted_acl() -> TestResult {
    let repo = TestRepo::build(
        "impact-core",
        &[
            ("src/core.js", "export function compute() {}\n"),
            (
                "src/mid.js",
                "import { compute } from './core.js';\nexport function runMid() { return compute(); }\n",
            ),
            (
                "src/top.js",
                "import { runMid } from './mid.js';\nexport function runTop() { return runMid(); }\n",
            ),
            (
                "src/deep3.js",
                "import { runTop } from './top.js';\nrunTop();\n",
            ),
            ("src/name_only.js", "function loose() { compute(); }\n"),
            (
                "test/direct.test.js",
                "import { compute } from '../src/core.js';\ncompute();\n",
            ),
            (
                "test/helper.js",
                "export { compute } from '../src/core.js';\n",
            ),
            (
                "test/via_helper.test.js",
                "import { compute } from './helper.js';\ncompute();\n",
            ),
            (
                "src/core.test.js",
                "describe('core', () => { compute(); });\n",
            ),
            (
                "crates/inline/src/lib.rs",
                "pub fn solo() {}\n#[cfg(test)]\nmod tests { #[test] fn t() { super::solo(); } }\n",
            ),
        ],
    )?;
    let reader = repo.reader()?;
    let Resolved::Symbols { symbols, .. } = resolve(&reader, &Target::Symbol("compute".into()))?
    else {
        return Err("compute must resolve".into());
    };
    seed_impact_acl_rows(&repo, &file_key("src/core.js"), &symbols[0].key)?;

    let Answer::Found(ans) = impact(
        &reader,
        &ImpactRequest::new(Target::Symbol("compute".into())),
    )?
    else {
        return Err("compute impact must resolve".into());
    };
    assert!(!ans.deadline_reached);
    let callers: Vec<(&str, u32, CallerVia)> = ans
        .callers
        .items
        .iter()
        .map(|c| (c.path.as_str(), c.depth, c.via))
        .collect();
    assert!(callers.contains(&("src/mid.js", 1, CallerVia::Imports)));
    assert!(callers.contains(&("src/top.js", 2, CallerVia::Dependent)));
    assert!(callers.contains(&("src/name_only.js", 1, CallerVia::NameOnly)));
    assert!(!callers.iter().any(|(p, _, _)| *p == "src/deep3.js"));
    assert!(!callers.iter().any(|(p, _, _)| p.contains(".test.")));

    let tests: Vec<(&str, Option<CoverHow>, bool)> = ans
        .tests
        .items
        .iter()
        .map(|t| (t.path.as_str(), t.how, t.via_helper))
        .collect();
    assert!(tests.contains(&("test/direct.test.js", Some(CoverHow::Import), false)));
    assert!(tests.contains(&("test/via_helper.test.js", Some(CoverHow::Import), true)));
    assert!(tests.contains(&("src/core.test.js", Some(CoverHow::Name), false)));

    let Answer::Found(inline_ans) =
        impact(&reader, &ImpactRequest::new(Target::Symbol("solo".into())))?
    else {
        return Err("solo impact must resolve".into());
    };
    assert_eq!(inline_ans.tests.items.len(), 1);
    assert_eq!(inline_ans.tests.items[0].how, Some(CoverHow::Inline));
    assert!(!inline_ans.tests.items[0].via_helper);

    assert_eq!(ans.records.items.len(), 1);
    assert_eq!(ans.records.items[0].record_id, "rec-project-1");
    assert_eq!(ans.restricted_records, 1);
    assert!(
        ans.changes
            .items
            .iter()
            .any(|c| c.actor.as_deref() == Some("public-actor"))
    );
    assert!(
        !ans.changes
            .items
            .iter()
            .any(|c| c.actor.as_deref() == Some("SYNTHETIC_RESTRICTED_ACTOR"))
    );
    Ok(())
}

#[test]
fn impact_caps_and_more_counts_across_all_sections() -> TestResult {
    let mut owned: Vec<(String, String)> =
        vec![("src/hub.js".into(), "export function hub() {}\n".into())];
    for i in 0..35 {
        owned.push((
            format!("src/caller{i:02}.js"),
            "import { hub } from './hub.js';\nhub();\n".into(),
        ));
    }
    for i in 0..22 {
        owned.push((
            format!("test/hub{i:02}.test.js"),
            "import { hub } from '../src/hub.js';\nhub();\n".into(),
        ));
    }
    let cap_files: Vec<(&str, &str)> = owned
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let cap_repo = TestRepo::build("impact-caps", &cap_files)?;
    let hub_key = file_key("src/hub.js");
    for i in 0..12 {
        let id = seed_record(
            cap_repo.store.connection(),
            &RecordSeed {
                record_id: &format!("rec-cap-{i:02}"),
                kind: "note",
                title: "Cap note",
                occurred_unix_ms: 1_000 + i,
                visibility: "project",
            },
        )?;
        seed_mention(cap_repo.store.connection(), id, "file", &hub_key, "exact")?;
        if i < 7 {
            seed_touch(
                cap_repo.store.connection(),
                &TouchSeed {
                    target_kind: "file",
                    target_key: &hub_key,
                    ordinal: i,
                    touch_kind: "note",
                    actor: "actor",
                    at_unix_ms: 2_000 + i,
                    source_record: Some(id),
                    restricted_record: None,
                },
            )?;
        }
    }
    let cap_reader = cap_repo.reader()?;
    let Answer::Found(capped) = impact(
        &cap_reader,
        &ImpactRequest::new(Target::Symbol("hub".into())),
    )?
    else {
        return Err("hub impact must resolve".into());
    };
    assert_eq!(capped.callers.items.len(), MAX_CALLERS);
    assert_eq!(capped.callers.more, 5);
    assert_eq!(capped.tests.items.len(), MAX_TESTS);
    assert_eq!(capped.tests.more, 2);
    assert_eq!(capped.records.items.len(), MAX_RECORDS);
    assert_eq!(capped.records.more, 2);
    assert_eq!(capped.changes.items.len(), MAX_CHANGES);
    assert_eq!(capped.changes.more, 2);
    Ok(())
}

#[test]
fn impact_zero_deadline_returns_found_with_floor_and_no_mislabeled_callers() -> TestResult {
    let repo = TestRepo::build(
        "impact-deadline",
        &[
            ("src/core.js", "export function compute() {}\n"),
            (
                "src/importer.js",
                "import { compute } from './core.js';\ncompute();\n",
            ),
            ("src/name_only.js", "function other() { compute(); }\n"),
            (
                "test/core.test.js",
                "import { compute } from '../src/core.js';\ncompute();\n",
            ),
        ],
    )?;
    let reader = repo.reader()?;
    let mut req = ImpactRequest::new(Target::Symbol("compute".into()));
    req.deadline = Duration::ZERO;
    let Answer::Found(found) = impact(&reader, &req)? else {
        return Err("zero-deadline impact must still return Found".into());
    };
    assert!(found.deadline_reached);
    assert!(
        found.callers.more_is_floor,
        "callers.more_is_floor must be true when deadline prevents a complete caller walk"
    );
    assert!(
        found
            .callers
            .items
            .iter()
            .all(|c| c.via != CallerVia::NameOnly),
        "must not emit mislabeled NameOnly callers after deadline"
    );
    assert!(
        found
            .callers
            .items
            .iter()
            .all(|c| !c.path.ends_with(".test.js")),
        "must not emit covering tests as callers"
    );
    Ok(())
}

fn seed_hooks_acl_rows(repo: &TestRepo, sym_key: &[u8]) -> TestResult {
    let conn = repo.store.connection();
    let key_a = file_key("src/a.js");
    let key_b = file_key("src/b.js");
    let proj1 = seed_record(
        conn,
        &RecordSeed {
            record_id: "hook-proj-1",
            kind: "note",
            title: "Project record 1",
            occurred_unix_ms: 1_000,
            visibility: "project",
        },
    )?;
    let proj2 = seed_record(
        conn,
        &RecordSeed {
            record_id: "hook-proj-2",
            kind: "note",
            title: "Project record 2",
            occurred_unix_ms: 2_000,
            visibility: "project",
        },
    )?;
    let rest1 = seed_record(
        conn,
        &RecordSeed {
            record_id: "hook-rest-1",
            kind: "note",
            title: "SYNTHETIC_HOOK_RESTRICTED",
            occurred_unix_ms: 3_000,
            visibility: "restricted",
        },
    )?;
    // proj1 mentions both files and a symbol -> must still be counted once.
    seed_mention(conn, proj1, "file", &key_a, "exact")?;
    seed_mention(conn, proj1, "file", &key_b, "exact")?;
    seed_mention(conn, proj1, "symbol", sym_key, "exact")?;
    seed_mention(conn, proj2, "file", &key_b, "exact")?;
    seed_mention(conn, rest1, "file", &key_a, "exact")?;
    seed_mention(conn, rest1, "symbol", sym_key, "exact")?;
    seed_touch(
        conn,
        &TouchSeed {
            target_kind: "file",
            target_key: &key_a,
            ordinal: 0,
            touch_kind: "note",
            actor: "public-hook-actor",
            at_unix_ms: 4_000,
            source_record: Some(proj1),
            restricted_record: None,
        },
    )?;
    seed_touch(
        conn,
        &TouchSeed {
            target_kind: "file",
            target_key: &key_a,
            ordinal: 1,
            touch_kind: "secret_touch",
            actor: "SYNTHETIC_HOOK_SECRET_ACTOR",
            at_unix_ms: 9_999_999_999_999,
            source_record: Some(rest1),
            restricted_record: Some(rest1),
        },
    )?;
    Ok(())
}

#[test]
fn hooks_sql_only_no_self_import_and_restricted_acl() -> TestResult {
    let repo = TestRepo::build(
        "hooks-q",
        &[
            ("src/a.js", "export function shared() {}\n"),
            (
                "src/b.js",
                "import { shared as base } from './a.js';\nexport function shared() { return base(); }\n",
            ),
            ("src/c.js", "import { shared } from './b.js';\nshared();\n"),
            ("src/d.js", "import './a.js';\n"),
            (
                "test/a.test.js",
                "import { shared } from '../src/a.js';\nshared();\n",
            ),
        ],
    )?;
    let reader = repo.reader()?;
    let Resolved::Symbols { symbols, .. } = resolve(&reader, &Target::Symbol("shared".into()))?
    else {
        return Err("shared must resolve".into());
    };
    seed_hooks_acl_rows(&repo, &symbols[0].key)?;

    // Delete the entire source tree; hooks must answer from SQLite alone.
    repo.delete_sources()?;

    let Answer::Found(ans) = hooks(&reader, &Target::Symbol("shared".into()))? else {
        return Err("shared hooks must resolve after deleting sources".into());
    };
    let defining: Vec<&str> = ans.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(defining, ["src/a.js", "src/b.js"]);
    // Defining file src/b.js must NOT appear as an importer of src/a.js.
    assert_eq!(ans.importers.items, ["test/a.test.js", "src/c.js"]);
    assert_eq!(ans.mentions, 2);
    assert!(
        ans.changes
            .items
            .iter()
            .any(|c| c.actor.as_deref() == Some("public-hook-actor"))
    );
    assert!(
        !ans.changes
            .items
            .iter()
            .any(|c| c.actor.as_deref() == Some("SYNTHETIC_HOOK_SECRET_ACTOR"))
    );
    Ok(())
}
