//! Reviewer acceptance tests for JS/TS outline rules, header-cap recovery,
//! extractor v2 reopen migration, history recording, monotonicity, 4,096-generation
//! pruning, and `changes` pagination and cursor integrity.
mod support;

use rusqlite::params;
use se_atlas_index::{
    IndexError,
    extract::{EXTRACTOR_VERSION, SymbolKind, extract, file_key, flags},
    store::{
        BuildOptions, ChangeKind, PathOutcome, RETAINED_GENERATIONS, RebuildReason, Store,
        StoreIdentity, now_unix_ms,
    },
};
use se_atlas_query::{
    Answer, Target,
    changes::{Changes, ChangesAnswer, ChangesRequest, RetentionFloor, Since, changes},
    outline::{DEFAULT_LIMIT as OUTLINE_DEFAULT_LIMIT, Incomplete, OutlineRequest, outline},
};
use std::{thread, time::Duration};
use support::{
    RecordSeed, TestRepo, TestResult, generation_timestamp, hex_encode, meta_generation,
    seed_mention, seed_record, table_count,
};

fn build_js_ts_header_cap_source() -> String {
    let mut text = String::from(
        "export async function build(opts, dependencies = {}) {\n  return dependencies;\n}\n\n\
         export const f: (x: number) => number = (x) => x + 1;\n\n\
         export class Runner {\n\
           list = items.map(x => { return x; });\n\
           add: (a: number, b: number) => number = (a, b) => a + b;\n\
           onDone = async (value: string): Promise<void> => {\n    return;\n  };\n\
           run() {}\n\
         }\n\n\
         export function hugeDefault(opts = {\n",
    );
    for idx in 1..=36 {
        text.push_str(&format!("  k{idx:02}: {idx},\n"));
    }
    text.push_str(
        "}) {\n  return opts;\n}\n\n\
         export function afterResumedCap() {\n  return 1;\n}\n\n\
         export function hugeParams(\n",
    );
    for idx in 1..=36 {
        text.push_str(&format!("  p{idx:02}: number,\n"));
    }
    text.push_str(
        ") {\n  return p01;\n}\n\n\
         export function afterLineCap() {\n  return 2;\n}\n",
    );
    text
}

#[test]
fn js_ts_outline_default_params_callbacks_typed_arrows_and_header_cap() -> TestResult {
    let source = build_js_ts_header_cap_source();
    let extracted = extract("web/runner.ts", source.as_bytes(), false);
    let summary: Vec<(&str, SymbolKind, bool)> = extracted
        .symbols
        .iter()
        .map(|s| (s.name.as_str(), s.kind, s.exported))
        .collect();
    assert_eq!(
        summary,
        [
            ("build", SymbolKind::Function, true),
            ("f", SymbolKind::Function, true),
            ("Runner", SymbolKind::Class, true),
            ("add", SymbolKind::Method, false),
            ("onDone", SymbolKind::Method, false),
            ("run", SymbolKind::Method, false),
            ("afterResumedCap", SymbolKind::Function, true),
            ("afterLineCap", SymbolKind::Function, true),
        ]
    );
    assert!(!summary.iter().any(|(name, _, _)| *name == "list"));
    assert!(!summary.iter().any(|(name, _, _)| *name == "hugeDefault"));
    assert!(!summary.iter().any(|(name, _, _)| *name == "hugeParams"));

    // Confirm the same outline persists through the store and outline query.
    let repo = TestRepo::build("jsts-outline", &[("web/runner.ts", &source)])?;
    let reader = repo.reader()?;
    let Answer::Found(found) = outline(
        &reader,
        &OutlineRequest::new(Target::File("web/runner.ts".into())),
    )?
    else {
        return Err("web/runner.ts must resolve".into());
    };
    let outlined: Vec<(&str, Option<SymbolKind>, u32)> = found
        .entries
        .iter()
        .map(|e| (e.name.as_str(), e.kind, e.depth))
        .collect();
    assert_eq!(
        outlined,
        [
            ("build", Some(SymbolKind::Function), 0),
            ("f", Some(SymbolKind::Function), 0),
            ("Runner", Some(SymbolKind::Class), 0),
            ("add", Some(SymbolKind::Method), 1),
            ("onDone", Some(SymbolKind::Method), 1),
            ("run", Some(SymbolKind::Method), 1),
            ("afterResumedCap", Some(SymbolKind::Function), 0),
            ("afterLineCap", Some(SymbolKind::Function), 0),
        ]
    );
    Ok(())
}

#[test]
fn extractor_v1_reopen_under_v2_preserves_history_and_records() -> TestResult {
    const { assert!(EXTRACTOR_VERSION > 1) };
    let mut repo = TestRepo::build("ext-v1", &[("src/lib.rs", "pub fn alpha() {}\n")])?;
    repo.edit("src/lib.rs", "pub fn alpha() { let _ = 1; }\n")?;
    let commit = [0x42u8; 20];
    let commit_gen = repo.store.record_commit(&commit)?;
    let rec_id = seed_record(
        repo.store.connection(),
        &RecordSeed {
            record_id: "rec-ext-1",
            kind: "note",
            title: "Keep across v2 upgrade",
            occurred_unix_ms: 1_700_000_000_000,
            visibility: "project",
        },
    )?;
    seed_mention(
        repo.store.connection(),
        rec_id,
        "file",
        &file_key("src/lib.rs"),
        "exact",
    )?;
    let before_gen = meta_generation(repo.store.connection())?;
    assert_eq!(before_gen, commit_gen);
    let before_generations = table_count(repo.store.connection(), "generations")?;
    let before_changes = table_count(repo.store.connection(), "changes")?;
    let before_commits = table_count(repo.store.connection(), "observed_commits")?;
    let before_records = table_count(repo.store.connection(), "records")?;
    let epoch_path = repo.store.path().to_path_buf();

    repo.store
        .connection()
        .execute("UPDATE meta SET extractor_version=1 WHERE singleton=1", [])?;
    let db = repo.db.clone();
    let root = repo.root;
    drop(repo.store);

    let (mut reopened, reason) = Store::open(&db, &StoreIdentity::default())?;
    assert_eq!(
        reason,
        Some(RebuildReason::Mismatch("extractor version differs"))
    );
    assert_eq!(reopened.path(), epoch_path.as_path());
    let ver: i64 = reopened.connection().query_row(
        "SELECT extractor_version FROM meta WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(ver, EXTRACTOR_VERSION);
    assert_eq!(meta_generation(reopened.connection())?, before_gen);
    assert_eq!(
        table_count(reopened.connection(), "generations")?,
        before_generations
    );
    assert_eq!(
        table_count(reopened.connection(), "changes")?,
        before_changes
    );
    assert_eq!(
        table_count(reopened.connection(), "observed_commits")?,
        before_commits
    );
    assert_eq!(
        table_count(reopened.connection(), "records")?,
        before_records
    );
    for code_table in [
        "files",
        "vocab",
        "vocab_post",
        "post_delta",
        "file_tok",
        "gram",
        "gram_delta",
        "short",
        "sym",
        "imp",
        "covers",
    ] {
        assert_eq!(
            table_count(reopened.connection(), code_table)?,
            0,
            "{code_table} must be cleared"
        );
    }

    reopened.cold_build(&root, &BuildOptions::default())?;
    assert_eq!(meta_generation(reopened.connection())?, before_gen + 1);
    Ok(())
}

type ChangeSummary = (
    i64,
    Option<ChangeKind>,
    Option<String>,
    Option<String>,
    bool,
);

fn collect_all_changes(
    reader: &se_atlas_index::store::Reader,
) -> Result<Vec<ChangeSummary>, Box<dyn std::error::Error>> {
    let answer_found = match changes(reader, &ChangesRequest::new(Since::ObservedUnixMillis(0)))? {
        ChangesAnswer::Found(found) => found,
        ChangesAnswer::CommitNotObserved { .. } => return Err("unexpected commit answer".into()),
    };
    Ok(answer_found
        .entries
        .into_iter()
        .map(|e| (e.generation, e.kind, e.path, e.symbol, e.baseline_reset))
        .collect())
}

#[test]
fn direct_per_batch_changes_cover_all_kinds_noop_cold_reset_and_remove_order() -> TestResult {
    let mut repo = TestRepo::build("batch-changes", &[("src/base.rs", "pub fn BaseFn() {}\n")])?;
    let reader = repo.reader()?;
    let cold = collect_all_changes(&reader)?;
    assert_eq!(cold.len(), 1);
    assert_eq!(cold[0], (1, Some(ChangeKind::Bulk), None, None, true));

    // Add a new file with multiple mixed-case symbols.
    let added_src = "pub struct ZetaNode {}\n\npub fn AlphaBuild(v: i32) -> i32 {\n    v + 1\n}\n\npub type BetaAlias = u32;\n";
    let PathOutcome::Indexed(add_rep) = repo.edit("src/work.rs", added_src)? else {
        return Err("add must index".into());
    };
    let add_gen = add_rep.generation.ok_or("add must bump generation")?;

    // SignatureChanged.
    let sig_src = "pub struct ZetaNode {}\n\npub fn AlphaBuild(v: i32, w: i32) -> i32 {\n    v + 1\n}\n\npub type BetaAlias = u32;\n";
    let PathOutcome::Indexed(sig_rep) = repo.edit("src/work.rs", sig_src)? else {
        return Err("sig edit must index".into());
    };
    let sig_gen = sig_rep.generation.ok_or("sig edit must bump generation")?;

    // BodyChanged.
    let body_src = "pub struct ZetaNode {}\n\npub fn AlphaBuild(v: i32, w: i32) -> i32 {\n    v + w + 2\n}\n\npub type BetaAlias = u32;\n";
    let PathOutcome::Indexed(body_rep) = repo.edit("src/work.rs", body_src)? else {
        return Err("body edit must index".into());
    };
    let body_gen = body_rep
        .generation
        .ok_or("body edit must bump generation")?;

    // Comment-only FileOnly edit.
    let comment_src = format!("{body_src}// trailing file comment\n");
    let PathOutcome::Indexed(file_only_rep) = repo.edit("src/work.rs", &comment_src)? else {
        return Err("comment edit must index".into());
    };
    let file_only_gen = file_only_rep
        .generation
        .ok_or("comment edit must bump generation")?;

    // Unchanged no-op: no generation bump.
    let gen_before_noop = meta_generation(repo.store.connection())?;
    let PathOutcome::Indexed(noop_rep) = repo.edit("src/work.rs", &comment_src)? else {
        return Err("noop edit must index".into());
    };
    assert_eq!(noop_rep.generation, None);
    assert_eq!(meta_generation(repo.store.connection())?, gen_before_noop);

    // Partial symbol removal in deterministic line order with declared casing.
    let keep_one = "pub fn AlphaBuild(v: i32, w: i32) -> i32 {\n    v + w + 2\n}\n";
    let PathOutcome::Indexed(partial_rm) = repo.edit("src/work.rs", keep_one)? else {
        return Err("partial removal must index".into());
    };
    let partial_rm_gen = partial_rm
        .generation
        .ok_or("partial removal must bump generation")?;

    // Whole-file removal with multiple mixed-case symbols in line order.
    let multi =
        "pub struct GammaType {}\n\npub fn DeltaRun() {}\n\npub const EpsilonMax: u32 = 1;\n";
    repo.edit("src/gone.rs", multi)?;
    let removed = repo.remove_and_index("src/gone.rs")?;
    assert!(matches!(removed, PathOutcome::Absent { removed: true }));
    let full_rm_gen = meta_generation(repo.store.connection())?;

    let all = collect_all_changes(&reader)?;
    let by_gen = |g: i64| -> Vec<(Option<ChangeKind>, Option<String>)> {
        all.iter()
            .filter(|row| row.0 == g)
            .map(|row| (row.1, row.3.clone()))
            .collect()
    };
    assert_eq!(
        by_gen(add_gen),
        [
            (Some(ChangeKind::Added), None),
            (Some(ChangeKind::Added), Some("ZetaNode".into())),
            (Some(ChangeKind::Added), Some("AlphaBuild".into())),
            (Some(ChangeKind::Added), Some("BetaAlias".into())),
        ]
    );
    assert_eq!(
        by_gen(sig_gen),
        [(
            Some(ChangeKind::SignatureChanged),
            Some("AlphaBuild".into())
        )]
    );
    assert_eq!(
        by_gen(body_gen),
        [(Some(ChangeKind::BodyChanged), Some("AlphaBuild".into()))]
    );
    assert_eq!(by_gen(file_only_gen), [(Some(ChangeKind::FileOnly), None)]);
    assert_eq!(
        by_gen(partial_rm_gen),
        [
            (Some(ChangeKind::Removed), Some("ZetaNode".into())),
            (Some(ChangeKind::Removed), Some("BetaAlias".into())),
        ]
    );
    assert_eq!(
        by_gen(full_rm_gen),
        [
            (Some(ChangeKind::Removed), None),
            (Some(ChangeKind::Removed), Some("GammaType".into())),
            (Some(ChangeKind::Removed), Some("DeltaRun".into())),
            (Some(ChangeKind::Removed), Some("EpsilonMax".into())),
        ]
    );
    Ok(())
}

#[test]
fn monotonic_observed_unix_ms_clamps_future_timestamps_without_false_pruned() -> TestResult {
    let mut repo = TestRepo::build("monotonic", &[("src/a.rs", "pub fn one() {}\n")])?;
    let now = now_unix_ms();
    let past = now - 60_000;
    let future = now + 600_000;
    repo.store.connection().execute(
        "UPDATE generations SET observed_unix_ms=?1 WHERE generation=1",
        [past],
    )?;

    let PathOutcome::Indexed(r2) = repo.edit("src/a.rs", "pub fn one() { let _ = 2; }\n")? else {
        return Err("edit 2 must index".into());
    };
    let g2 = r2.generation.ok_or("gen 2")?;
    repo.store.connection().execute(
        "UPDATE generations SET observed_unix_ms=?1 WHERE generation=?2",
        params![future, g2],
    )?;

    let PathOutcome::Indexed(r3) = repo.edit("src/a.rs", "pub fn one() { let _ = 3; }\n")? else {
        return Err("edit 3 must index".into());
    };
    let g3 = r3.generation.ok_or("gen 3")?;
    let ts3 = generation_timestamp(repo.store.connection(), g3)?;
    assert!(ts3 >= future, "gen 3 timestamp {ts3} must be >= {future}");

    let reader = repo.reader()?;
    let ChangesAnswer::Found(since_future) = changes(
        &reader,
        &ChangesRequest::new(Since::ObservedUnixMillis(future)),
    )?
    else {
        return Err("expected Found".into());
    };
    assert!(!since_future.pruned);
    let gens: Vec<i64> = since_future.entries.iter().map(|e| e.generation).collect();
    assert_eq!(gens, [g2, g3]);

    let ChangesAnswer::Found(since_rel) =
        changes(&reader, &ChangesRequest::new(Since::RelativeMillis(30_000)))?
    else {
        return Err("expected Found".into());
    };
    assert!(!since_rel.pruned);
    let rel_gens: Vec<i64> = since_rel.entries.iter().map(|e| e.generation).collect();
    assert_eq!(rel_gens, [g2, g3]);
    Ok(())
}

fn seed_generations_through(repo: &TestRepo, start: i64, end: i64, base_ts: i64) -> TestResult {
    let conn = repo.store.connection();
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let res = (|| -> rusqlite::Result<()> {
        let mut insert_gen = conn.prepare(
            "INSERT INTO generations(generation, observed_unix_ms, event_serial, batch_kind)
             VALUES (?1, ?2, ?1, 'Files')",
        )?;
        for g in start..=end {
            insert_gen.execute(params![g, base_ts + g])?;
        }
        conn.execute("UPDATE meta SET generation=?1 WHERE singleton=1", [end])?;
        Ok(())
    })();
    if res.is_ok() {
        conn.execute_batch("COMMIT")?;
    } else {
        let _ = conn.execute_batch("ROLLBACK");
    }
    res?;
    Ok(())
}

fn seed_change_with_author(repo: &TestRepo, generation: i64, path: &str) -> TestResult {
    let conn = repo.store.connection();
    conn.execute(
        "INSERT INTO changes(generation, ordinal, file_key, path, kind, dependent_generation,
           baseline_reset)
         VALUES (?1, 0, ?2, ?3, 'FileOnly', ?1, 0)",
        params![generation, file_key(path).as_slice(), path],
    )?;
    conn.execute(
        "INSERT INTO authors(generation, ordinal, resolved_at_generation, hint_json)
         VALUES (?1, 0, ?1, '{\"source\":\"seed\"}')",
        [generation],
    )?;
    Ok(())
}

#[test]
fn pruning_at_4352_generations_keeps_fk_integrity_and_updates_floor() -> TestResult {
    assert_eq!(RETAINED_GENERATIONS, 4096);
    let mut repo = TestRepo::build("prune-4352", &[("src/a.rs", "pub fn a() {}\n")])?;
    let base_ts = 1_700_000_000_000i64;
    repo.store.connection().execute(
        "UPDATE generations SET observed_unix_ms=?1 WHERE generation=1",
        [base_ts + 1],
    )?;
    let early_oid = [0x11u8; 20];
    let g2 = repo.store.record_commit(&early_oid)?;
    assert_eq!(g2, 2);
    repo.store.connection().execute(
        "UPDATE generations SET observed_unix_ms=?1 WHERE generation=2",
        [base_ts + 2],
    )?;
    seed_generations_through(&repo, 3, 4351, base_ts)?;
    let kept_oid = [0x22u8; 20];
    repo.store.connection().execute(
        "INSERT INTO observed_commits(oid, generation) VALUES (?1, 300)",
        [kept_oid.as_slice()],
    )?;
    seed_change_with_author(&repo, 10, "src/a.rs")?;
    seed_change_with_author(&repo, 255, "src/a.rs")?;
    seed_change_with_author(&repo, 256, "src/a.rs")?;
    seed_change_with_author(&repo, 400, "src/a.rs")?;

    // Generation 4352 is divisible by 256 -> prunes generations < 4352 - 4096 = 256.
    let PathOutcome::Indexed(rep) = repo.edit("src/a.rs", "pub fn a() { let _ = 1; }\n")? else {
        return Err("4352 edit must index".into());
    };
    assert_eq!(rep.generation, Some(4352));

    let fk_violations: i64 = repo
        .store
        .connection()
        .prepare("PRAGMA foreign_key_check")?
        .query_map([], |_| Ok(1i64))?
        .count() as i64;
    assert_eq!(fk_violations, 0, "PRAGMA foreign_key_check must be empty");

    for table in ["generations", "changes", "observed_commits", "authors"] {
        let sql = format!("SELECT count(*) FROM {table} WHERE generation < 256");
        let stale: i64 = repo.store.connection().query_row(&sql, [], |r| r.get(0))?;
        assert_eq!(stale, 0, "{table} must have zero rows < 256");
    }
    let retained_authors: i64 = repo.store.connection().query_row(
        "SELECT count(*) FROM authors WHERE generation >= 256",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(retained_authors, 2);

    let reader = repo.reader()?;
    let early_ans = changes(
        &reader,
        &ChangesRequest::new(Since::Commit(hex_encode(&early_oid))),
    )?;
    assert_eq!(
        early_ans,
        ChangesAnswer::CommitNotObserved {
            commit: hex_encode(&early_oid)
        }
    );

    let ChangesAnswer::Found(since_kept) = changes(
        &reader,
        &ChangesRequest::new(Since::Commit(hex_encode(&kept_oid))),
    )?
    else {
        return Err("kept commit must resolve".into());
    };
    assert!(!since_kept.pruned);
    let kept_gens: Vec<i64> = since_kept.entries.iter().map(|e| e.generation).collect();
    assert_eq!(kept_gens, [400, 4352]);

    let ChangesAnswer::Found(old) = changes(
        &reader,
        &ChangesRequest::new(Since::ObservedUnixMillis(base_ts)),
    )?
    else {
        return Err("old timestamp must return retained entries".into());
    };
    assert!(old.pruned);
    assert_eq!(
        old.retention_floor,
        Some(RetentionFloor {
            generation: 256,
            observed_unix_ms: base_ts + 256,
        })
    );
    let old_gens: Vec<i64> = old.entries.iter().map(|e| e.generation).collect();
    assert_eq!(old_gens, [256, 400, 4352]);
    Ok(())
}

fn read_page(
    reader: &se_atlas_index::store::Reader,
    since: Since,
    limit: usize,
    cursor: Option<String>,
) -> Result<Changes, Box<dyn std::error::Error>> {
    match changes(
        reader,
        &ChangesRequest {
            since,
            limit,
            cursor,
        },
    )? {
        ChangesAnswer::Found(found) => Ok(found),
        ChangesAnswer::CommitNotObserved { commit } => Err(format!("unobserved {commit}").into()),
    }
}

#[test]
fn changes_commit_lengths_prefixes_ambiguity_and_unobserved() -> TestResult {
    let mut repo = TestRepo::build("changes-commits", &[("src/a.rs", "pub fn a() {}\n")])?;
    let sha1 = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc,
    ];
    repo.store.record_commit(&sha1)?;
    repo.edit("src/a.rs", "pub fn a() { let _ = 1; }\n")?;

    let sha256 = [0xab; 32];
    repo.store.record_commit(&sha256)?;
    repo.edit("src/a.rs", "pub fn a() { let _ = 2; }\n")?;

    // Two commits sharing a 7-hex-digit prefix ("deadbee").
    let mut amb1 = [0x01; 20];
    amb1[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xe1]);
    let mut amb2 = [0x02; 20];
    amb2[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xe2]);
    repo.store.record_commit(&amb1)?;
    repo.edit("src/a.rs", "pub fn a() { let _ = 3; }\n")?;
    repo.store.record_commit(&amb2)?;
    repo.edit("src/a.rs", "pub fn a() { let _ = 4; }\n")?;

    let reader = repo.reader()?;
    for (commit, expected_len) in [
        (hex_encode(&sha1), 4usize),
        (hex_encode(&sha256), 3),
        ("1234567".into(), 4),
        ("ABABABA".into(), 3),
        ("deadbee1".into(), 2),
    ] {
        let page = read_page(&reader, Since::Commit(commit.clone()), 50, None)?;
        assert_eq!(page.entries.len(), expected_len, "commit {commit}");
    }

    // Ambiguous, short, and non-hex commit prefixes return Invalid.
    for bad in ["deadbee", "123456", "zzzzzzz"] {
        assert!(
            matches!(
                changes(&reader, &ChangesRequest::new(Since::Commit(bad.into()))),
                Err(IndexError::Invalid(_))
            ),
            "{bad} must be Invalid"
        );
    }

    // Unobserved commit returns CommitNotObserved.
    let missing = "feedface00000000000000000000000000000000";
    assert_eq!(
        changes(&reader, &ChangesRequest::new(Since::Commit(missing.into())))?,
        ChangesAnswer::CommitNotObserved {
            commit: missing.into()
        }
    );
    Ok(())
}

#[test]
fn changes_cursor_digests_and_relative_page_stability_across_time_and_edits() -> TestResult {
    let mut repo = TestRepo::build("changes-rel", &[("src/a.rs", "pub fn a() {}\n")])?;
    for n in 1..=4 {
        repo.edit("src/a.rs", &format!("pub fn a() {{ let _ = {n}; }}\n"))?;
    }
    let reader = repo.reader()?;

    let p1 = read_page(&reader, Since::RelativeMillis(250), 2, None)?;
    let cursor = p1.next_cursor.clone().ok_or("page 1 must return cursor")?;
    assert_eq!(p1.entries.len(), 2);

    // Cursor digest rejects mismatched requests and malformed/oversized cursors.
    for (since, bad_cursor) in [
        (Since::RelativeMillis(1_000), cursor.clone()),
        (Since::ObservedUnixMillis(0), cursor.clone()),
        (
            Since::RelativeMillis(250),
            "not-a-valid-cursor-at-all-too-long".into(),
        ),
    ] {
        assert!(matches!(
            changes(
                &reader,
                &ChangesRequest {
                    since,
                    limit: 2,
                    cursor: Some(bad_cursor),
                }
            ),
            Err(IndexError::Invalid(_))
        ));
    }

    // Sleep past the relative window and commit a concurrent edit after Page 1.
    thread::sleep(Duration::from_millis(320));
    repo.edit("src/late.rs", "pub fn late() {}\n")?;

    let mut collected = p1.entries;
    let mut next = Some(cursor);
    while let Some(c) = next {
        let page = read_page(&reader, Since::RelativeMillis(250), 2, Some(c))?;
        assert_eq!(page.through_generation, p1.through_generation);
        collected.extend(page.entries);
        next = page.next_cursor;
    }
    assert!(
        !collected
            .iter()
            .any(|e| e.path.as_deref() == Some("src/late.rs")),
        "concurrent edit after page 1 must stay off bounded pages"
    );
    assert_eq!(collected.len(), 5, "cold build + 4 edits before sleep");

    // Fresh RelativeMillis(250) after the sleep sees only the concurrent edit.
    let fresh = read_page(&reader, Since::RelativeMillis(250), 50, None)?;
    assert!(
        fresh
            .entries
            .iter()
            .all(|e| e.path.as_deref() == Some("src/late.rs"))
    );
    assert!(!fresh.entries.is_empty());
    Ok(())
}

#[test]
fn changes_mid_pagination_pruning_sets_pruned_flag() -> TestResult {
    let mut repo = TestRepo::build("mid-prune", &[("src/a.rs", "pub fn a() {}\n")])?;
    let base_ts = 1_700_000_000_000i64;
    repo.store.connection().execute(
        "UPDATE generations SET observed_unix_ms=?1 WHERE generation=1",
        [base_ts + 1],
    )?;
    seed_generations_through(&repo, 2, 4351, base_ts)?;
    seed_change_with_author(&repo, 10, "src/a.rs")?;
    seed_change_with_author(&repo, 20, "src/a.rs")?;
    seed_change_with_author(&repo, 300, "src/a.rs")?;
    seed_change_with_author(&repo, 400, "src/a.rs")?;

    let reader = repo.reader()?;
    let p1 = read_page(&reader, Since::ObservedUnixMillis(base_ts + 10), 1, None)?;
    assert!(!p1.pruned);
    assert_eq!(p1.through_generation, 4351);
    assert_eq!(p1.entries.len(), 1);
    assert_eq!(p1.entries[0].generation, 10);
    let cursor = p1.next_cursor.ok_or("page 1 must return cursor")?;

    // Trigger pruning at generation 4352 (floor moves to 256, past cursor gen 10).
    let PathOutcome::Indexed(rep) = repo.edit("src/a.rs", "pub fn a() { let _ = 9; }\n")? else {
        return Err("edit 4352 must index".into());
    };
    assert_eq!(rep.generation, Some(4352));

    let p2 = read_page(
        &reader,
        Since::ObservedUnixMillis(base_ts + 10),
        10,
        Some(cursor),
    )?;
    assert!(p2.pruned, "pruning past cursor position must set pruned");
    assert_eq!(p2.through_generation, 4351);
    assert_eq!(
        p2.retention_floor,
        Some(RetentionFloor {
            generation: 256,
            observed_unix_ms: base_ts + 256,
        })
    );
    let gens: Vec<i64> = p2.entries.iter().map(|e| e.generation).collect();
    assert_eq!(gens, [300, 400]);
    Ok(())
}

#[test]
fn outline_depth_first_hierarchy_symbol_root_and_300_cap() -> TestResult {
    let hierarchy = concat!(
        "pub mod sub {\n",
        "    pub struct Inner;\n",
        "    impl Inner {\n",
        "        pub fn deep() {}\n",
        "    }\n",
        "}\n",
        "pub fn tail() {}\n",
    );
    let mut big = String::new();
    for i in 0..320 {
        big.push_str(&format!("pub fn f{i:03}() {{}}\n"));
    }
    let repo = TestRepo::build(
        "outline-hier",
        &[("src/tree.rs", hierarchy), ("src/big.rs", &big)],
    )?;
    let reader = repo.reader()?;

    let Answer::Found(tree) = outline(
        &reader,
        &OutlineRequest::new(Target::File("src/tree.rs".into())),
    )?
    else {
        return Err("tree.rs must resolve".into());
    };
    let dfs: Vec<(&str, u32)> = tree
        .entries
        .iter()
        .map(|e| (e.name.as_str(), e.depth))
        .collect();
    assert_eq!(
        dfs,
        [
            ("sub", 0),
            ("Inner", 1),
            ("Inner", 1),
            ("deep", 2),
            ("tail", 0),
        ]
    );
    assert_eq!(tree.incomplete, None);

    let Answer::Found(sub_only) =
        outline(&reader, &OutlineRequest::new(Target::Symbol("sub".into())))?
    else {
        return Err("sub must resolve".into());
    };
    let sub_dfs: Vec<(&str, u32)> = sub_only
        .entries
        .iter()
        .map(|e| (e.name.as_str(), e.depth))
        .collect();
    assert_eq!(
        sub_dfs,
        [("sub", 0), ("Inner", 1), ("Inner", 1), ("deep", 2)]
    );

    let Answer::Found(capped) = outline(
        &reader,
        &OutlineRequest::new(Target::File("src/big.rs".into())),
    )?
    else {
        return Err("big.rs must resolve".into());
    };
    assert_eq!(capped.entries.len(), OUTLINE_DEFAULT_LIMIT);
    assert_eq!(capped.omitted, 20);
    Ok(())
}

#[test]
fn outline_distinguishes_refused_not_found_and_incomplete_variants() -> TestResult {
    let minified = format!("var x = \"{}\";\n", "a".repeat(5_000));
    let repo = TestRepo::build_bytes(
        "outline-inc",
        &[
            ("assets/blob.bin", b"hdr\0payload"),
            ("dist/app.js", minified.as_bytes()),
            ("src/trunc.rs", b"pub fn t() {}\n"),
            ("src/fail.rs", b"pub fn e() {}\n"),
        ],
    )?;
    repo.store.connection().execute(
        "UPDATE files SET flags=?1 WHERE path='src/trunc.rs'",
        [flags::TRUNCATED],
    )?;
    repo.store.connection().execute(
        "UPDATE files SET flags=?1 WHERE path='src/fail.rs'",
        [flags::EXTRACT_FAILED],
    )?;
    let reader = repo.reader()?;

    assert!(matches!(
        outline(&reader, &OutlineRequest::new(Target::Auto(".env".into())))?,
        Answer::Refused { .. }
    ));
    assert!(matches!(
        outline(
            &reader,
            &OutlineRequest::new(Target::File("src/missing.rs".into()))
        )?,
        Answer::NotFound { .. }
    ));
    for (path, expected) in [
        ("assets/blob.bin", Incomplete::Binary),
        ("dist/app.js", Incomplete::Minified),
        ("src/trunc.rs", Incomplete::Truncated),
        ("src/fail.rs", Incomplete::ExtractFailed),
    ] {
        let Answer::Found(ans) = outline(&reader, &OutlineRequest::new(Target::File(path.into())))?
        else {
            return Err(format!("{path} must resolve").into());
        };
        assert_eq!(ans.incomplete, Some(expected), "{path}");
    }
    Ok(())
}
