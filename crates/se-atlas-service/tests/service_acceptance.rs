//! End-to-end acceptance tests for live OS watching, custody/policy boundaries,
//! freshness honesty, failure preservation, and clean shutdown on `se_atlas_service::Root`.

mod support;

use rusqlite::Connection;
use se_atlas_service::{Root, RootSpec};
use se_types::{
    Read,
    code::{
        AtlasPrincipal, BulkReason, ChangeBaseline, CodeChange, CoverageReason, IndexState,
        SearchKind,
    },
};
use std::{
    fs, thread,
    time::{Duration, Instant, SystemTime},
};
use support::*;

#[test]
fn live_watcher_settles_tracks_edits_deletes_and_git_head() -> TestResult {
    let commit_one = "1111111111111111111111111111111111111111";
    let commit_two = "2222222222222222222222222222222222222222";
    let started = Instant::now();
    let mut live = LiveRoot::start(
        "live-watch",
        &[
            (".git/HEAD", "ref: refs/heads/main\n"),
            (".git/refs/heads/main", &format!("{commit_one}\n")),
            ("src/lib.rs", "pub fn initial_anchor() -> u32 { 1 }\n"),
            ("src/math.rs", "pub fn old_alpha_calc() -> i32 { 10 }\n"),
        ],
    )?;
    let summary = wait_current(live.root()?, SETTLE_TIMEOUT)?;
    assert!(
        started.elapsed() < SETTLE_TIMEOUT,
        "clean repo must settle under {SETTLE_TIMEOUT:?}"
    );
    assert!(summary.coverage.watch_discovery_complete);
    assert!(summary.coverage.watched_directories >= 1);

    // Create a new file and confirm live visibility in find.
    live.repo.write(
        "src/live_added.rs",
        "pub fn fresh_live_symbol() -> u32 { 42 }\n",
    )?;
    wait_find_path(live.root()?, "fresh_live_symbol", "src/live_added.rs")?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;

    // Edit an existing file and confirm both find and outline reflect the change.
    live.repo
        .write("src/math.rs", "pub fn updated_beta_calc() -> i32 { 99 }\n")?;
    wait_find_path(live.root()?, "updated_beta_calc", "src/math.rs")?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;
    let old_q = find_query(SearchKind::All, "old_alpha_calc", budget(20, 65_536)?, None)?;
    let old_res = present(live.root()?.find(&old_q, &DenyAllRecords)?.data)?;
    assert!(
        old_res.page.items().is_empty(),
        "edited-away symbol must vanish"
    );
    let outlined = present(
        live.root()?
            .outline(&outline_query("src/math.rs")?, &DenyAllRecords)?
            .data,
    )?;
    let names: Vec<&str> = outlined.symbols.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"updated_beta_calc"));
    assert!(!names.contains(&"old_alpha_calc"));

    // Delete a file and verify its ghost is removed completely.
    fs::remove_file(live.repo.join("src/live_added.rs"))?;
    wait_until(QUERY_TIMEOUT, "deleted file removed", || {
        if live.root()?.summary()?.state != IndexState::Current {
            return Ok(None);
        }
        let q = find_query(
            SearchKind::All,
            "fresh_live_symbol",
            budget(20, 65_536)?,
            None,
        )?;
        let ans = live.root()?.find(&q, &DenyAllRecords)?;
        let res = present(ans.data)?;
        Ok((res.page.items().is_empty() && ans.index.negative_complete()).then_some(()))
    })?;

    // Advance .git/refs/heads/main and confirm live Git HEAD observation works.
    live.repo
        .write(".git/refs/heads/main", &format!("{commit_two}\n"))?;
    let viewer = AtlasPrincipal::Agent(agent_id(1)?);
    wait_until(QUERY_TIMEOUT, "observed second git commit", || {
        let q = changes_query(
            ChangeBaseline::ObservedCommitPrefix("2222222".into()),
            20,
            None,
        )?;
        let ans = live.root()?.changes(&q, &viewer)?;
        Ok(matches!(ans.data, Read::Present { .. }).then_some(()))
    })?;

    live.stop(STOP_TIMEOUT)
}

#[test]
fn secrets_directory_create_rename_and_delete_round_trip() -> TestResult {
    let mut live = LiveRoot::start("secrets-dir", &[("src/lib.rs", "pub fn root_entry() {}\n")])?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;

    live.repo.write(
        "src/secrets/provider.rs",
        "pub fn secret_provider_lookup() -> bool { true }\n",
    )?;
    wait_find_path(
        live.root()?,
        "secret_provider_lookup",
        "src/secrets/provider.rs",
    )?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;

    // Rename `src/secrets/` -> `src/vault_moved/` and verify old ghosts disappear.
    fs::rename(
        live.repo.join("src/secrets"),
        live.repo.join("src/vault_moved"),
    )?;
    wait_until(QUERY_TIMEOUT, "renamed secrets dir reconciled", || {
        if live.root()?.summary()?.state != IndexState::Current {
            return Ok(None);
        }
        let q = find_query(
            SearchKind::All,
            "secret_provider_lookup",
            budget(20, 65_536)?,
            None,
        )?;
        let res = present(live.root()?.find(&q, &DenyAllRecords)?.data)?;
        let paths = code_hit_paths(&res);
        let moved = paths.iter().any(|p| p == "src/vault_moved/provider.rs")
            && !paths.iter().any(|p| p == "src/secrets/provider.rs");
        Ok(moved.then_some(()))
    })?;
    let old_outline = live
        .root()?
        .outline(&outline_query("src/secrets/provider.rs")?, &DenyAllRecords)?;
    assert!(!matches!(old_outline.data, Read::Present { .. }));

    // Recreate `src/secrets/` with a file, wait until indexed, then delete the whole directory.
    live.repo.write(
        "src/secrets/ephemeral.rs",
        "pub fn secret_dir_removed_canary() {}\n",
    )?;
    wait_find_path(
        live.root()?,
        "secret_dir_removed_canary",
        "src/secrets/ephemeral.rs",
    )?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;

    fs::remove_dir_all(live.repo.join("src/secrets"))?;
    wait_until(QUERY_TIMEOUT, "deleted secrets dir cleaned up", || {
        if live.root()?.summary()?.state != IndexState::Current {
            return Ok(None);
        }
        let q = find_query(
            SearchKind::All,
            "secret_dir_removed_canary",
            budget(20, 65_536)?,
            None,
        )?;
        let res = present(live.root()?.find(&q, &DenyAllRecords)?.data)?;
        Ok(res.page.items().is_empty().then_some(()))
    })?;
    let gone_outline = live
        .root()?
        .outline(&outline_query("src/secrets/ephemeral.rs")?, &DenyAllRecords)?;
    assert!(!matches!(gone_outline.data, Read::Present { .. }));

    live.stop(STOP_TIMEOUT)
}

#[test]
fn custody_and_policy_refuse_links_and_private_files_while_indexing_code() -> TestResult {
    let outside = TempDir::new("custody-outside")?;
    outside.write(
        "leaked.rs",
        "pub fn outside_link_canary_9917() -> &'static str { \"EXFIL_SECRET_9917\" }\n",
    )?;

    let mut repo = TempDir::new("custody-repo")?;
    repo.write("src/app.rs", "pub fn app_entry() {}\n")?;
    repo.write(
        "auth/credentials.py",
        "def load_credentials_helper():\n    return True\n",
    )?;
    repo.write(".env", "API_KEY=ENV_CANARY_8821\n")?;
    repo.write("secrets.yaml", "token: YAML_CANARY_8822\n")?;
    repo.write("credentials", "BARE_CRED_CANARY_8823\n")?;
    repo.write("deploy/secrets/db.yaml", "password: NESTED_DB_8824\n")?;
    repo.add_dir_link("src/linked_outside", outside.path())?;

    let state = TempDir::new("custody-state")?;
    let mut live = LiveRoot::start_in(repo, state)?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;

    for forbidden in [
        "outside_link_canary_9917",
        "EXFIL_SECRET_9917",
        "ENV_CANARY_8821",
        "YAML_CANARY_8822",
        "BARE_CRED_CANARY_8823",
        "NESTED_DB_8824",
    ] {
        let q = find_query(SearchKind::All, forbidden, budget(20, 65_536)?, None)?;
        let res = present(live.root()?.find(&q, &DenyAllRecords)?.data)?;
        assert!(
            res.page.items().is_empty(),
            "forbidden token {forbidden} leaked into search results"
        );
    }

    let linked_outline = live.root()?.outline(
        &outline_query("src/linked_outside/leaked.rs")?,
        &DenyAllRecords,
    )?;
    assert!(!matches!(linked_outline.data, Read::Present { .. }));

    for private in [
        ".env",
        "secrets.yaml",
        "credentials",
        "deploy/secrets/db.yaml",
    ] {
        let out = live
            .root()?
            .outline(&outline_query(private)?, &DenyAllRecords)?;
        match out.data {
            Read::Unknown { what } => assert!(
                what.contains("private file"),
                "expected private-file refusal for {private}, got: {what}"
            ),
            other => return Err(format!("expected refusal for {private}, got {other:?}").into()),
        }
    }

    wait_find_path(
        live.root()?,
        "load_credentials_helper",
        "auth/credentials.py",
    )?;
    let py_outline = present(
        live.root()?
            .outline(&outline_query("auth/credentials.py")?, &DenyAllRecords)?
            .data,
    )?;
    assert!(
        py_outline
            .symbols
            .iter()
            .any(|s| s.name == "load_credentials_helper")
    );

    // Live writes to private files or outside links must also leak zero bytes.
    live.repo.write("sub/.env", "LIVE_ENV_CANARY_8825\n")?;
    outside.write("live_leak.rs", "pub fn live_outside_canary_8826() {}\n")?;
    live.repo
        .write("src/fence_ok.rs", "pub fn policy_fence_ok() {}\n")?;
    wait_find_path(live.root()?, "policy_fence_ok", "src/fence_ok.rs")?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;
    for forbidden in ["LIVE_ENV_CANARY_8825", "live_outside_canary_8826"] {
        let q = find_query(SearchKind::All, forbidden, budget(20, 65_536)?, None)?;
        let res = present(live.root()?.find(&q, &DenyAllRecords)?.data)?;
        assert!(res.page.items().is_empty(), "live {forbidden} leaked");
    }

    live.stop(STOP_TIMEOUT)
}

#[test]
fn symbol_find_degrades_on_stale_edit_instead_of_false_absent() -> TestResult {
    let mut live = LiveRoot::start(
        "stale-sym",
        &[("src/sym.rs", "pub fn stale_sym_v0() -> u32 { 0 }\n")],
    )?;
    let mut summary = wait_current(live.root()?, SETTLE_TIMEOUT)?;

    let mut observed_degraded = false;
    for round in 0..3u32 {
        let old_name = format!("stale_sym_v{round}");
        let new_name = format!("stale_sym_v{}", round + 1);
        let gen_before = summary.generation.map_or(0, |g| g.0);
        live.repo.write(
            "src/sym.rs",
            &format!("pub fn {new_name}() -> u32 {{ {} }}\n", round + 1),
        )?;
        let q = find_query(SearchKind::Symbol, &old_name, budget(20, 65_536)?, None)?;
        let ans = live.root()?.find(&q, &DenyAllRecords)?;
        let gen_now = ans.index.generation.map_or(0, |g| g.0);
        if gen_now == gen_before {
            let res = present(ans.data)?;
            assert!(
                res.page.items().is_empty(),
                "stale symbol ghost must be dropped"
            );
            assert!(
                matches!(ans.index.state, IndexState::Updating { .. }),
                "stale symbol find must degrade to Updating, got {:?}",
                ans.index.state
            );
            assert!(
                !res.page.window().complete() && res.page.window().exit_code(false) == 2,
                "stale symbol find must not return false exit-0 absent"
            );
            assert!(
                ans.index
                    .coverage
                    .reasons
                    .contains(&CoverageReason::StaleSnapshot)
            );
            observed_degraded = true;
            let _ = wait_generation_gt(live.root()?, gen_before, SETTLE_TIMEOUT)?;
            wait_find_path(live.root()?, &new_name, "src/sym.rs")?;
            break;
        }
        summary = wait_current(live.root()?, SETTLE_TIMEOUT)?;
    }
    assert!(
        observed_degraded,
        "expected query to observe the pre-commit stale symbol window"
    );

    live.stop(STOP_TIMEOUT)
}

#[test]
fn mass_touch_over_hundred_files_does_not_trigger_cold_rebuild() -> TestResult {
    let repo = TempDir::new("mass-touch-repo")?;
    for idx in 0..110u32 {
        repo.write(
            &format!("src/m_{idx:03}.rs"),
            &format!("pub fn touched_fn_{idx:03}() -> u32 {{ {idx} }}\n"),
        )?;
    }
    let state = TempDir::new("mass-touch-state")?;
    let mut live = LiveRoot::start_in(repo, state)?;
    let before = wait_current(live.root()?, SETTLE_TIMEOUT)?;
    let viewer = AtlasPrincipal::Agent(agent_id(9)?);
    let baseline_cursor =
        range_cursor_for(&before, &viewer, before.generation.map_or(0, |g| g.0), None)?;

    let future = SystemTime::now() + Duration::from_secs(5);
    for idx in 0..110u32 {
        let path = live.repo.join(&format!("src/m_{idx:03}.rs"));
        fs::OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_modified(future)?;
    }
    live.repo.write(
        "src/after_touch.rs",
        "pub fn after_mass_touch_fence() -> u32 { 7 }\n",
    )?;
    wait_find_path(live.root()?, "after_mass_touch_fence", "src/after_touch.rs")?;
    let after = wait_current(live.root()?, SETTLE_TIMEOUT)?;
    assert_eq!(after.epoch, before.epoch, "touch burst must keep epoch");

    let changes = collect_all_changes(
        live.root()?,
        ChangeBaseline::Cursor(baseline_cursor),
        &viewer,
        50,
    )?
    .items;
    assert!(
        !changes.iter().any(|change| matches!(
            change,
            CodeChange::Bulk(bulk) if bulk.reason == BulkReason::WatchReconcile
        )),
        "touching 110 files must not trigger a cold rebuild"
    );
    assert!(
        !changes.iter().any(|change| matches!(
            change,
            CodeChange::Edit(edit) if edit.baseline_reset
        )),
        "touching 110 files must not reset the baseline"
    );

    live.stop(STOP_TIMEOUT)
}

#[test]
fn failed_startup_preserves_unreadable_and_stop_shuts_down_cleanly() -> TestResult {
    // 1) Engine::open failure preserves IndexState::Unreadable and refuses feeds cleanly.
    let missing_parent = TempDir::new("missing-src")?;
    let state_open = TempDir::new("missing-state")?;
    let bad_spec = RootSpec {
        project: project_id(2)?,
        root: root_id(2)?,
        source: missing_parent.join("does-not-exist"),
        directory: state_open.path().to_path_buf(),
    };
    let bad_root = Root::start(bad_spec.clone())?;
    let _ = wait_until(QUERY_TIMEOUT, "open failure Unreadable", || {
        let summary = bad_root.summary()?;
        Ok(matches!(summary.state, IndexState::Unreadable { .. }).then_some(summary))
    })?;
    thread::sleep(Duration::from_millis(100));
    assert!(matches!(
        bad_root.summary()?.state,
        IndexState::Unreadable { .. }
    ));
    assert!(feed_batch(&bad_root, &bad_spec.project, None, event_id(1)?, Vec::new()).is_err());
    bad_root.stop(STOP_TIMEOUT)?;

    // 2) Engine::prepare failure preserves Phase::Failed(reason) as Unreadable (never Closed).
    let mut live = LiveRoot::start(
        "prepare-fail",
        &[("src/a.rs", "pub fn prep_seed() -> u32 { 1 }\n")],
    )?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;
    live.stop(STOP_TIMEOUT)?;

    // Drop `files` while keeping valid `meta` + `user_version` so open succeeds and prepare fails.
    let db = epoch_db_path(live.state.path())?;
    {
        let conn = Connection::open(&db)?;
        conn.execute("DROP TABLE files", [])?;
    }
    live.restart()?;
    let failed_prepare = wait_until(QUERY_TIMEOUT, "prepare failure Unreadable", || {
        let summary = live.root()?.summary()?;
        if matches!(
            summary.state,
            IndexState::Opening | IndexState::Updating { .. } | IndexState::ColdIndexing { .. }
        ) {
            return Ok(None);
        }
        Ok(Some(summary))
    })?;
    assert!(
        matches!(failed_prepare.state, IndexState::Unreadable { .. }),
        "prepare failure must stay Unreadable, not {:?}",
        failed_prepare.state
    );
    thread::sleep(Duration::from_millis(120));
    assert!(matches!(
        live.root()?.summary()?.state,
        IndexState::Unreadable { .. }
    ));
    assert!(
        feed_batch(
            live.root()?,
            &live.spec.project,
            None,
            event_id(2)?,
            Vec::new()
        )
        .is_err()
    );
    live.stop(STOP_TIMEOUT)?;

    // 3) Clean shutdown under an active write burst joins within deadline with zero panics.
    let mut burst = LiveRoot::start("clean-stop", &[("src/init.rs", "pub fn init() {}\n")])?;
    let _ = wait_current(burst.root()?, SETTLE_TIMEOUT)?;
    for idx in 0..20u32 {
        burst.repo.write(
            &format!("src/burst_{idx:02}.rs"),
            &format!("pub fn burst_{idx:02}() -> u32 {{ {idx} }}\n"),
        )?;
    }
    let root_handle = burst.root.take().ok_or("missing root handle")?;
    root_handle.stop(STOP_TIMEOUT)?;
    assert_eq!(root_handle.summary()?.state, IndexState::Closed);

    Ok(())
}
