use super::*;

type Check = std::result::Result<(), Box<dyn std::error::Error>>;

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(label: &str) -> std::result::Result<Scratch, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "se-adoption-install-{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(Scratch(dir))
}

fn plan_for(
    kind: Kind,
    exe: &Path,
    home: &Path,
    config_home: &Path,
    atlas: bool,
) -> std::result::Result<Plan, Box<dyn std::error::Error>> {
    let entries = match kind {
        Kind::Claude => super::super::settings::hooks(exe, home, atlas)?,
        Kind::Codex => super::super::codex::hooks(exe, home, atlas)?,
    };
    let required = match kind {
        Kind::Claude => super::super::settings::hooks(exe, home, false)?,
        Kind::Codex => super::super::codex::hooks(exe, home, false)?,
    };
    Ok(Plan {
        kind,
        provider: config_home.join("provider"),
        config_home: config_home.to_owned(),
        entries,
        required,
    })
}

fn seed_installed(
    path: &Path,
    plan: &Plan,
) -> std::result::Result<super::super::Registration, Box<dyn std::error::Error>> {
    let planned = super::super::settings::plan(path, &plan.entries)?;
    let reg = super::super::Registration {
        schema: 1,
        settings: NativePath::from_local(path.to_owned())?,
        provider: NativePath::from_local(plan.provider.clone())?,
        config_home: NativePath::from_local(plan.config_home.clone())?,
        hooks: planned.entries.clone(),
        layout: planned.layout.clone(),
        installed: true,
        projects: vec![],
        discovery: None,
        discovery_refusal: None,
        installation: Some("test-inst".into()),
        upgrade: None,
    };
    super::super::settings::commit(path, planned)?;
    Ok(reg)
}

#[test]
fn atlas_disable_after_written_preserves_owner_removal_across_reenable() -> Check {
    let dir = scratch("atlas-removal")?;
    let home = dir.0.join("home");
    let settings = dir.0.join("settings.json");
    let exe = dir.0.join("se");
    let base_plan = plan_for(Kind::Claude, &exe, &home, &dir.0, false)?;
    let mut saved = seed_installed(&settings, &base_plan)?;
    let base_bytes = std::fs::read(&settings)?;

    // Enable Atlas -> upgrade writes Atlas hook and marks it awaiting discovery.
    let atlas_plan = plan_for(Kind::Claude, &exe, &home, &dir.0, true)?;
    let WritePlan::Upgrade(planned) = plan_upgrade(&settings, &atlas_plan, &mut saved)? else {
        return Err("expected WritePlan::Upgrade for new Atlas hook".into());
    };
    super::super::settings::commit(&settings, planned)?;
    saved
        .upgrade
        .as_mut()
        .ok_or("missing upgrade journal")?
        .mark_written();

    // Owner removes Atlas hook before discovery finishes, then disables Atlas.
    std::fs::write(&settings, &base_bytes)?;
    let plan_off = plan_upgrade(&settings, &base_plan, &mut saved)?;
    assert!(matches!(plan_off, WritePlan::None));
    assert!(saved.upgrade.is_none(), "retired discovery work");
    assert_eq!(
        saved.hooks.len(),
        8,
        "published Atlas hook stays in custody"
    );

    // Re-enabling Atlas must NOT re-append the hook the owner removed.
    let plan_back = plan_upgrade(&settings, &atlas_plan, &mut saved)?;
    assert!(matches!(plan_back, WritePlan::None));
    assert_eq!(saved.hooks.len(), 8);
    Ok(())
}

#[test]
fn unpublished_writing_entry_leaves_custody_when_disabled() -> Check {
    let dir = scratch("writing-drop")?;
    let home = dir.0.join("home");
    let settings = dir.0.join("settings.json");
    let exe = dir.0.join("se");
    let base_plan = plan_for(Kind::Claude, &exe, &home, &dir.0, false)?;
    let mut saved = seed_installed(&settings, &base_plan)?;

    // Journal upgrade in `writing` phase without committing settings.
    let atlas_plan = plan_for(Kind::Claude, &exe, &home, &dir.0, true)?;
    let WritePlan::Upgrade(_) = plan_upgrade(&settings, &atlas_plan, &mut saved)? else {
        return Err("expected WritePlan::Upgrade".into());
    };
    assert_eq!(saved.hooks.len(), 8);

    // Disabling Atlas drops the never-written entry from custody.
    let plan_off = plan_upgrade(&settings, &base_plan, &mut saved)?;
    assert!(matches!(plan_off, WritePlan::None));
    assert!(saved.upgrade.is_none());
    assert_eq!(saved.hooks.len(), 7);

    // Re-enabling Atlas now plans installing it cleanly.
    let plan_back = plan_upgrade(&settings, &atlas_plan, &mut saved)?;
    assert!(matches!(plan_back, WritePlan::Upgrade(_)));
    Ok(())
}

#[test]
fn readopt_from_different_executable_path_never_duplicates_hooks() -> Check {
    for (kind, file) in [
        (Kind::Claude, "settings.json"),
        (Kind::Codex, "config.toml"),
    ] {
        let dir = scratch(kind.name())?;
        let home = dir.0.join("home");
        let settings = dir.0.join(file);
        let old_exe = dir.0.join("old dir").join("a'b").join("se");
        let new_exe = dir.0.join("new dir").join("c'd").join("se");

        let old_plan = plan_for(kind, &old_exe, &home, &dir.0, true)?;
        let mut saved = seed_installed(&settings, &old_plan)?;
        let before_hooks = saved.hooks.len();
        assert_eq!(before_hooks, 8);

        let new_plan = plan_for(kind, &new_exe, &home, &dir.0, true)?;
        let write_plan = plan_upgrade(&settings, &new_plan, &mut saved)?;
        assert!(matches!(write_plan, WritePlan::None));
        assert_eq!(saved.hooks.len(), before_hooks);

        for (old, new) in old_plan.entries.iter().zip(&new_plan.entries) {
            assert!(same_hook(old, new), "logical key mismatch for {}", old.0);
        }
    }
    Ok(())
}
