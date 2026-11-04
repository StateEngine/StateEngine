use se_core::ops::installation::{
    TemporaryFileAuthority, UninstallFile, UninstallPathEdit, UninstallPlan,
};
use std::path::{Path, PathBuf};
type Check = Result<(), Box<dyn std::error::Error>>;

/// Real distribution archives include more than 256 executable and notice files.
#[test]
fn complete_release_license_inventory_fits_a_bounded_execution_plan() -> Check {
    let mut plan = fixture();
    let directory = PathBuf::from(&plan.files[0].path)
        .parent()
        .ok_or("parent")?
        .to_owned();
    plan.files = (0..512)
        .map(|index| UninstallFile {
            path: directory
                .join(format!("notice-{index}"))
                .display()
                .to_string(),
            sha256: "a".repeat(64),
        })
        .collect();
    plan.created_directories.clear();
    plan.path_edits.clear();
    let admitted = plan.clone().validate()?;
    assert_eq!(admitted.files().len(), 512);
    // Exercise the real receipt consumer with unit readback inputs too. Native
    // installation/removal is qualified separately through the release archive.
    use se_core::ops::{
        installation::{UninstallEffects, finish_uninstall},
        outputs::*,
    };
    let witness = || Witness {
        state: WitnessState::Witnessed,
        method: "unit readback input".into(),
        observed_at: "unit input".into(),
        detail: None,
    };
    let effects = UninstallEffects {
        install_files: admitted
            .files()
            .iter()
            .map(|f| FileEffect {
                path: f.path.clone(),
                outcome: FileOutcome::Removed,
                witness: witness(),
            })
            .collect(),
        directories: vec![],
        integrations: vec![],
        stops: vec![],
        revocations: vec![],
        path: PathEffect {
            scope: "unit input".into(),
            before_entries: vec![],
            after_entries: vec![],
            witness: witness(),
        },
        path_complete: true,
        preserved: vec![],
        recovery: admitted
            .recovery_directories()
            .iter()
            .map(|d| RecoveryDirectoryEffect {
                directory: d.display().to_string(),
                copies: se_types::Read::Present { value: vec![] },
                temporary_files: se_types::Read::Present { value: vec![] },
                witness: witness(),
            })
            .collect(),
    };
    let receipt = finish_uninstall(
        &admitted,
        se_types::IdempotencyKey::new("license-inventory")?,
        effects,
    )?;
    assert!(receipt.complete);
    assert!(receipt.issues.is_empty());
    assert_eq!(receipt.install_files.len(), 512);
    plan.files.push(UninstallFile {
        path: directory.join("one-too-many").display().to_string(),
        sha256: "a".repeat(64),
    });
    assert!(plan.validate().is_err());
    Ok(())
}

fn fixture() -> UninstallPlan {
    let root = std::env::temp_dir().join("validated-uninstall-contract");
    UninstallPlan {
        state_home: root.join("state"),
        owner: "verified-owner".into(),
        files: vec![UninstallFile {
            path: root.join("program/se").display().to_string(),
            sha256: "a".repeat(64),
        }],
        created_directories: vec![root.join("program").display().to_string()],
        path_edits: vec![UninstallPathEdit {
            target: if cfg!(windows) {
                "HKCU\\Environment\\Path".into()
            } else {
                root.join("profile").display().to_string()
            },
            before_sha256: None,
            before_bytes: Some(0),
            block: "owned path entry".into(),
        }],
    }
}

/// Protects: wire values remain untrusted DTOs; immutable admission does not change the wire schema or lend mutation authority.
#[test]
fn wire_round_trip_requires_fresh_admission() -> Check {
    let dto = fixture();
    let wire = serde_json::to_value(&dto)?;
    let admitted = dto.validate()?;
    assert_eq!(serde_json::to_value(&admitted)?, wire);
    let mut decoded: UninstallPlan = serde_json::from_value(wire)?;
    decoded.owner.clear();
    assert!(decoded.validate().is_err());
    let mut copy = admitted.as_untrusted().clone();
    copy.files.clear();
    assert!(copy.validate().is_err());
    assert_eq!(admitted.owner(), "verified-owner");
    assert_eq!(admitted.files().len(), 1);
    assert_eq!(admitted.state_home(), fixture().state_home);
    assert!(admitted.file_path(1).is_err());
    assert_eq!(
        admitted.file_path(0)?,
        PathBuf::from(&admitted.files()[0].path)
    );
    Ok(())
}

/// Protects: cached parents preserve exact directory membership and recorded digest authority over native-name recognition.
#[test]
fn exact_parents_and_temporary_authority_survive_admission() -> Check {
    let mut dto = fixture();
    let parent = Path::new(&dto.files[0].path)
        .parent()
        .ok_or("parent")?
        .to_owned();
    let recorded = parent.join(".se-publish-recorded-long-token");
    dto.files.push(UninstallFile {
        path: recorded.display().to_string(),
        sha256: "b".repeat(64),
    });
    let admitted = dto.validate()?;
    let parents = admitted.recovery_directories();
    assert_eq!(parents.iter().filter(|path| **path == parent).count(), 1);
    assert!(parents.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(parents.len(), if cfg!(windows) { 1 } else { 2 });
    assert!(matches!(
        admitted.temporary_file(&parent.join(".se-profile-AB12cd34")),
        Some(TemporaryFileAuthority::NativeOwnedName)
    ));
    assert!(matches!(
        admitted.temporary_file(&parent.join(".se-publish-AB12cd34")),
        Some(TemporaryFileAuthority::NativeOwnedName)
    ));
    assert!(
        matches!(admitted.temporary_file(&recorded), Some(TemporaryFileAuthority::Recorded { sha256 }) if sha256 == "b".repeat(64))
    );
    for rejected in [
        parent.join(".se-profile-short"),
        parent.join(".se-profile-AB12cd3-"),
        parent.join("nested/.se-profile-AB12cd34"),
        parent
            .parent()
            .ok_or("grandparent")?
            .join("unplanned/.se-profile-AB12cd34"),
        PathBuf::from(".se-profile-AB12cd34"),
        PathBuf::from(&admitted.files()[0].path),
    ] {
        assert!(
            admitted.temporary_file(&rejected).is_none(),
            "{}",
            rejected.display()
        );
    }
    Ok(())
}

/// Protects: invalid untrusted paths, protected assets, duplicates, owner and edit metadata cannot acquire an execution plan.
#[test]
fn invalid_dtos_never_admit() {
    let mut cases = Vec::new();
    let mut plan = fixture();
    plan.state_home = "relative".into();
    cases.push(plan);
    let mut plan = fixture();
    plan.owner.push('\0');
    cases.push(plan);
    let mut plan = fixture();
    plan.files[0].path = plan.state_home.join("state.db").display().to_string();
    cases.push(plan);
    let mut plan = fixture();
    plan.files[0].path = plan.state_home.join("backups/copy").display().to_string();
    cases.push(plan);
    let mut plan = fixture();
    plan.files.push(plan.files[0].clone());
    cases.push(plan);
    let mut plan = fixture();
    plan.files[0].sha256 = "A".repeat(64);
    cases.push(plan);
    let mut plan = fixture();
    plan.created_directories.push(plan.files[0].path.clone());
    cases.push(plan);
    let mut plan = fixture();
    plan.path_edits[0].before_bytes = Some(1);
    cases.push(plan);
    let mut plan = fixture();
    plan.path_edits[0].block.clear();
    cases.push(plan);
    let mut plan = fixture();
    plan.path_edits[0].target = "unowned-relative-target".into();
    cases.push(plan);
    for (index, plan) in cases.into_iter().enumerate() {
        assert!(plan.validate().is_err(), "case {index}");
    }
}
