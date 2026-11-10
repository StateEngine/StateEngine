#![allow(
    dead_code,
    reason = "The actual human renderer shares other CLI renderers."
)]
#[path = "../src/render/acp.rs"]
mod acp;
#[path = "../src/render/labels.rs"]
mod labels;
#[path = "../src/render/read.rs"]
mod read;
#[path = "../src/render/write.rs"]
mod render_write;
#[path = "../src/render/transcript.rs"]
mod transcript;
use se_core::ops::{AnyOutput, installation::*, outputs::*};
use se_proc::{NativeStateFiles, OwnedFile};
use se_types::{IdempotencyKey, Read};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::{Path, PathBuf},
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
const BEFORE: &[u8] = b"original profile\nowned block\n";
const AFTER: &[u8] = b"original profile\n";
fn witnessed(method: &str) -> Witness {
    Witness {
        state: WitnessState::Witnessed,
        method: method.into(),
        observed_at: "fixture native readback".into(),
        detail: None,
    }
}
fn publish(files: &NativeStateFiles, path: &Path, bytes: &[u8]) -> Check {
    let mut staged = files.create_staging(path.parent().ok_or("fixture parent")?)?;
    staged.file.write_all(bytes)?;
    staged.file.sync_all()?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, path)?;
    Ok(())
}
struct Facts {
    root: PathBuf,
    removed: PathBuf,
    image: PathBuf,
    profile: PathBuf,
    retained: PathBuf,
    directory: PathBuf,
    plan: ValidatedUninstallPlan,
    effects: UninstallEffects,
}
impl Facts {
    fn new() -> Check<Self> {
        se_proc::initialize_file_creation_owner()?;
        let entropy = se_proc::random_secret()?;
        let suffix: String = entropy.expose()[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let root = std::env::temp_dir().join(format!("otto-uninstall-facts-{suffix}"));
        let files = NativeStateFiles::create(&root)?;
        let removed = root.join("removed-asset");
        let image = root.join("retry-image");
        let profile = root.join("fixture-profile");
        let retained = root.join("retained-history");
        let directory = root.join("created-directory");
        publish(&files, &removed, b"owned asset")?;
        publish(&files, &image, b"retry image")?;
        publish(&files, &profile, BEFORE)?;
        publish(&files, &retained, b"retained user data")?;
        std::fs::create_dir(&directory)?;
        OwnedFile::open(&removed)?
            .ok_or("owned asset missing")?
            .remove(Sha256::digest(b"owned asset").into())?;
        assert!(!removed.try_exists()?);
        let native = se_proc::observe_owner_self(&[])?;
        let owner = match native.owner() {
            se_proc::NativeOwner::Unix { effective_uid, .. } => effective_uid.to_string(),
            se_proc::NativeOwner::Windows { sid } => sid.clone(),
        };
        let mut edits = Vec::new();
        let mut integrations = Vec::new();
        let mut before_entries = Vec::new();
        let mut after_entries = Vec::new();
        if cfg!(unix) {
            // Windows PATH is a registry operation; these checks never edit the
            // user's real registry. Native file-effect coverage runs on both OSes.
            OwnedFile::open(&profile)?
                .ok_or("profile missing")?
                .replace(Sha256::digest(BEFORE).into(), AFTER)?;
            assert_eq!(std::fs::read(&profile)?, AFTER);
            edits.push(UninstallPathEdit {
                target: profile.display().to_string(),
                before_sha256: Some(format!("{:x}", Sha256::digest(AFTER))),
                before_bytes: Some(AFTER.len() as u64),
                block: "owned block\n".into(),
            });
            integrations.push(IntegrationEffect {
                path: profile.display().to_string(),
                entry: "owned block\n".into(),
                action: FileOutcome::Removed,
                witness: witnessed("held profile replacement and outside byte readback"),
            });
            before_entries.push(String::from_utf8(BEFORE.to_vec())?);
            after_entries.push(String::from_utf8(AFTER.to_vec())?);
        }
        let plan = UninstallPlan {
            state_home: root.join("state"),
            owner,
            files: vec![
                UninstallFile {
                    path: removed.display().to_string(),
                    sha256: format!("{:x}", Sha256::digest(b"owned asset")),
                },
                UninstallFile {
                    path: image.display().to_string(),
                    sha256: format!("{:x}", Sha256::digest(b"retry image")),
                },
            ],
            created_directories: vec![directory.display().to_string()],
            path_edits: edits,
        };
        let plan = plan.validate()?;
        let effects = UninstallEffects {
            install_files: vec![FileEffect {
                path: removed.display().to_string(),
                outcome: FileOutcome::Removed,
                witness: witnessed("held native file removal and outside absence"),
            }],
            directories: vec![],
            integrations,
            stops: vec![],
            revocations: vec![],
            path: PathEffect {
                scope: "exact fixture-owned targets".into(),
                before_entries,
                after_entries,
                witness: witnessed("outside readback of every planned PATH target"),
            },
            path_complete: true,
            preserved: vec![retained.display().to_string()],
            recovery: vec![],
        };
        Ok(Self {
            root,
            removed,
            image,
            profile,
            retained,
            directory,
            plan,
            effects,
        })
    }
    fn recovery(&mut self) -> Check {
        assert!(se_proc::scan_recovery(&self.root)?.is_empty());
        assert!(se_proc::scan_temporary(&self.root)?.is_empty());
        self.effects.recovery.push(RecoveryDirectoryEffect {
            directory: self.root.display().to_string(),
            copies: Read::Present { value: vec![] },
            temporary_files: Read::Present { value: vec![] },
            witness: witnessed("finite native no-follow recovery and temporary scans"),
        });
        Ok(())
    }
    fn incomplete(&self, output: UninstallOutput) -> Check {
        assert!(!output.complete);
        assert!(
            !output.issues.is_empty(),
            "post-effect validation issue was discarded"
        );
        assert!(
            output
                .install_files
                .iter()
                .any(|file| Path::new(&file.path) == self.removed
                    && matches!(file.outcome, FileOutcome::Removed)
                    && file.witness.state == WitnessState::Witnessed),
            "achieved native removal was discarded"
        );
        assert!(
            output
                .install_files
                .iter()
                .any(|file| Path::new(&file.path) == self.image
                    && matches!(file.outcome, FileOutcome::Pending)
                    && file.witness.state == WitnessState::Unknown),
            "unobserved retry image was not retained as pending"
        );
        assert!(
            output
                .directories
                .iter()
                .any(|entry| Path::new(&entry.path) == self.directory
                    && matches!(entry.outcome, DirectoryOutcome::Pending))
        );
        let mut human = Vec::new();
        render_write::uninstall(&output, &mut human)?;
        let human = String::from_utf8(human)?;
        for text in [
            "removed-asset: removed",
            "retry-image: pending",
            "Uninstall result check:",
            "Uninstall incomplete",
            "retained-history",
            "retry se uninstall",
        ] {
            assert!(human.contains(text), "human output dropped {text}: {human}");
        }
        if cfg!(unix) {
            assert_eq!(
                output.path.before_entries,
                vec![String::from_utf8(BEFORE.to_vec())?]
            );
            assert_eq!(
                output.path.after_entries,
                vec![String::from_utf8(AFTER.to_vec())?]
            );
            for text in ["Before:", "After:", "original profile", "fixture-profile"] {
                assert!(human.contains(text), "lost achieved PATH facts: {human}");
            }
            assert_eq!(std::fs::read(&self.profile)?, AFTER);
        }
        let output: AnyOutput = output.into();
        assert_eq!(
            output.exit_code(),
            2,
            "partial native effects claimed successful completion"
        );
        let json = serde_json::to_value(output)?;
        assert_eq!(json["schema"], "se.uninstall/v1");
        assert_eq!(json["complete"], false);
        assert!(
            !json["issues"]
                .as_array()
                .ok_or("structured issues missing")?
                .is_empty()
        );
        assert!(!self.removed.try_exists()?);
        assert_eq!(std::fs::read(&self.image)?, b"retry image");
        assert_eq!(std::fs::read(&self.retained)?, b"retained user data");
        Ok(())
    }
}
impl Drop for Facts {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.root) {
            eprintln!("retaining owned fixture {}: {error}", self.root.display());
        }
    }
}

/// Protects: achieved native file and PATH changes survive a missing recovery readback; absent evidence is reported as unknown, never empty or complete.
#[test]
fn missing_recovery_keeps_native_effects_in_json_and_human_receipts() -> Check {
    let f = Facts::new()?;
    let output = finish_uninstall(
        &f.plan,
        IdempotencyKey::new("missing-recovery")?,
        f.effects.clone(),
    )?;
    assert!(matches!(output.recovery[0].copies, Read::Unknown { .. }));
    assert!(matches!(
        output.recovery[0].temporary_files,
        Read::Unknown { .. }
    ));
    f.incomplete(output)
}

/// Protects: a later incomplete file/directory readback retains the earlier native removal and restored profile, an explicit pending retry image and a typed state-conflict issue.
#[test]
fn missing_file_readback_preserves_achieved_facts_and_typed_issue() -> Check {
    let mut f = Facts::new()?;
    f.recovery()?;
    let output = finish_uninstall(
        &f.plan,
        IdempotencyKey::new("missing-file")?,
        f.effects.clone(),
    )?;
    assert_eq!(
        serde_json::to_value(&output)?["issues"][0]["code"],
        "state-conflict"
    );
    f.incomplete(output)
}

/// Protects: a fully witnessed uninstall still completes; partial-effect reporting does not turn successful native effects into an uncertain receipt.
#[test]
fn complete_native_readbacks_still_return_success() -> Check {
    let mut f = Facts::new()?;
    f.recovery()?;
    OwnedFile::open(&f.image)?
        .ok_or("retry image missing")?
        .remove(Sha256::digest(b"retry image").into())?;
    std::fs::remove_dir(&f.directory)?;
    assert!(!f.image.try_exists()? && !f.directory.try_exists()?);
    f.effects.install_files.push(FileEffect {
        path: f.image.display().to_string(),
        outcome: FileOutcome::Removed,
        witness: witnessed("held retry image removal and outside absence"),
    });
    f.effects.directories.push(DirectoryEffect {
        path: f.directory.display().to_string(),
        outcome: DirectoryOutcome::Removed,
        witness: witnessed("owned empty fixture directory removal and outside absence"),
    });
    let output = finish_uninstall(
        &f.plan,
        IdempotencyKey::new("complete-effects")?,
        f.effects.clone(),
    )?;
    assert!(output.complete);
    assert_eq!(
        output.install_files.len(),
        2,
        "complete receipt dropped witnessed file removals"
    );
    assert!(output.issues.is_empty());
    let output: AnyOutput = output.into();
    assert_eq!(output.exit_code(), 0);
    assert!(serde_json::to_value(output)?.get("issues").is_none());
    Ok(())
}

/// Protects: a deferred Windows parent keeps achieved effects, recovery, PATH,
/// preserved work and the original key without claiming completion or retrying
/// through its about-to-be-deleted image.
#[test]
fn deferred_report_preserves_facts_and_omits_the_dead_image_retry() -> Check {
    let mut f = Facts::new()?;
    f.recovery()?;
    let output = finish_uninstall(
        &f.plan,
        IdempotencyKey::new("deferred-original-key")?,
        f.effects.clone(),
    )?;
    let mut text = Vec::new();
    render_write::uninstall_deferred(&output, &mut text)?;
    let text = String::from_utf8(text)?;
    for fact in [
        "removed-asset: removed",
        "retry-image: pending",
        "Recovery scan",
        "Preserved:",
        "PATH (",
        "deferred-original-key",
        "Uninstall handoff pending",
    ] {
        assert!(text.contains(fact), "deferred report lost {fact}: {text}");
    }
    assert!(!text.contains("retry se uninstall"));
    assert!(!text.contains("Uninstall incomplete"));
    let structured = serde_json::to_value(AnyOutput::from(output))?;
    assert_eq!(structured["schema"], "se.uninstall/v1");
    assert_eq!(structured["idempotency_key"], "deferred-original-key");
    assert!(!structured["complete"].as_bool().ok_or("completion flag")?);
    assert!(
        !structured["install_files"]
            .as_array()
            .ok_or("file facts")?
            .is_empty()
    );
    Ok(())
}
