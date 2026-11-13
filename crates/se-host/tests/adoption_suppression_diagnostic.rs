//! Reviewer-owned regression: a suppressed managed-ancestry hook leaves a
//! bounded doctor observation that never becomes pending adoption status.
#![cfg(any(target_os = "linux", windows))]

use se_host::adoption::{Action, diagnostic};
use se_types::ProjectId;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn Error>>;

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("cannot remove owned diagnostic fixture: {error}");
        }
    }
}
fn home() -> Result<(Scratch, PathBuf), Box<dyn Error>> {
    let path = std::env::temp_dir().join(format!(
        "se-adoption-diagnostic-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    se_proc::NativeStateFiles::create(&path)?;
    Ok((Scratch(path.clone()), path))
}
fn names(home: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(home.join("adoption-diagnostics"))? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

#[test]
fn every_action_leaves_one_observation_and_never_pending_status() -> Check {
    let (_scratch, home) = home()?;
    assert!(
        diagnostic::observations(&home)?.is_empty(),
        "absent is not an observation"
    );
    for project in [
        ProjectId::from_parts(1, [1; 10])?,
        ProjectId::from_parts(1, [2; 10])?,
    ] {
        for action in Action::ALL {
            // Repeats and a second project replace a slot; they never add one.
            diagnostic::record(&home, &project, action)?;
            diagnostic::record(&home, &project, action)?;
        }
    }
    let mut expected: Vec<String> = Action::ALL
        .iter()
        .map(|a| format!("{}.json", a.name()))
        .collect();
    expected.sort();
    assert_eq!(names(&home)?, expected, "exactly six fixed slots");
    let rows = diagnostic::observations(&home)?;
    assert_eq!(rows.len(), 6);
    let latest = ProjectId::from_parts(1, [2; 10])?;
    assert!(rows.iter().all(|row| row.project == latest));
    assert!(
        !home.join("adoption-status").exists(),
        "a suppressed refusal must not create pending adoption state"
    );
    Ok(())
}

#[test]
fn stray_files_never_widen_the_read_beyond_six() -> Check {
    let (_scratch, home) = home()?;
    let project = ProjectId::from_parts(1, [3; 10])?;
    diagnostic::record(&home, &project, Action::Mail)?;
    fs::write(home.join("adoption-diagnostics").join("extra.json"), b"{}")?;
    let rows = diagnostic::observations(&home)?;
    assert_eq!(rows.len(), 1);
    assert!(rows.len() <= Action::ALL.len());
    Ok(())
}

#[cfg(unix)]
fn plant_oversize(home: &Path, action: Action) -> Check {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(
            home.join("adoption-diagnostics")
                .join(format!("{}.json", action.name())),
        )?;
    file.write_all(&vec![b' '; 4096])?;
    Ok(())
}

/// Documents the behaviour for a damaged slot: both sides refuse loudly
/// (never truncate, never report zero), and write cannot repair it.
#[cfg(unix)]
#[test]
fn oversize_slot_is_refused_on_read_and_write_not_truncated() -> Check {
    let (_scratch, home) = home()?;
    let project = ProjectId::from_parts(1, [4; 10])?;
    diagnostic::record(&home, &project, Action::Stop)?;
    fs::remove_file(home.join("adoption-diagnostics").join("stop.json"))?;
    plant_oversize(&home, Action::Stop)?;
    assert!(diagnostic::observations(&home).is_err());
    for _ in 0..3 {
        assert!(
            diagnostic::record(&home, &project, Action::Stop).is_err(),
            "record keeps failing until the slot is removed by hand"
        );
    }
    Ok(())
}
