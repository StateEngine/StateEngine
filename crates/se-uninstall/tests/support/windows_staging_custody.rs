use super::*;
use crate::windows_policy_fixture::*;
// Staging creation with a user-private descriptor and no label runs on an
// ordinary Medium token; the High label check is the only step substituted.
fn private_sddl() -> Check<String> {
    let user = user()?;
    Ok(format!("O:{user}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})"))
}
fn staged(home: &Home) -> Check<Vec<std::ffi::OsString>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&home.0)? {
        let name = entry?.file_name();
        if name.to_string_lossy().starts_with(".se-uninstall-") {
            names.push(name);
        }
    }
    Ok(names)
}
#[test]
fn created_staging_opens_state_files_through_creation_custody() -> Check {
    let home = Home::new()?;
    let parent = NativeStateFiles::open(&home.0)?;
    let mut judged = None;
    let staging = Staging::create_with(&parent, &private_sddl()?, |created| {
        judged = Some(directory_id(created)?);
        Ok(())
    })?;
    let custody = staging.directory.clone();
    assert_eq!(judged, Some(custody.id));
    let leaf = custody.path.file_name().ok_or("staging path has no leaf")?;
    assert_eq!(staged(&home)?, vec![leaf.to_owned()]);
    assert_eq!(directory_id(staging.pin())?, custody.id);
    drop(staging);
    cleanup_directory(&custody)?;
    assert!(staged(&home)?.is_empty(), "staging directory remained");
    Ok(())
}
#[test]
fn failed_staging_setup_retires_created_directory() -> Check {
    let home = Home::new()?;
    let parent = NativeStateFiles::open(&home.0)?;
    let mut judged = false;
    let failure = match Staging::create_with(&parent, &private_sddl()?, |created| {
        directory_id(created)?;
        judged = true;
        Err(refuse("judge staging setup", "forced setup failure"))
    }) {
        Ok(_) => return Err("forced setup failure returned staging".into()),
        Err(failure) => failure,
    };
    assert!(
        judged,
        "setup failed before reaching the judged step: {failure}"
    );
    assert_eq!(failure.operation, "judge staging setup");
    assert_eq!(failure.source.to_string(), "forced setup failure");
    assert!(failure.pending_paths.is_empty(), "{failure}");
    assert!(failure.cleanup_failures.is_empty(), "{failure}");
    assert!(staged(&home)?.is_empty(), "created staging was not retired");
    Ok(())
}
