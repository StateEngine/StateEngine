//! Actual production credential adapter; never prints credential bytes/digests.
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
#[path = "../src/route/credential.rs"]
mod credential;
#[allow(
    dead_code,
    reason = "Exercise only the production credential file adapter."
)]
#[path = "../src/route/files.rs"]
mod files;
use se_proc::NativeStateFiles;
use se_types::{Read, Secret};
use std::{
    fs,
    io::{Read as _, Write as _},
    path::PathBuf,
};
type Check = Result<(), Box<dyn std::error::Error>>;
struct Home(cleanup_directory::PrivateDirectory);
impl Home {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = cleanup_directory::private_case_directory()?;
        drop(NativeStateFiles::create(&root)?);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o775))?;
        }
        drop(NativeStateFiles::create(&root.join("state"))?);
        Ok(Self(root.cleanup_on_drop()))
    }
    fn state(&self) -> PathBuf {
        self.0.join("state")
    }
    fn files(&self) -> Result<files::Files, Box<dyn std::error::Error>> {
        Ok(files::Files::open(&self.state())?)
    }
    fn inventory(&self, expected: &[&str]) -> Check {
        let mut actual = fs::read_dir(self.state())?
            .map(|entry| entry.map(|e| e.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        actual.sort();
        let mut names: Vec<_> = expected.iter().map(std::ffi::OsString::from).collect();
        names.sort();
        assert_eq!(
            actual, names,
            "credential publication left unowned staging or an extra file"
        );
        Ok(())
    }
    fn outside(&self) -> Result<Secret, Box<dyn std::error::Error>> {
        let reader = NativeStateFiles::open(&self.state())?;
        let file = reader
            .readback(&self.state().join("credential"))?
            .ok_or("outside credential absent")?;
        let mut bytes = Vec::new();
        file.take(33).read_to_end(&mut bytes)?;
        let secret = Secret::new(bytes).map_err(|_| "outside credential empty")?;
        assert_eq!(secret.expose().len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::metadata(self.state())?.mode() & 0o777, 0o700);
            assert_eq!(
                fs::metadata(self.state().join("credential"))?.mode() & 0o777,
                0o600
            );
            assert_eq!(fs::metadata(&self.0)?.mode() & 0o777, 0o775);
        }
        Ok(secret)
    }
}
fn publication_and_reuse() -> Check {
    let home = Home::new()?;
    let first = credential::initialize(&home.files()?)?;
    let outside = home.outside()?;
    assert!(
        first.expose() == outside.expose(),
        "outside reader differs from published credential"
    );
    for _ in 0..4 {
        let again = credential::initialize(&home.files()?)?;
        assert!(
            again.expose() == first.expose(),
            "retry replaced the create-once credential"
        );
        assert!(credential::require(&home.files()?)?.expose() == first.expose());
    }
    home.inventory(&["credential"])?;
    let other = Home::new()?;
    assert!(
        credential::initialize(&other.files()?)?.expose() != first.expose(),
        "independent homes repeated a credential"
    );
    other.inventory(&["credential"])
}
fn absence_is_not_initialization() -> Check {
    let home = Home::new()?;
    assert!(matches!(
        credential::read(&home.files()?)?,
        Read::Absent { .. }
    ));
    let error = credential::require(&home.files()?)
        .err()
        .ok_or("ordinary runtime allocated a missing credential")?;
    assert!(error.to_string().contains("credential is missing"));
    home.inventory(&[])
}
fn malformed_is_not_replaced() -> Check {
    for count in [0, 1, 31, 33, 64] {
        let home = Home::new()?;
        let native = NativeStateFiles::open(&home.state())?;
        let mut staged = native.create_staging(&home.state())?;
        let prior = vec![b'x'; count];
        staged.file.write_all(&prior)?;
        staged.file.sync_all()?;
        drop(staged.file);
        let path = home.state().join("credential");
        native.publish_no_replace(&staged.path, &path)?;
        assert!(
            credential::initialize(&home.files()?).is_err(),
            "malformed credential accepted or replaced"
        );
        assert!(credential::require(&home.files()?).is_err());
        assert!(
            fs::read(&path)? == prior,
            "corrupt bytes changed during refusal"
        );
        home.inventory(&["credential"])?;
    }
    Ok(())
}
fn native_failure_has_no_publication() -> Check {
    let home = Home::new()?;
    let error = credential::initialize(&home.files()?)
        .err()
        .ok_or("OS RNG failure published a credential")?;
    assert!(
        error.to_string().contains("OS cryptographic random source"),
        "{error}"
    );
    assert!(
        error
            .body
            .remedy(&se_types::RenderCx::default())?
            .text
            .contains("no credential was published"),
        "{error}"
    );
    home.inventory(&[])
}
fn main() -> Check {
    if std::env::args().any(|v| v == "--list") {
        if !std::env::args().any(|v| v == "--ignored") {
            println!("credential_native: test");
        }
        return Ok(());
    }
    se_proc::initialize_file_creation_owner()?;
    if std::env::args().nth(1).as_deref() == Some("--expect-native-failure") {
        native_failure_has_no_publication()?;
        println!("1 passed, 0 failed; native RNG failure precedes every credential/staging write");
        return Ok(());
    }
    publication_and_reuse()?;
    absence_is_not_initialization()?;
    malformed_is_not_replaced()?;
    println!(
        "3 passed, 0 failed; actual credential adapter with outside protected readback; public init NOT GRADED"
    );
    Ok(())
}
