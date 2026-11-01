use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
struct Home(PathBuf);
impl Home {
    fn new() -> Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "se-path-fit-{}-{} with spaces",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir(&root)?;
        Ok(Self(root))
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("owned path fixture {}: {error}", self.0.display());
        }
    }
}
fn same_file(input: &Path, expected: &[u8]) -> Result<PathBuf> {
    let output = se_proc::canonicalize_path(input)?;
    assert_eq!(fs::read(&output)?, expected);
    assert_eq!(fs::canonicalize(&output)?, fs::canonicalize(input)?);
    Ok(output)
}
#[test]
fn ordinary_paths_remain_readable_with_spaces_unicode_and_dot_components() -> Result {
    let home = Home::new()?;
    fs::create_dir(home.0.join("nested"))?;
    let name = "document-λ.txt";
    fs::write(home.0.join(name), b"outside readback")?;
    let input = home.0.join("nested").join("..").join(name);
    let output = same_file(&input, b"outside readback")?;
    #[cfg(windows)]
    assert!(
        matches!(output.components().next(),Some(std::path::Component::Prefix(prefix)) if matches!(prefix.kind(),std::path::Prefix::Disk(_))),
        "ordinary drive path retained a verbatim prefix: {}",
        output.display()
    );
    #[cfg(not(windows))]
    assert_eq!(output, fs::canonicalize(input)?);
    assert_eq!(
        se_proc::canonicalize_path(home.0.join("absent"))
            .err()
            .ok_or("absent path invented")?
            .kind(),
        std::io::ErrorKind::NotFound
    );
    Ok(())
}
#[cfg(windows)]
#[test]
fn a_name_requiring_verbatim_semantics_cannot_be_redirected_to_its_plain_alias() -> Result {
    let home = Home::new()?;
    let verbatim = fs::canonicalize(&home.0)?;
    fs::write(verbatim.join("literal"), b"plain alias")?;
    let special = verbatim.join("literal.");
    fs::write(&special, b"verbatim-only name")?;
    let output = same_file(&special, b"verbatim-only name")?;
    assert!(
        matches!(output.components().next(),Some(std::path::Component::Prefix(prefix)) if matches!(prefix.kind(),std::path::Prefix::VerbatimDisk(_))),
        "inequivalent plain alias replaced verbatim semantics"
    );
    assert_eq!(fs::read(home.0.join("literal"))?, b"plain alias");
    fs::remove_file(special)?;
    Ok(())
}
#[cfg(windows)]
#[test]
#[ignore = "requires the existing localhost administrative share; never creates a share"]
fn existing_unc_share_resolves_to_a_plain_unc_path_with_identical_bytes() -> Result {
    let home = Home::new()?;
    fs::write(home.0.join("document.txt"), b"native UNC readback")?;
    let canonical = fs::canonicalize(&home.0)?;
    let mut components = canonical.components();
    let Some(std::path::Component::Prefix(prefix)) = components.next() else {
        return Err("missing native drive prefix".into());
    };
    let drive = match prefix.kind() {
        std::path::Prefix::Disk(drive) | std::path::Prefix::VerbatimDisk(drive) => drive,
        _ => return Err("fixture temp is not on a local drive".into()),
    };
    let mut unc = PathBuf::from(format!(r"\\localhost\{}$", char::from(drive)));
    unc.push(components.as_path());
    unc.push("document.txt");
    let output = same_file(&unc, b"native UNC readback")?;
    assert!(
        matches!(output.components().next(),Some(std::path::Component::Prefix(prefix)) if matches!(prefix.kind(),std::path::Prefix::UNC(_, _))),
        "equivalent UNC path retained a device prefix: {}",
        output.display()
    );
    Ok(())
}
