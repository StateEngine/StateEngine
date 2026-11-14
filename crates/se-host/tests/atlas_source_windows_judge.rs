//! Native Windows source custody witnesses; Linux runs no substitute.
#![cfg(windows)]
use se_atlas::{
    lifecycle::{AtlasSource, CaseMode},
    model::{CacheLocation, ParseBudget, RelativePath, RootId, RootRegistration},
};
use se_host::atlas_source::NativeAtlasSource;
use se_types::ProjectId;
use std::os::windows::process::CommandExt;
use std::{
    error::Error,
    fs,
    path::PathBuf,
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn Error>>;
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        for p in ["source/junction", "source", "root-link"] {
            let path = self.0.join(p);
            if fs::symlink_metadata(&path).is_ok_and(|m| {
                use std::os::windows::fs::MetadataExt;
                m.file_attributes() & 0x400 != 0
            }) {
                let _ = fs::remove_dir(path);
            }
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let root = std::env::temp_dir().join(format!(
        "se-atlas-win-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&root)?;
    let fixture = Fixture(root);
    fs::create_dir(fixture.0.join("source"))?;
    fs::create_dir(fixture.0.join("outside"))?;
    Ok(fixture)
}
fn registration(f: &Fixture) -> Result<RootRegistration, Box<dyn Error>> {
    Ok(RootRegistration {
        project: ProjectId::from_parts(1, [1; 10])?,
        root: RootId::from_parts(1, [2; 10])?,
        canonical_source_root: f.0.join("source"),
        cache: CacheLocation {
            directory: f.0.join("cache"),
        },
        git_metadata: None,
    })
}
fn budget() -> ParseBudget {
    ParseBudget {
        max_source_bytes: 524288,
        max_rows: 100,
        max_work: Duration::from_millis(200),
        reserved_bytes: 524288,
    }
}
fn junction(link: PathBuf, target: PathBuf) -> Check {
    // mklink is a cmd builtin: its path parser rejects forward slashes and the
    // verbatim prefix returned by canonicalize, although native file APIs accept both.
    fn cmd_path(path: &std::path::Path) -> Result<String, Box<dyn Error>> {
        let text = path
            .to_str()
            .ok_or("junction fixture path is not Unicode")?;
        let text = text.replace('/', "\\");
        let text = text.strip_prefix("\\\\?\\").unwrap_or(&text);
        if text.as_bytes().get(1) != Some(&b':')
            || text.as_bytes().get(2) != Some(&b'\\')
            || text.contains(['\"', '%', '!', '\r', '\n'])
        {
            return Err("junction fixture requires a plain absolute drive-letter path".into());
        }
        Ok(text.to_owned())
    }
    let command = format!(
        "mklink /J \"{}\" \"{}\"",
        cmd_path(&link)?,
        cmd_path(&target)?
    );
    let output = Command::new("cmd.exe")
        .args(["/d", "/c"])
        .raw_arg(command)
        .output()?;
    assert!(
        output.status.success(),
        "native junction creation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    use std::os::windows::fs::MetadataExt;
    assert_ne!(fs::symlink_metadata(link)?.file_attributes() & 0x400, 0);
    Ok(())
}
#[test]
fn native_windows_refuses_ads_devices_and_ambiguous_spellings() -> Check {
    let f = fixture()?;
    fs::write(f.0.join("source/plain.rs"), b"original")?;
    let root = se_proc::NativeSourceRoot::open(&f.0.join("source"))?;
    for name in [
        "plain.rs:stream",
        "plain.rs.",
        "plain.rs ",
        "NUL",
        "NUL.txt",
        "COM1",
    ] {
        assert!(
            RelativePath::new(name).is_err(),
            "portable ingress accepted {name}"
        );
        let result = root.open_relative(name);
        assert!(
            result.is_err() || matches!(result, Ok(None)),
            "native lookup aliased {name}"
        );
    }
    assert_eq!(fs::read(f.0.join("source/plain.rs"))?, b"original");
    Ok(())
}
#[test]
fn native_windows_refuses_intermediate_and_root_junctions() -> Check {
    let f = fixture()?;
    fs::write(f.0.join("outside/sentinel.rs"), b"outside")?;
    junction(f.0.join("source/junction"), f.0.join("outside"))?;
    let source = NativeAtlasSource::open(registration(&f)?, CaseMode::InsensitivePreserving)?;
    let p = RelativePath::new("junction/sentinel.rs")?;
    assert!(source.read(&p, budget()).is_err());
    assert!(source.read_chunk(&p, 0, 16).is_err());
    drop(source);
    junction(f.0.join("root-link"), f.0.join("outside"))?;
    let mut reg = registration(&f)?;
    reg.canonical_source_root = f.0.join("root-link");
    assert!(NativeAtlasSource::open(reg, CaseMode::InsensitivePreserving).is_err());
    assert_eq!(fs::read(f.0.join("outside/sentinel.rs"))?, b"outside");
    Ok(())
}
#[test]
fn native_windows_refuses_root_replacement_instead_of_reporting_absent() -> Check {
    let f = fixture()?;
    let source = NativeAtlasSource::open(registration(&f)?, CaseMode::InsensitivePreserving)?;
    fs::rename(f.0.join("source"), f.0.join("retired"))?;
    fs::create_dir(f.0.join("source"))?;
    let p = RelativePath::new("absent.rs")?;
    assert!(source.read(&p, budget()).is_err());
    assert!(source.read_chunk(&p, 0, 16).is_err());
    Ok(())
}
