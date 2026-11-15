#![cfg(all(windows, feature = "listener"))]
//! Retained public consumers must reread images without native qualification.
use se_host::secode_image::Images;
use se_proc::{NativeExecutablePin, NativeStateFiles, native_ipc::ExecutableStamp};
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    process::Command,
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn journal(create: bool) -> Check {
    let volume = std::env::var("DELTA_VOLUME")?;
    assert!(
        volume.len() == 2 && volume.as_bytes()[0].is_ascii_alphabetic() && volume.ends_with(':')
    );
    let args = if create {
        vec!["usn", "createjournal", "m=8388608", "a=1048576", &volume]
    } else {
        vec!["usn", "deletejournal", "/n", &volume]
    };
    assert!(Command::new("fsutil.exe").args(args).status()?.success());
    let queried = Command::new("fsutil.exe")
        .args(["usn", "queryjournal", &volume])
        .status()?;
    assert_eq!(queried.success(), create, "journal state was not witnessed");
    Ok(())
}
fn package(name: &str) -> Check<(PathBuf, PathBuf)> {
    se_proc::initialize_file_creation_owner()?;
    let root =
        PathBuf::from(std::env::var_os("DELTA_ROOT").ok_or("private root absent")?).join(name);
    let _files = NativeStateFiles::create(&root)?;
    let cli = root.join("secode.exe");
    let server = root.join("secode-server.exe");
    let mut content = vec![b'A'; 4096];
    content[..4].copy_from_slice(b"MZ\0\0");
    for path in [&cli, &server] {
        // Two closed writes establish a positive USN on an active journal.
        fs::write(path, &content)?;
        fs::write(path, &content)?;
    }
    Ok((cli, server))
}
fn clock_helper(mode: &str, path: &Path, args: &[String]) -> Check<serde_json::Value> {
    let helper = std::env::var_os("DELTA_CLOCK_HELPER").ok_or("native fixture helper absent")?;
    let output = Command::new(helper)
        .arg(mode)
        .arg(path)
        .args(args)
        .output()?;
    assert!(
        output.status.success(),
        "native clock fixture failed: {output:?}"
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
fn edit(path: &Path, before: &serde_json::Value, byte: u8) -> Check {
    let after = clock_helper(
        "rewrite",
        path,
        &[
            before["modified"]
                .as_i64()
                .ok_or("mtime absent")?
                .to_string(),
            before["changed"]
                .as_i64()
                .ok_or("change time absent")?
                .to_string(),
            byte.to_string(),
        ],
    )?;
    assert_eq!(before["modified"], after["modified"]);
    assert_eq!(before["changed"], after["changed"]);
    assert_eq!(after["bytes"], 4096);
    Ok(())
}
fn evict_exclusion(path: &Path, byte: u8) -> Check {
    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => drop(file),
        Err(error) => {
            assert_eq!(error.raw_os_error(), Some(32), "unexpected write refusal");
            let external = clock_helper("probe-write", path, &[])?;
            assert_eq!(external["write_opened"], false);
            assert_eq!(external["native_error"], 32);
            let directory = path
                .parent()
                .ok_or("native fixture parent absent")?
                .join(format!("eviction-{byte}"));
            fs::create_dir(&directory)?;
            for index in 0..64 {
                let image = directory.join(format!("image-{index}.exe"));
                let mut bytes = vec![b'E'; 4096];
                bytes[..2].copy_from_slice(b"MZ");
                fs::write(&image, bytes)?;
                assert!(ExecutableStamp::observe(&image)?.is_some());
            }
            drop(OpenOptions::new().read(true).write(true).open(path)?);
            eprintln!("RETAINED_GUARD byte={byte} native_write_denied=32 eviction_released=true");
        }
    }
    Ok(())
}
fn retained(mode: &str, server_selected: bool) -> Check {
    journal(true)?;
    let name = format!("retained-{mode}-{server_selected}");
    let (cli, server) = package(&name)?;
    let path: &Path = if server_selected { &server } else { &cli };
    let before = clock_helper("read", path, &[])?;
    let mut held = None;
    match mode {
        "unavailable" => journal(false)?,
        "held-writer" => held = Some(OpenOptions::new().read(true).write(true).open(path)?),
        "removed" => assert!(
            ExecutableStamp::observe(path)?.is_some(),
            "warm fixture is unqualified"
        ),
        _ => return Err("unknown retained-image mode".into()),
    }
    let mut images = Images::open(&cli)?;
    images.validate()?;
    if mode == "removed" {
        journal(false)?;
        // Losing qualification alone must still accept the unchanged bytes.
        images.validate()?;
    }
    let pin = NativeExecutablePin::open(path)?.ok_or("native image is absent")?;
    let invocation = pin.prepare()?;
    invocation.validate()?;
    let mut previous = ExecutableStamp::observe(path)?;
    assert!(previous.is_some(), "native observation is absent");
    for byte in *b"BCD" {
        // A process-local proof may exclude writes until its bounded cache entry
        // is evicted. Witness that native refusal, then exercise changed bytes
        // through the same retained public consumers after exclusion ends.
        evict_exclusion(path, byte)?;
        // The external fixture edits bytes while our writer, when requested,
        // stays retained across all observations and all three rewrites.
        edit(path, &before, byte)?;
        assert_eq!(
            fs::read(path)?[4095],
            byte,
            "changed bytes were not read back"
        );
        assert!(
            images.validate().is_err(),
            "RETAINED_IMAGE_STALE_ACCEPT mode={mode} server={server_selected} byte={byte}"
        );
        let current = ExecutableStamp::observe(path)?;
        assert!(
            current.is_some() && current != previous,
            "fresh native stamp did not detect changed bytes"
        );
        assert!(
            invocation.validate().is_err(),
            "creation custody accepted changed bytes"
        );
        let mut fresh = Images::open(&cli)?;
        fresh.validate()?;
        previous = current;
        eprintln!(
            "RETAINED_IMAGE mode={mode} server={server_selected} byte={byte} stale_refused=true stamp_drift=true invocation_refused=true fresh_validation=true clocks_restored=true"
        );
    }
    drop(held);
    journal(true)?;
    Ok(())
}
#[test]
fn cli_journal_unavailable_from_open() -> Check {
    retained("unavailable", false)
}
#[test]
fn server_journal_unavailable_from_open() -> Check {
    retained("unavailable", true)
}
#[test]
fn cli_journal_removed_after_warming() -> Check {
    retained("removed", false)
}
#[test]
fn server_journal_removed_after_warming() -> Check {
    retained("removed", true)
}
#[test]
fn cli_writer_retained_across_qualification() -> Check {
    retained("held-writer", false)
}
#[test]
fn server_writer_retained_across_qualification() -> Check {
    retained("held-writer", true)
}
