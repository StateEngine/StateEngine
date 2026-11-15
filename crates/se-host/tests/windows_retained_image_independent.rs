#![cfg(all(windows, feature = "listener"))]
//! Retained public consumers must reread images without native qualification.
use se_host::harness::secode_image::Images;
use se_proc::{NativeStateFiles, native_ipc::ExecutableStamp};
use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
    process::Command,
};
#[repr(C)]
struct BasicInfo {
    created: i64,
    accessed: i64,
    modified: i64,
    changed: i64,
    attributes: u32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "GetFileInformationByHandleEx"]
    fn get_file_information(
        handle: *mut std::ffi::c_void,
        class: i32,
        output: *mut std::ffi::c_void,
        size: u32,
    ) -> i32;
    #[link_name = "SetFileInformationByHandle"]
    fn set_file_information(
        handle: *mut std::ffi::c_void,
        class: i32,
        input: *mut std::ffi::c_void,
        size: u32,
    ) -> i32;
}
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
fn clocks(file: &File) -> Check<BasicInfo> {
    let mut value: BasicInfo = unsafe { std::mem::zeroed() };
    if unsafe {
        get_file_information(
            file.as_raw_handle(),
            0,
            (&mut value as *mut BasicInfo).cast(),
            std::mem::size_of::<BasicInfo>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(value)
}
fn edit(file: &mut File, before: &BasicInfo, byte: u8) -> Check {
    file.seek(SeekFrom::Start(4095))?;
    file.write_all(&[byte])?;
    file.sync_all()?;
    let mut restore = BasicInfo {
        created: 0,
        accessed: 0,
        modified: before.modified,
        changed: before.changed,
        attributes: 0,
    };
    if unsafe {
        set_file_information(
            file.as_raw_handle(),
            0,
            (&mut restore as *mut BasicInfo).cast(),
            std::mem::size_of::<BasicInfo>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let after = clocks(file)?;
    assert_eq!(before.modified, after.modified);
    assert_eq!(before.changed, after.changed);
    assert_eq!(file.metadata()?.len(), 4096);
    Ok(())
}
fn retained(mode: &str, server_selected: bool) -> Check {
    journal(true)?;
    let name = format!("retained-{mode}-{server_selected}");
    let (cli, server) = package(&name)?;
    let path: &Path = if server_selected { &server } else { &cli };
    let before = clocks(&File::open(path)?)?;
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
    }
    for byte in [b'B', b'C', b'D'] {
        if let Some(file) = held.as_mut() {
            edit(file, &before, byte)?;
        } else {
            let mut file = OpenOptions::new().read(true).write(true).open(path)?;
            edit(&mut file, &before, byte)?;
        }
        assert_eq!(
            fs::read(path)?[4095],
            byte,
            "changed bytes were not read back"
        );
        assert!(
            images.validate().is_err(),
            "RETAINED_IMAGE_STALE_ACCEPT mode={mode} server={server_selected} byte={byte}"
        );
        assert!(
            ExecutableStamp::observe(path)?.is_none(),
            "unqualified image returned a reusable stamp"
        );
        eprintln!(
            "RETAINED_IMAGE mode={mode} server={server_selected} byte={byte} stale_refused=true stamp_unavailable=true clocks_restored=true"
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
