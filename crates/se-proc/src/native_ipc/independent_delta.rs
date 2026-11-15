//! Independent Windows native proof boundary controls.
use super::{image, *};
use sha2::{Digest, Sha256 as Hasher};
use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    time::Duration,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandleEx, SetFileInformationByHandle,
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn bound() -> IpcIoBound {
    IpcIoBound {
        deadline: Instant::now() + Duration::from_secs(20),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn fixture(name: &str) -> Check<PathBuf> {
    let root = PathBuf::from(std::env::var_os("DELTA_ROOT").ok_or("private root absent")?);
    let path = root.join(name);
    fs::create_dir(&path)?;
    Ok(path.join("image.bin"))
}
fn digest(path: &Path) -> Check<Sha256> {
    Ok(Sha256::from_bytes(Hasher::digest(fs::read(path)?).into()))
}
fn basic(file: &File) -> Check<FILE_BASIC_INFO> {
    let mut out: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            (&mut out as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(out)
}
fn rewrite(file: &mut File, bytes: &[u8], clock: &FILE_BASIC_INFO) -> Check {
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let mut clocks = FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: 0,
        LastWriteTime: clock.LastWriteTime,
        ChangeTime: clock.ChangeTime,
        FileAttributes: 0,
    };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileBasicInfo,
            (&mut clocks as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
#[test]
fn active_journal_cache_hit() -> Check {
    let path = fixture("active-hit")?;
    fs::write(&path, vec![b'A'; 4096])?;
    let file = File::open(&path)?;
    let stamp = image::key(&file, &file.metadata()?)?;
    let key = serde_json::to_value(&stamp)?;
    assert!(
        key["changed"][0].as_i64().is_some_and(|n| n > 0) && key["changed"][1] == 1,
        "positive journal key absent: {key}"
    );
    let synthetic = Sha256::from_bytes([0x5a; 32]);
    image::remember(stamp, synthetic)?;
    assert_eq!(
        image::hash_image(File::open(&path)?, &bound())?,
        synthetic,
        "qualified key did not take cache path"
    );
    eprintln!(
        "DELTA active-hit qualified_revision={} cache_hit_witnessed=true",
        key["changed"][0]
    );
    Ok(())
}
#[test]
fn held_writer_repeated_rewrites_and_hint_publication() -> Check {
    let path = fixture("held-writer")?;
    fs::write(&path, vec![b'A'; 4096])?;
    let home = path.parent().unwrap().join("home");
    let _files = crate::NativeStateFiles::create(&home)?;
    let mut writer = OpenOptions::new().read(true).write(true).open(&path)?;
    let clock = basic(&writer)?;
    for byte in [b'B', b'C', b'D'] {
        rewrite(&mut writer, &vec![byte; 4096], &clock)?;
        prepare_adoption_image_cache(&home, &path, &bound())?;
        let actual = digest(&path)?;
        assert_eq!(
            image::hash_image(File::open(&path)?, &bound())?,
            actual,
            "held writer reused an earlier digest"
        );
        let provider = fs::read_dir(&home)?
            .filter_map(Result::ok)
            .find(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("ipc-adoption-provider-")
            })
            .ok_or("provider hint absent")?;
        let entry: serde_json::Value = serde_json::from_slice(&fs::read(provider.path())?)?;
        assert!(
            entry["image"]["changed"].is_null(),
            "held-writer hint published reusable key: {entry}"
        );
        eprintln!("DELTA held-writer byte={byte} digest_verified=true hint_unqualified=true");
    }
    drop(writer);
    let _ = restore_adoption_provider_cache(&home, &path, &bound())?;
    assert_eq!(
        image::hash_image(File::open(&path)?, &bound())?,
        digest(&path)?
    );
    Ok(())
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileMappingW(
        file: *mut std::ffi::c_void,
        attributes: *const std::ffi::c_void,
        protect: u32,
        high: u32,
        low: u32,
        name: *const u16,
    ) -> *mut std::ffi::c_void;
    fn MapViewOfFile(
        mapping: *mut std::ffi::c_void,
        access: u32,
        high: u32,
        low: u32,
        size: usize,
    ) -> *mut std::ffi::c_void;
    fn UnmapViewOfFile(view: *const std::ffi::c_void) -> i32;
    fn FlushViewOfFile(view: *const std::ffi::c_void, size: usize) -> i32;
}
struct View(*mut std::ffi::c_void);
impl Drop for View {
    fn drop(&mut self) {
        assert_ne!(unsafe { UnmapViewOfFile(self.0) }, 0, "unmap failed");
    }
}
#[test]
fn writable_mapping_outlives_writer_handle() -> Check {
    let path = fixture("mapped-writer")?;
    fs::write(&path, vec![b'A'; 4096])?;
    let writer = OpenOptions::new().read(true).write(true).open(&path)?;
    let clock = basic(&writer)?;
    let attributes = OpenOptions::new().access_mode(0x180).open(&path)?;
    let raw = unsafe {
        CreateFileMappingW(
            writer.as_raw_handle(),
            std::ptr::null(),
            4,
            0,
            4096,
            std::ptr::null(),
        )
    };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let mapping = unsafe { OwnedHandle::from_raw_handle(raw) };
    let raw = unsafe { MapViewOfFile(mapping.as_raw_handle(), 2, 0, 0, 4096) };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let view = View(raw);
    drop(writer);
    for byte in [b'B', b'C', b'D'] {
        unsafe { std::ptr::write_bytes(view.0.cast::<u8>(), byte, 4096) };
        assert_ne!(unsafe { FlushViewOfFile(view.0, 4096) }, 0);
        let mut restored = FILE_BASIC_INFO {
            CreationTime: 0,
            LastAccessTime: 0,
            LastWriteTime: clock.LastWriteTime,
            ChangeTime: clock.ChangeTime,
            FileAttributes: 0,
        };
        assert_ne!(
            unsafe {
                SetFileInformationByHandle(
                    attributes.as_raw_handle(),
                    FileBasicInfo,
                    (&mut restored as *mut FILE_BASIC_INFO).cast(),
                    std::mem::size_of::<FILE_BASIC_INFO>() as u32,
                )
            },
            0
        );
        let actual = digest(&path)?;
        assert_eq!(
            image::hash_image(File::open(&path)?, &bound())?,
            actual,
            "retained mapping reused stale bytes"
        );
        eprintln!("DELTA mapped-writer byte={byte} digest_verified=true writer_handle_closed=true");
    }
    drop(view);
    drop(mapping);
    Ok(())
}
#[test]
fn zz_journal_removed_after_warming() -> Check {
    let path = fixture("journal-loss")?;
    fs::write(&path, vec![b'A'; 4096])?;
    assert_eq!(
        image::hash_image(File::open(&path)?, &bound())?,
        digest(&path)?
    );
    let clock = basic(&File::open(&path)?)?;
    let volume = std::env::var("DELTA_VOLUME")?;
    assert!(
        volume.len() == 2 && volume.as_bytes()[0].is_ascii_alphabetic() && volume.ends_with(':')
    );
    let status = std::process::Command::new("fsutil.exe")
        .args(["usn", "deletejournal", "/d", &volume])
        .status()?;
    assert!(status.success());
    let mut writer = OpenOptions::new().read(true).write(true).open(&path)?;
    rewrite(&mut writer, &vec![b'B'; 4096], &clock)?;
    drop(writer);
    assert_eq!(
        image::hash_image(File::open(&path)?, &bound())?,
        digest(&path)?,
        "journal loss reused warm digest"
    );
    let held = File::open(&path)?;
    let key = serde_json::to_value(image::key(&held, &held.metadata()?)?)?;
    assert!(
        key["changed"].is_null(),
        "unavailable journal qualified a key: {key}"
    );
    eprintln!(
        "DELTA journal-removed warm_digest_invalidated=true unavailable_full_hash_verified=true"
    );
    Ok(())
}
