#![cfg(windows)]
//! Public reader regression: restored native clocks cannot hide changed bytes.
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
use se_proc::{NativeStateFiles, native_ipc::*};
use se_types::Sha256;
use sha2::{Digest, Sha256 as Hasher};
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    process::Command,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
type Check<T = ()> = Result<T, Box<dyn Error>>;
fn bound() -> IpcIoBound {
    IpcIoBound {
        deadline: Instant::now() + Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn digest(path: &Path) -> Check<Sha256> {
    let mut f = File::open(path)?;
    let mut h = Hasher::new();
    let mut b = [0; 65536];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(Sha256::from_bytes(h.finalize().into()))
}
fn child(
    image: &Path,
    home: &Path,
    reader: &str,
    mode: &str,
    old: Sha256,
    actual: Sha256,
) -> Check {
    let out = Command::new(image)
        .args(["--ignored", "--exact", "native_reader_child", "--nocapture"])
        .env("PROOF_HOME", home)
        .env("PROOF_READER", reader)
        .env("PROOF_MODE", mode)
        .env("PROOF_OLD", serde_json::to_string(&old)?)
        .env("PROOF_ACTUAL", serde_json::to_string(&actual)?)
        .output()?;
    assert!(out.status.success(), "reader={reader},mode={mode}: {out:?}");
    Ok(())
}
#[test]
#[ignore = "fresh native helper invoked by public reader checks"]
fn native_reader_child() -> Check {
    let home = std::env::var_os("PROOF_HOME").ok_or("private home absent")?;
    let home = Path::new(&home);
    let reader = std::env::var("PROOF_READER")?;
    let mode = std::env::var("PROOF_MODE")?;
    let old: Sha256 = serde_json::from_str(&std::env::var("PROOF_OLD")?)?;
    let actual: Sha256 = serde_json::from_str(&std::env::var("PROOF_ACTUAL")?)?;
    let image = std::env::current_exe()?;
    match (mode.as_str(), reader.as_str()) {
        ("publish", "host") => publish_image_cache(home, actual, &bound())?,
        ("publish", "remote") => {
            assert_eq!(
                publish_remote_image_cache(home, actual, &bound())?,
                ImageCacheRead::Current
            );
        }
        ("publish", "adoption" | "hook") => prepare_adoption_image_cache(home, &image, &bound())?,
        ("check", "host") => {
            assert_eq!(
                restore_image_cache(home, old, &bound())?,
                ImageCacheRead::Current
            );
        }
        ("check", "remote") => {
            assert_eq!(
                restore_remote_image_cache(home, old, &bound())?,
                ImageCacheRead::Current
            );
        }
        ("check", "adoption") => {
            assert!(matches!(
                restore_adoption_provider_cache(home, &image, &bound())?,
                ImageCacheRead::Current | ImageCacheRead::Stale
            ));
        }
        ("check", "hook") => prepare_adoption_image_cache(home, &image, &bound())?,
        ("cold", _) => {}
        _ => return Err("unknown native reader/mode".into()),
    }
    let peer = observe_ipc_self_bounded(&bound())?;
    assert_eq!(peer.pid(), std::process::id());
    eprintln!(
        "NATIVE_READER reader={reader} mode={mode} old={old:?} observed={:?} actual={actual:?}",
        peer.image_sha256()
    );
    assert_eq!(peer.image_sha256(), actual, "RESTORED_CLOCK_STALE_DIGEST");
    Ok(())
}
fn rewrite_and_restore_clocks(image: &Path) -> Check<i64> {
    use std::{mem::size_of, os::windows::io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandleEx, SetFileInformationByHandle,
    };
    let metadata = fs::metadata(image)?;
    let mut held = OpenOptions::new().read(true).write(true).open(image)?;
    // SAFETY: all-integer native output and exact documented byte size.
    let mut before: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: retained test-file handle and exact aligned output.
    if unsafe {
        GetFileInformationByHandleEx(
            held.as_raw_handle(),
            FileBasicInfo,
            (&mut before as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    held.seek(SeekFrom::End(-1))?;
    held.write_all(b"B")?;
    held.sync_all()?;
    let mut restored = FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: 0,
        LastWriteTime: before.LastWriteTime,
        ChangeTime: before.ChangeTime,
        FileAttributes: 0,
    };
    // SAFETY: retained writable test-file handle and exact aligned input.
    if unsafe {
        SetFileInformationByHandle(
            held.as_raw_handle(),
            FileBasicInfo,
            (&mut restored as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    drop(held);
    let held = File::open(image)?;
    // SAFETY: all-integer native output and exact documented byte size.
    let mut after: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: retained test-file handle and exact aligned output.
    if unsafe {
        GetFileInformationByHandleEx(
            held.as_raw_handle(),
            FileBasicInfo,
            (&mut after as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    assert_eq!(before.LastWriteTime, after.LastWriteTime);
    assert_eq!(before.ChangeTime, after.ChangeTime);
    assert_eq!(fs::metadata(image)?.len(), metadata.len());
    eprintln!(
        "CLOCK_RESET last_write={} change={} size={}",
        after.LastWriteTime,
        after.ChangeTime,
        metadata.len()
    );
    Ok(before.ChangeTime)
}
fn exercise(reader: &str) -> Check {
    se_proc::initialize_file_creation_owner()?;
    let base = std::env::var_os("PROOF_JUDGE_ROOT").ok_or("explicit private root required")?;
    let root = Path::new(&base).join(reader);
    fs::create_dir(&root)?;
    let owner = cleanup_directory::PrivateDirectory::for_case(root.clone());
    let home = root.join("home");
    let files = NativeStateFiles::create(&home)?;
    let image = root.join("probe.exe");
    fs::copy(std::env::current_exe()?, &image)?;
    OpenOptions::new()
        .append(true)
        .open(&image)?
        .write_all(b"independent-native-proof-A")?;
    let original = digest(&image)?;
    let generationless = std::env::var("PROOF_LEGACY_MODE").as_deref() == Ok("generationless");
    let unavailable = std::env::var("PROOF_LEGACY_MODE").as_deref() == Ok("unavailable");
    let old = if generationless {
        Sha256::from_bytes([0x5a; 32])
    } else {
        original
    };
    child(&image, &home, reader, "publish", old, original)?;
    let clock = if generationless {
        0
    } else {
        rewrite_and_restore_clocks(&image)?
    };
    // Clock keys retain the old measured digest after a same-file rewrite.
    // Generation-less keys carry a sentinel to witness forbidden reuse.
    let mut hints = 0;
    for entry in fs::read_dir(&home)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().ends_with(".json") {
            continue;
        }
        let mut value: serde_json::Value = serde_json::from_slice(&fs::read(entry.path())?)?;
        if let Some(key) = value.get_mut("image") {
            if unavailable {
                assert!(key["changed"].is_null(), "disk hint unexpectedly qualified");
                eprintln!(
                    "UNAVAILABLE_DISK_HINT reader={reader} native_key_null=true fresh_process=true"
                );
            }
            if generationless {
                assert!(
                    key["changed"].is_array(),
                    "legacy revision fixture lacks a native key"
                );
                key["changed"][1] = serde_json::json!(1);
                key.as_object_mut()
                    .ok_or("image key is not an object")?
                    .remove("journal");
                value["digest"] = serde_json::to_value(old)?;
            } else {
                key["changed"] = serde_json::json!([clock, 0]);
            }
            fs::write(entry.path(), serde_json::to_vec(&value)?)?;
            hints += 1;
        }
    }
    assert!(hints > 0, "no protected legacy hint was exercised");
    eprintln!("LEGACY_KEYS reader={reader} hints={hints} generationless={generationless}");
    let actual = digest(&image)?;
    assert_ne!(old, actual);
    child(&image, &home, reader, "cold", old, actual)?;
    child(&image, &home, reader, "check", old, actual)?;
    println!(
        "PASS public {reader} hint reader preserves actual native executable digest after restored clocks"
    );
    drop(files);
    owner.finish(Ok(()))
}
#[test]
fn host_hint_reader() -> Check {
    exercise("host")
}
#[test]
fn remote_hint_reader() -> Check {
    exercise("remote")
}
#[test]
fn adoption_provider_reader() -> Check {
    exercise("adoption")
}
#[test]
fn adoption_hook_reader() -> Check {
    exercise("hook")
}
