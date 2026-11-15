//! Owned Windows fixture operations for cross-process native image controls.
#[cfg(not(windows))]
fn main() {}
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        fs::{File, OpenOptions},
        io::{Seek, SeekFrom, Write},
        os::windows::io::AsRawHandle,
        path::PathBuf,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandleEx, SetFileInformationByHandle,
    };
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().ok_or("fixture mode absent")?;
    let path = PathBuf::from(args.next().ok_or("fixture image absent")?);
    let root = PathBuf::from(std::env::var_os("DELTA_ROOT").ok_or("owned root absent")?);
    if !se_proc::canonicalize_path(&path)?.starts_with(se_proc::canonicalize_path(&root)?)
        || !matches!(
            path.file_name().and_then(|n| n.to_str()),
            Some("secode.exe" | "secode-server.exe")
        )
        || std::fs::metadata(&path)?.len() != 4096
    {
        return Err("image is not an owned bounded fixture".into());
    }
    if mode == "probe-write" {
        let attempt = OpenOptions::new().read(true).write(true).open(&path);
        let (opened, error) = match attempt {
            Ok(file) => {
                drop(file);
                (true, None)
            }
            Err(error) => (false, error.raw_os_error()),
        };
        println!(
            "{}",
            serde_json::json!({"write_opened": opened, "native_error": error})
        );
        return Ok(());
    }
    let file = if mode == "read" {
        File::open(&path)?
    } else if mode == "rewrite" {
        let modified: i64 = args
            .next()
            .ok_or("mtime absent")?
            .to_str()
            .ok_or("mtime encoding")?
            .parse()?;
        let changed: i64 = args
            .next()
            .ok_or("change time absent")?
            .to_str()
            .ok_or("ctime encoding")?
            .parse()?;
        let byte: u8 = args
            .next()
            .ok_or("byte absent")?
            .to_str()
            .ok_or("byte encoding")?
            .parse()?;
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        file.seek(SeekFrom::Start(4095))?;
        file.write_all(&[byte])?;
        file.sync_all()?;
        let mut restore = FILE_BASIC_INFO {
            CreationTime: 0,
            LastAccessTime: 0,
            LastWriteTime: modified,
            ChangeTime: changed,
            FileAttributes: 0,
        };
        // SAFETY: retained owned writable fixture and aligned initialized input.
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileBasicInfo,
                (&mut restore as *mut FILE_BASIC_INFO).cast(),
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        file
    } else {
        return Err("unknown fixture mode".into());
    };
    // SAFETY: all-integer native output is valid when zero initialized.
    let mut info: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: retained owned fixture and exact writable aligned output.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            (&mut info as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    println!(
        "{}",
        serde_json::json!({"modified":info.LastWriteTime,"changed":info.ChangeTime,"bytes":file.metadata()?.len()})
    );
    Ok(())
}
