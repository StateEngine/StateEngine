use crate::windows_policy_fixture::*;
use std::{
    fs::{self, File},
    os::windows::io::AsRawHandle,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, HANDLE},
    Security::{
        Authorization::{SE_FILE_OBJECT, SE_OBJECT_TYPE, SetSecurityInfo},
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    },
    Storage::FileSystem::*,
};

pub(crate) fn set_dacl(raw: HANDLE, kind: SE_OBJECT_TYPE, text: &str) -> Check {
    let descriptor = Descriptor::new(text)?;
    // SAFETY: retained handle and descriptor ACL remain valid throughout the call.
    let code = unsafe {
        SetSecurityInfo(
            raw,
            kind,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            descriptor.acl(false)?,
            ptr::null_mut(),
        )
    };
    if code != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(code as i32).into());
    }
    Ok(())
}

#[test]
fn image_identity_refuses_multiple_hard_links() -> Check {
    let home = Home::new()?;
    let path = home.0.join("image.exe");
    let alias = home.0.join("alias.exe");
    fs::copy(std::env::current_exe()?, &path)?;
    drop(
        crate::windows_native::open_image(&path, false)
            .map_err(|e| format!("{}: {}", e.operation, e.source))?,
    );
    fs::hard_link(&path, &alias)?;
    let original = File::open(&path)?;
    let linked = File::open(&alias)?;
    assert_eq!(
        file_key(original.as_raw_handle())?,
        file_key(linked.as_raw_handle())?,
        "hard link did not preserve file identity"
    );
    for delete in [false, true] {
        let error = crate::windows_native::open_image(&path, delete)
            .err()
            .ok_or("multi-link image accepted")?;
        assert_eq!(error.operation, "read native file identity");
        assert!(
            error
                .source
                .to_string()
                .contains("single-link regular disk file required"),
            "{}: {}",
            error.operation,
            error.source
        );
    }
    drop(linked);
    drop(original);
    fs::remove_file(alias)?;
    for delete in [false, true] {
        drop(
            crate::windows_native::open_image(&path, delete)
                .map_err(|e| format!("{}: {}", e.operation, e.source))?,
        );
    }
    println!(
        "image links: both read/delete consumers refused 2 links and accepted restored single link"
    );
    Ok(())
}
#[test]
fn store_refuses_deny_ace_even_when_the_os_allows_reading() -> Check {
    let home = Home::new()?;
    let files = crate::NativeStateFiles::open(&home.0)?;
    let path = home.0.join("record");
    fs::write(&path, b"unchanged record")?;
    let file = File::options().read(true).write(true).open(&path)?;
    // Open with WRITE_DAC explicitly, independently of ordinary read/write rights.
    // SAFETY: terminated owned regular-file path and explicit bounded access.
    let acl_handle = own(unsafe {
        CreateFileW(
            wide(path.as_os_str()).as_ptr(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    })?;
    let user = user()?;
    let good = format!("D:P(A;;FA;;;{user})(A;;FA;;;SY)");
    set_dacl(acl_handle.as_raw_handle(), SE_FILE_OBJECT, &good)?;
    assert!(files.readback(&path)?.is_some());
    // Builtin Guests is not the current user; its deny ACE must be refused by
    // store policy even though it does not deny our actual kernel read.
    set_dacl(
        acl_handle.as_raw_handle(),
        SE_FILE_OBJECT,
        &format!("D:P(D;;FW;;;BG)(A;;FA;;;{user})(A;;FA;;;SY)"),
    )?;
    assert_eq!(fs::read(&path)?, b"unchanged record");
    let error = files
        .readback(&path)
        .err()
        .ok_or("store accepted deny ACE")?;
    assert_eq!(error.code, crate::StateFileErrorCode::LocationUnsafe);
    assert_eq!(error.operation, "unexpected protection ACE");
    let mut installation = crate::OwnedFile::open(&path)?.ok_or("installation control absent")?;
    installation.claim_installation_record()?;
    assert_eq!(installation.read(128)?, b"unchanged record");
    drop(installation);
    set_dacl(acl_handle.as_raw_handle(), SE_FILE_OBJECT, &good)?;
    assert!(files.readback(&path)?.is_some());
    drop(file);
    Ok(())
}

#[path = "windows_install_inheritance.rs"]
mod windows_install_inheritance;
