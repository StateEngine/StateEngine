//! Actual native filtered tokens whose restricting-SID lists remain empty.
use super::*;

fn primary() -> ProcResult<OwnedHandle> {
    let mut raw = ptr::null_mut();
    // SAFETY: opens only the current process token for querying and creating an owned restricted copy.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) }
        == 0
    {
        return Err(last("open native token regression fixture"));
    }
    handle(raw, "own native token regression fixture")
}
fn filtered(
    token: HANDLE,
    group: Option<&SID_AND_ATTRIBUTES>,
    privilege: Option<&LUID_AND_ATTRIBUTES>,
) -> ProcResult<OwnedHandle> {
    let mut raw = ptr::null_mut();
    // SAFETY: creates a separate owned token; it never adjusts this or another process's token.
    if unsafe {
        CreateRestrictedToken(
            token,
            0,
            u32::from(group.is_some()),
            group.map_or(ptr::null(), |g| g),
            u32::from(privilege.is_some()),
            privilege.map_or(ptr::null(), |p| p),
            0,
            ptr::null(),
            &mut raw,
        )
    } == 0
    {
        return Err(last("create native token regression copy"));
    }
    handle(raw, "own filtered native token regression copy")
}
#[test]
fn deleted_privileges_cannot_match_an_ordinary_broker() -> ProcResult<()> {
    let original = primary()?;
    let baseline = token_context(original.as_raw_handle())?;
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let name: Vec<u16> = "SeChangeNotifyPrivilege"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: terminated native privilege spelling and writable LUID output.
    if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) } == 0 {
        return Err(last("resolve native regression privilege"));
    }
    assert!(
        baseline
            .privileges
            .iter()
            .any(|p| p.0 == luid.LowPart && p.1 == luid.HighPart)
    );
    let copy = filtered(
        original.as_raw_handle(),
        None,
        Some(&LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: 0,
        }),
    )?;
    let limited = token_context(copy.as_raw_handle())?;
    // token_context already verifies IsTokenRestricted == FALSE; the deleted right
    // must nevertheless remain part of the broker equality and child witness.
    assert!(
        limited
            .privileges
            .iter()
            .all(|p| p.0 != luid.LowPart || p.1 != luid.HighPart)
    );
    assert!(limited != baseline);
    Ok(())
}
#[test]
fn disabled_group_attributes_cannot_match_an_ordinary_broker() -> ProcResult<()> {
    let original = primary()?;
    let baseline = token_context(original.as_raw_handle())?;
    let mut storage = [0u32; 17];
    let mut bytes = std::mem::size_of_val(&storage) as u32;
    // SAFETY: aligned 68-byte well-known SID output and writable length.
    if unsafe {
        CreateWellKnownSid(
            WinWorldSid,
            ptr::null_mut(),
            storage.as_mut_ptr().cast(),
            &mut bytes,
        )
    } == 0
    {
        return Err(last("create native group regression SID"));
    }
    let group = SID_AND_ATTRIBUTES {
        Sid: storage.as_mut_ptr().cast(),
        Attributes: 0,
    };
    let copy = filtered(original.as_raw_handle(), Some(&group), None)?;
    let limited = token_context(copy.as_raw_handle())?;
    let before = baseline
        .groups
        .iter()
        .find(|p| p.0 == "S-1-1-0")
        .ok_or_else(|| input("native regression", "Everyone group missing"))?;
    let after = limited
        .groups
        .iter()
        .find(|p| p.0 == "S-1-1-0")
        .ok_or_else(|| input("native regression", "filtered Everyone group missing"))?;
    assert_ne!(before.1, after.1);
    assert_ne!(
        after.1 & windows_sys::Win32::System::SystemServices::SE_GROUP_USE_FOR_DENY_ONLY as u32,
        0
    );
    assert!(limited != baseline);
    Ok(())
}
