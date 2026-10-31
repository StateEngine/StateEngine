use super::*;

fn flags(handle: HANDLE) -> std::result::Result<u32, Box<dyn std::error::Error>> {
    let mut value = 0;
    // SAFETY: borrowed live fixture handle and one initialized native output.
    if unsafe { GetHandleInformation(handle, &mut value) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(value)
}

#[test]
fn received_native_pipe_clears_original_and_duplicate_inheritance()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (read, _write) = pipe()?;
    let original = duplicate_same(read.as_raw_handle(), true)?;
    assert_ne!(flags(original.as_raw_handle())? & HANDLE_FLAG_INHERIT, 0);
    let received = inherited(original.as_raw_handle() as usize as u64)?;
    assert_eq!(
        flags(original.as_raw_handle())? & HANDLE_FLAG_INHERIT,
        0,
        "startup original can leak to a later child"
    );
    assert_eq!(
        flags(received.as_raw_handle())? & HANDLE_FLAG_INHERIT,
        0,
        "received custody duplicate can leak to a later child"
    );
    require_pipe(&File::from(received))?;
    Ok(())
}

#[test]
fn ordinary_uninherited_handle_cannot_select_the_private_receiver()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (read, _write) = pipe()?;
    assert_eq!(flags(read.as_raw_handle())? & HANDLE_FLAG_INHERIT, 0);
    assert!(inherited(read.as_raw_handle() as usize as u64).is_err());
    Ok(())
}
