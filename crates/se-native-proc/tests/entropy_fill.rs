//! New public fill API: arbitrary slice lengths, exact error and complete zeroization.
#[test]
fn public_helpers_keep_byte_order_and_accept_arbitrary_fill_lengths()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(se_types::hex_lower(&[]), "");
    assert_eq!(
        se_types::hex_lower(&[0, 1, 15, 16, 128, 255]),
        "00010f1080ff"
    );
    for length in [0, 1, 16, 32, 257, 1025] {
        let mut bytes = vec![0; length];
        se_proc::fill_entropy(&mut bytes)?;
        assert_eq!(bytes.len(), length);
    }
    Ok(())
}
#[cfg(target_os = "linux")]
#[path = "support/entropy_fill_fixture.rs"]
mod fixture;
#[cfg(target_os = "linux")]
#[test]
fn partial_native_error_zeroizes_the_entire_caller_buffer() -> fixture::Check {
    fixture::run_child("fill_failure_child")
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "Executed only by the parent with its process-bound native fault interposer"]
fn fill_failure_child() -> fixture::Check {
    let mut bytes = [0x7e; 37];
    fixture::arm(bytes.len())?;
    let error = se_proc::fill_entropy(&mut bytes)
        .err()
        .ok_or("partial native error returned success")?;
    assert_eq!(error.operation, "getrandom");
    assert_eq!(error.native_code, Some(5));
    assert!(
        bytes.iter().all(|&byte| byte == 0),
        "partial native error left bytes in caller buffer"
    );
    fixture::assert_partial_then_eio()
}
