//! Remote image verification refusals adapt the shared native SSH transport.
use super::unavailable;
pub(super) use se_ssh_transport::close;
pub(crate) use se_ssh_transport::command as ssh;
use se_types::SeError;

pub(crate) fn verification_error(bytes: &[u8]) -> SeError {
    if let Some(mode) = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("unsafe-mode:"))
        })
        .and_then(|mode| u16::from_str_radix(mode, 8).ok())
        .filter(|mode| *mode <= 0o7777)
    {
        return unavailable(&format!(
            "native runtime image mode {mode:04o} permits group or other writes; preserve the existing image and restore an account-owned image without foreign write permissions"
        ));
    }
    unavailable(
        "native runtime image verification failed; preserve the existing image and check its account ownership, permissions and distribution hash",
    )
}
