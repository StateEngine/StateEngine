//! Fixed Unix image transactions retain checks while reducing SSH round trips.
use super::staging;

pub(crate) const CACHE_PREPARED: &[u8] = b"image-cache-prepared\n";
pub(crate) const VERIFY_FAILED: &str = "image-verification-failed";
pub(crate) const CLEANUP_FAILED: &str = "image-cleanup-failed";

pub(crate) fn cached(directory: &str, path: &str, digest: &str, apple: bool) -> String {
    let prepare = staging::prepare(directory, false, apple);
    let verify = staging::verify(path, digest, false, apple);
    staging::sh(&format!(
        "({prepare}) || exit 1\nprintf \"image-cache-prepared\\n\"\n({verify})"
    ))
}

pub(crate) fn publish(upload: &str, path: &str, digest: &str, apple: bool) -> String {
    let staged = staging::verify(upload, digest, false, apple);
    let publish = staging::publish(upload, path, false);
    let promoted = staging::check(path, false, apple);
    let published = staging::verify(path, digest, false, apple);
    let remove = staging::remove(upload, false);
    // Each verification has its own shell scope: its refusal must not bypass
    // cleanup. A winning link makes the published path the verified upload's
    // own inode, so it re-proves identity only; a losing publisher still
    // verifies the incumbent's bytes before success.
    staging::sh(&format!(
        "se_ok=0\n({staged}) || se_ok=1\n\
         if test \"$se_ok\" -eq 0; then\nif ({publish}); then\n({promoted}) || se_ok=1\n\
         else\n({published}) || se_ok=1\nfi\nfi\n\
         if test \"$se_ok\" -ne 0; then printf \"{VERIFY_FAILED}\\n\"; fi\n\
         ({remove}) || {{ printf \"{CLEANUP_FAILED}\\n\"; exit 1; }}\nexit \"$se_ok\""
    ))
}

pub(crate) fn accept(verify: &str, invoke: &str) -> String {
    staging::sh(&format!(
        "se_detail=$({verify}) || {{ printf \"{VERIFY_FAILED}\\n%s\\n\" \"$se_detail\"; exit 1; }}\n{invoke}"
    ))
}

pub(crate) fn has_marker(bytes: &[u8], marker: &str) -> bool {
    bytes
        .split(|byte| *byte == b'\n')
        .any(|line| line == marker.as_bytes())
}
