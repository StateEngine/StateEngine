//! Fixed Unix image transactions retain checks while reducing SSH round trips.
use super::staging;

pub(in crate::remote) const CACHE_PREPARED: &[u8] = b"image-cache-prepared\n";
pub(in crate::remote) const VERIFY_FAILED: &str = "image-verification-failed";
pub(in crate::remote) const CLEANUP_FAILED: &str = "image-cleanup-failed";

pub(in crate::remote) fn cached(directory: &str, path: &str, digest: &str, apple: bool) -> String {
    let prepare = staging::prepare(directory, false, apple);
    let verify = staging::verify(path, digest, false, apple);
    format!("({prepare}) || exit 1\nprintf 'image-cache-prepared\\n'\n({verify})")
}

pub(in crate::remote) fn publish(upload: &str, path: &str, digest: &str, apple: bool) -> String {
    let staged = staging::verify(upload, digest, false, apple);
    let publish = staging::publish(upload, path, false);
    let published = staging::verify(path, digest, false, apple);
    let remove = staging::remove(upload, false);
    // Each verification has its own shell scope: its refusal must not bypass
    // cleanup. A losing publisher still verifies the incumbent before success.
    format!(
        "se_ok=0\n({staged}) || se_ok=1\n\
         if test \"$se_ok\" -eq 0; then\n({publish}) || :\n({published}) || se_ok=1\nfi\n\
         if test \"$se_ok\" -ne 0; then printf '{VERIFY_FAILED}\\n'; fi\n\
         ({remove}) || {{ printf '{CLEANUP_FAILED}\\n'; exit 1; }}\nexit \"$se_ok\""
    )
}

pub(in crate::remote) fn accept(verify: &str, invoke: &str) -> String {
    format!(
        "se_detail=$({verify}) || {{ printf '{VERIFY_FAILED}\\n%s\\n' \"$se_detail\"; exit 1; }}\n{invoke}"
    )
}

pub(in crate::remote) fn has_marker(bytes: &[u8], marker: &str) -> bool {
    bytes
        .split(|byte| *byte == b'\n')
        .any(|line| line == marker.as_bytes())
}
