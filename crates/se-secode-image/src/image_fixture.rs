//! Synthetic image bytes for the secode_process image-review tests. Kept in a
//! test-only module outside the exact-budget secode_process directory: the
//! stamp reader takes a four-byte header and never executes the image,
//! so eight bytes replaces the 128 MiB test-binary copies that overflowed CI.
pub(crate) fn image_bytes() -> Vec<u8> {
    let magic: &[u8] = if cfg!(windows) {
        b"MZ"
    } else if cfg!(target_os = "macos") {
        b"\xfe\xed\xfa\xce"
    } else {
        b"\x7fELF"
    };
    // Eight bytes: the size-preserving edit tests flip the final byte, which
    // must stay outside the four-byte header the stamp reader takes.
    let mut bytes = vec![0u8; 8];
    bytes[..magic.len()].copy_from_slice(magic);
    bytes
}
