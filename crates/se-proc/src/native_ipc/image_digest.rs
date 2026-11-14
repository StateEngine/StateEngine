//! Digest state only; file pins, byte bounds, deadlines and cache admission live
//! in the executable proof. Minimal process-library consumers retain SHA-2.

#[cfg(all(target_os = "linux", feature = "native-sha256"))]
pub(super) struct Hasher(aws_lc_rs::digest::Context);

#[cfg(all(target_os = "linux", feature = "native-sha256"))]
impl Hasher {
    pub(super) fn new() -> Self {
        Self(aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256))
    }

    pub(super) fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub(super) fn finish(self) -> [u8; 32] {
        let digest = self.0.finish();
        let mut bytes = [0; 32];
        bytes.copy_from_slice(digest.as_ref());
        bytes
    }
}

#[cfg(not(all(target_os = "linux", feature = "native-sha256")))]
pub(super) struct Hasher(sha2::Sha256);

#[cfg(not(all(target_os = "linux", feature = "native-sha256")))]
impl Hasher {
    pub(super) fn new() -> Self {
        use sha2::Digest as _;
        Self(sha2::Sha256::new())
    }

    pub(super) fn update(&mut self, bytes: &[u8]) {
        use sha2::Digest as _;
        self.0.update(bytes);
    }

    pub(super) fn finish(self) -> [u8; 32] {
        use sha2::Digest as _;
        self.0.finalize().into()
    }
}
