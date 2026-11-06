//! A bounded byte tail retains native crashes without treating omitted bytes as absent.
pub(super) struct StderrTail {
    bytes: Vec<u8>,
    omitted: u64,
}
impl StderrTail {
    pub fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(8192),
            omitted: 0,
        }
    }
    pub fn push(&mut self, bytes: &[u8]) {
        let discard = (self.bytes.len() + bytes.len()).saturating_sub(8192);
        self.omitted = self.omitted.saturating_add(discard as u64);
        if discard >= self.bytes.len() {
            let skip = discard - self.bytes.len();
            self.bytes.clear();
            self.bytes.extend_from_slice(&bytes[skip..]);
        } else {
            self.bytes.drain(..discard);
            self.bytes.extend_from_slice(bytes);
        }
    }
    pub fn diagnostic(&self) -> String {
        let invalid = std::str::from_utf8(&self.bytes).is_err();
        format!(
            "stderr ({} earlier bytes omitted{}): {}",
            self.omitted,
            if invalid {
                ", invalid UTF-8 replaced"
            } else {
                ""
            },
            String::from_utf8_lossy(&self.bytes)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retains_native_failure_tail_and_reports_discarded_or_invalid_bytes() {
        let mut tail = StderrTail::new();
        tail.push(&[b'x'; 9000]);
        tail.push(b"\nfailed source: alpha.rs\n");
        let diagnostic = tail.diagnostic();
        assert!(diagnostic.contains("833 earlier bytes omitted"));
        assert!(diagnostic.ends_with("failed source: alpha.rs\n"));
        tail.push(&[255]);
        assert!(tail.diagnostic().contains("invalid UTF-8 replaced"));
        assert_eq!(tail.bytes.len(), 8192);
    }
}
