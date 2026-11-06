use crate::source::SourceFile;
use std::{
    io::{self, Read},
    time::Instant,
};
pub(super) struct Observed<'a, 'q> {
    inner: &'a mut dyn SourceFile,
    deadline: Instant,
    pub hash: blake3::Hasher,
    pub eof: bool,
    pub binary: bool,
    pub non_utf8: bool,
    tail: [u8; 4],
    pub tail_len: usize,
    count: u64,
    pub lexical: Option<super::lexical::Counter<'q>>,
}
impl<'a, 'q> Observed<'a, 'q> {
    pub fn new(
        inner: &'a mut dyn SourceFile,
        deadline: Instant,
        terms: Option<&'q super::lexical::Terms>,
    ) -> Self {
        Self {
            inner,
            deadline,
            hash: blake3::Hasher::new(),
            eof: false,
            binary: false,
            non_utf8: false,
            tail: [0; 4],
            tail_len: 0,
            count: 0,
            lexical: terms.map(super::lexical::Counter::new),
        }
    }
}
impl Read for Observed<'_, '_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Atlas text deadline",
            ));
        }
        let limit = bytes.len().min(8192);
        let count = self.inner.read(&mut bytes[..limit])?;
        if count == 0 {
            self.eof = true;
            return Ok(0);
        }
        self.count += count as u64;
        if self.count > 64 * 1024 * 1024 {
            return Err(io::Error::other(
                "source grew beyond 64 MiB during text search",
            ));
        }
        self.hash.update(&bytes[..count]);
        self.binary |= bytes[..count].contains(&0);
        let mut utf8 = [0; 8196];
        utf8[..self.tail_len].copy_from_slice(&self.tail[..self.tail_len]);
        utf8[self.tail_len..self.tail_len + count].copy_from_slice(&bytes[..count]);
        let length = self.tail_len + count;
        self.tail_len = 0;
        let valid = match std::str::from_utf8(&utf8[..length]) {
            Ok(text) => text,
            Err(error) => {
                if error.error_len().is_some() {
                    self.non_utf8 = true;
                } else {
                    let tail = &utf8[error.valid_up_to()..length];
                    self.tail_len = tail.len();
                    self.tail[..tail.len()].copy_from_slice(tail);
                }
                std::str::from_utf8(&utf8[..error.valid_up_to()])
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            }
        };
        if let Some(counter) = &mut self.lexical {
            counter.observe(valid);
        }
        Ok(count)
    }
}
