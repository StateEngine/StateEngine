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
    fn observe_valid(&mut self, bytes: &[u8]) -> io::Result<()> {
        if let Some(c) = &mut self.lexical {
            c.observe(
                std::str::from_utf8(bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            );
        }
        Ok(())
    }
}
impl Read for Observed<'_, '_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if crate::clock::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Atlas text deadline",
            ));
        }
        let limit = bytes.len().min(32_768);
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
        let chunk = &bytes[..count];
        self.hash.update(chunk);
        self.binary |= chunk.contains(&0);
        let mut rest = chunk;
        if self.tail_len > 0 {
            let t = self.tail_len;
            let take = chunk.len().min(4 - t);
            let mut stitch = [0u8; 4];
            stitch[..t].copy_from_slice(&self.tail[..t]);
            stitch[t..t + take].copy_from_slice(&chunk[..take]);
            let len = t + take;
            self.tail_len = 0;
            match std::str::from_utf8(&stitch[..len]) {
                Ok(text) => {
                    if let Some(c) = &mut self.lexical {
                        c.observe(text);
                    }
                    rest = &chunk[take..];
                }
                Err(e) if e.valid_up_to() >= t => {
                    self.observe_valid(&stitch[..e.valid_up_to()])?;
                    rest = &chunk[e.valid_up_to() - t..];
                }
                Err(e) => {
                    if e.error_len().is_some() {
                        self.non_utf8 = true;
                    } else {
                        self.tail[..len].copy_from_slice(&stitch[..len]);
                        self.tail_len = len;
                    }
                    return Ok(count);
                }
            }
        }
        match std::str::from_utf8(rest) {
            Ok(text) => {
                if let Some(c) = &mut self.lexical {
                    c.observe(text);
                }
            }
            Err(e) => {
                if e.error_len().is_some() {
                    self.non_utf8 = true;
                } else {
                    let tail = &rest[e.valid_up_to()..];
                    self.tail_len = tail.len();
                    self.tail[..tail.len()].copy_from_slice(tail);
                }
                self.observe_valid(&rest[..e.valid_up_to()])?;
            }
        }
        Ok(count)
    }
}
