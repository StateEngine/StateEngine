//! Raw Linux process-file grammar, shared without caching observations or policy.
//! Callers retain their own byte bounds, native error context, absence handling
//! and repeated observations across image pins or effects.

pub(crate) const STAT_BYTES: usize = 4096;
pub(crate) const BOOT_ID_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StatError {
    MissingDelimiter,
    InvalidState,
    TruncatedNumber,
    InvalidNumber,
    PidOverflow,
}

pub(crate) struct ProcStat<'a> {
    fields: [&'a [u8]; 20],
}
impl<'a> ProcStat<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, StatError> {
        // comm is arbitrary bytes, including whitespace, ')' and non-UTF8.
        let end = bytes
            .windows(2)
            .rposition(|part| part == b") ")
            .ok_or(StatError::MissingDelimiter)?;
        // Only the prefix through starttime (field 22) is consumed. Keep it
        // on the stack so IPC birth observations gain no per-read allocation.
        let mut fields = bytes[end + 2..]
            .split(u8::is_ascii_whitespace)
            .filter(|part| !part.is_empty());
        Ok(Self {
            fields: std::array::from_fn(|_| fields.next().unwrap_or_default()),
        })
    }

    pub(crate) fn state(&self) -> Result<u8, StatError> {
        match self.fields.first().copied() {
            Some([state]) => Ok(*state),
            _ => Err(StatError::InvalidState),
        }
    }
    fn number(&self, index: usize) -> Result<u64, StatError> {
        let bytes = self
            .fields
            .get(index)
            .filter(|field| !field.is_empty())
            .ok_or(StatError::TruncatedNumber)?;
        std::str::from_utf8(bytes)
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or(StatError::InvalidNumber)
    }
    fn pid(&self, index: usize) -> Result<u32, StatError> {
        u32::try_from(self.number(index)?).map_err(|_| StatError::PidOverflow)
    }
    pub(crate) fn parent(&self) -> Result<u32, StatError> {
        self.pid(1)
    }
    pub(crate) fn group(&self) -> Result<u32, StatError> {
        self.pid(2)
    }
    pub(crate) fn session(&self) -> Result<u32, StatError> {
        self.pid(3)
    }
    pub(crate) fn start_ticks(&self) -> Result<u64, StatError> {
        self.number(19)
    }
}

pub(crate) fn boot_id(bytes: &[u8]) -> Option<[u8; 16]> {
    let mut digits = bytes
        .iter()
        .copied()
        .filter(|b| *b != b'-' && !b.is_ascii_whitespace());
    let digit = |b| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut id = [0; 16];
    for byte in &mut id {
        *byte = digit(digits.next()?)? * 16 + digit(digits.next()?)?;
    }
    digits.next().is_none().then_some(id)
}

#[cfg(test)]
#[path = "linux_native/tests.rs"]
mod tests;
