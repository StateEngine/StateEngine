//! One deterministic allowance shared by grammar parsing and extraction.
pub(super) struct Work {
    remaining: u32,
}

impl Work {
    pub fn new(steps: u32) -> Self {
        Self { remaining: steps }
    }

    pub fn charge(&mut self, steps: usize) -> bool {
        let Ok(steps) = u32::try_from(steps) else {
            self.remaining = 0;
            return false;
        };
        let Some(remaining) = self.remaining.checked_sub(steps) else {
            self.remaining = 0;
            return false;
        };
        self.remaining = remaining;
        true
    }

    pub fn bytes(&mut self, bytes: usize) -> bool {
        self.charge(bytes.div_ceil(64))
    }
}
