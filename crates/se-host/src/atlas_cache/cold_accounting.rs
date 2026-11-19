//! Bounded disk measurements for cold and regular writers.
use super::*;

impl NativeAtlasCache {
    pub(super) fn measured_root(&self, bytes: u64) -> AtlasResult<u64> {
        #[cfg(windows)]
        let measurement_started = std::time::Instant::now();
        #[cfg(windows)]
        let estimate = if self.cold_accounting.get()
            && self
                .measured_at
                .get()
                .is_some_and(|time| time.elapsed() < std::time::Duration::from_secs(1))
            && self.writer_growth.get()
                < 512_000_000u64.saturating_sub(self.measured_bytes.get()) / 8
        {
            self.measured_bytes
                .get()
                .checked_add(self.writer_growth.get())
        } else {
            None
        };
        #[cfg(not(windows))]
        let estimate: Option<u64> = None;
        let estimate = estimate.filter(|root| {
            root.saturating_add(self.growth.get()).saturating_add(bytes) < 504_000_000
        });
        let cached = if estimate.is_some() {
            None
        } else {
            self.inventory
                .borrow()
                .as_ref()
                .map(inventory::Inventory::measure)
                .transpose()?
                .flatten()
        };
        // Recount near the disk cap before trusting the cached inventory.
        let root = match estimate.or(cached) {
            Some(root)
                if root.saturating_add(self.growth.get()).saturating_add(bytes) < 504_000_000 =>
            {
                root
            }
            _ => {
                let (root, snapshot) = inventory::root(&self.root)?;
                *self.inventory.borrow_mut() = Some(snapshot);
                root
            }
        };
        #[cfg(windows)]
        if self.cold_accounting.get() && estimate.is_none() {
            // A later checkpoint may copy the existing WAL into the database
            // without emitting a new WAL frame.
            self.measured_bytes
                .set(root.saturating_add(self.observed_wal.get()));
            self.writer_growth.set(0);
            self.measured_at.set(Some(measurement_started));
        }
        Ok(root)
    }
}
