//! Bind native events to the retained source identity.
use super::*;
use std::{io, sync::Arc, time::Duration};

#[path = "events.rs"]
mod events;
pub use events::NativeWatchEvents;

pub struct NativeSourceWatch(se_fsevents::Watcher);
impl NativeSourceWatch {
    pub fn new() -> io::Result<Self> {
        Ok(Self(se_fsevents::Watcher::new()?))
    }
    pub fn set_signal(&self, signal: Arc<dyn Fn() + Send + Sync>) -> io::Result<()> {
        self.0.set_signal(signal)
    }
    pub fn subscribe_tree(
        &self,
        root: &NativeSourceRoot,
    ) -> io::Result<Option<NativeWatchRegistration>> {
        let Some(pin) = root.open_directory("")? else {
            return Ok(None);
        };
        let descriptor = self.0.subscribe_tree(&root.path)?;
        if !pin.validate_name()? {
            return Err(changed("source changed while arming watch"));
        }
        Ok(Some(NativeWatchRegistration {
            descriptor,
            physical_directory: pin.identity.root_key(),
        }))
    }
    pub fn synchronize(&self, timeout: Duration) -> io::Result<()> {
        self.0.synchronize(timeout)
    }
    pub fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.read(buffer)
    }
}
