//! Linux's parent-death signal follows the spawning thread, not its process.
//! Keep that thread alive through the worker's exact cancellation and reap.
use std::{
    io,
    process::{Child, Command},
    sync::mpsc::{self, Sender},
    thread::{self, JoinHandle},
};

pub(super) struct Parent {
    release: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}
impl Parent {
    pub(super) fn spawn(mut command: Command) -> io::Result<(Child, Self)> {
        let (result, received) = mpsc::sync_channel(1);
        let (release, released) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("atlas-parent".into())
            .spawn(move || {
                if result.send(command.spawn()).is_ok() {
                    let _ = released.recv();
                }
            })?;
        let parent = Self {
            release: Some(release),
            thread: Some(thread),
        };
        let child = received.recv().map_err(|_| {
            io::Error::other("Atlas spawning thread exited before returning its child")
        })??;
        Ok((child, parent))
    }
}
impl Drop for Parent {
    fn drop(&mut self) {
        self.release.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
