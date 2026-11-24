//! Platform-independent watch facts.
use std::ffi::OsStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeWatchRegistration {
    pub descriptor: u32,
    pub physical_directory: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeWatchAction {
    Changed,
    Removed,
    MovedFrom,
    MovedTo,
    Invalidated,
    Overflow,
}
#[derive(Debug)]
pub struct NativeWatchEvent<'a> {
    pub descriptor: Option<u32>,
    pub action: NativeWatchAction,
    pub name: &'a OsStr,
    pub directory: bool,
    pub watch_removed: bool,
    pub cookie: u32,
}
