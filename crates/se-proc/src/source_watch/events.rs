//! Decode bounded completion records for the platform-independent consumer.
use super::{NativeWatchAction, NativeWatchEvent, invalid};
use std::{ffi::OsStr, io};

pub struct NativeWatchEvents<'a> {
    bytes: &'a [u8],
}
impl<'a> NativeWatchEvents<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
    fn decode(&mut self) -> io::Result<NativeWatchEvent<'a>> {
        let header = self
            .bytes
            .get(..12)
            .ok_or_else(|| invalid("short Windows watch envelope"))?;
        let id = u32::from_le_bytes(header[..4].try_into().map_err(|_| invalid("watch id"))?);
        let action = match header[4] {
            0 => NativeWatchAction::Changed,
            1 => NativeWatchAction::Removed,
            2 => NativeWatchAction::MovedFrom,
            3 => NativeWatchAction::MovedTo,
            4 => NativeWatchAction::Invalidated,
            5 => NativeWatchAction::Overflow,
            _ => return Err(invalid("watch action")),
        };
        let len = u32::from_le_bytes(
            header[8..12]
                .try_into()
                .map_err(|_| invalid("watch name size"))?,
        ) as usize;
        let end = 12usize
            .checked_add(len)
            .ok_or_else(|| invalid("watch name overflow"))?;
        let bytes = self
            .bytes
            .get(12..end)
            .ok_or_else(|| invalid("short watch name"))?;
        let name = std::str::from_utf8(bytes).map_err(|_| invalid("watch name encoding"))?;
        self.bytes = &self.bytes[end..];
        Ok(NativeWatchEvent {
            descriptor: (action != NativeWatchAction::Overflow).then_some(id),
            action,
            name: OsStr::new(name),
            directory: header[5] != 0,
            watch_removed: false,
            cookie: 0,
        })
    }
}
impl<'a> Iterator for NativeWatchEvents<'a> {
    type Item = io::Result<NativeWatchEvent<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        let event = self.decode();
        if event.is_err() {
            self.bytes = &[];
        }
        Some(event)
    }
}
