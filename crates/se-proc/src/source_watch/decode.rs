//! Decode Windows directory notifications and ancestor events.
use super::*;

impl Worker {
    pub(super) fn decode_completion(
        &self,
        id: u32,
        item: &Subscription,
        count: u32,
    ) -> io::Result<()> {
        // SAFETY: the completion has returned, count was bounded by the exact
        // allocation size, and reading its initialized bytes needs no alignment.
        let bytes = unsafe {
            std::slice::from_raw_parts(item.buffer.as_ptr().cast::<u8>(), count as usize)
        };
        self.decode(id, item.sentinel.as_ref(), item.recursive, bytes)
    }
    fn decode(
        &self,
        id: u32,
        sentinel: Option<&(u32, String)>,
        recursive: bool,
        bytes: &[u8],
    ) -> io::Result<()> {
        let mut offset = 0usize;
        loop {
            let header = bytes
                .get(offset..offset + 12)
                .ok_or_else(|| invalid("short Windows watch event"))?;
            let number = |at| u32::from_le_bytes(header[at..at + 4].try_into().unwrap_or_default());
            let next = number(0) as usize;
            let action = number(4);
            let length = number(8) as usize;
            if length == 0 || !length.is_multiple_of(2) || length > BUFFER - 12 {
                return Err(invalid("invalid Windows watch name"));
            }
            let end = offset
                .checked_add(12 + length)
                .ok_or_else(|| invalid("Windows watch event overflow"))?;
            let name = bytes
                .get(offset + 12..end)
                .ok_or_else(|| invalid("short Windows watch name"))?;
            let units: Vec<u16> = name
                .chunks_exact(2)
                .map(|v| u16::from_le_bytes([v[0], v[1]]))
                .collect();
            let mut name = String::from_utf16(&units)
                .map_err(|_| invalid("unsupported Windows watch name"))?;
            if recursive {
                name = name.replace('\\', "/");
            }
            if name.contains(['\\', '\0', ':'])
                || name.starts_with('/')
                || name
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
            {
                return Err(invalid("invalid Windows watch component"));
            }
            if let Some((owner, target)) = sentinel {
                // Metadata updates to a retained ancestor do not replace its
                // directory. Name removal or rename can invalidate its pin.
                let invalidates = match action {
                    FILE_ACTION_REMOVED
                    | FILE_ACTION_RENAMED_OLD_NAME
                    | FILE_ACTION_RENAMED_NEW_NAME => true,
                    FILE_ACTION_ADDED | FILE_ACTION_MODIFIED => false,
                    _ => return Err(invalid("unknown Windows ancestor watch action")),
                };
                if invalidates
                    && (!target.is_ascii() || !name.is_ascii() || name.eq_ignore_ascii_case(target))
                {
                    self.invalidate(*owner);
                }
                if next == 0 {
                    return Ok(());
                }
                if next < 12 + length || !next.is_multiple_of(4) {
                    return Err(invalid("invalid Windows watch next offset"));
                }
                offset = offset
                    .checked_add(next)
                    .ok_or_else(|| invalid("Windows watch offset overflow"))?;
                continue;
            }
            let action = match action {
                FILE_ACTION_REMOVED => 1,
                FILE_ACTION_RENAMED_OLD_NAME => 2,
                FILE_ACTION_RENAMED_NEW_NAME => 3,
                FILE_ACTION_ADDED | FILE_ACTION_MODIFIED => 0,
                _ => return Err(invalid("unknown Windows watch action")),
            };
            let mut event = Vec::with_capacity(12 + name.len());
            event.extend_from_slice(&id.to_le_bytes());
            event.push(action);
            // FILE_NOTIFY_INFORMATION has no directory bit. Reconcile conservatively.
            event.push(1);
            event.extend_from_slice(&[0, 0]);
            event.extend_from_slice(&(name.len() as u32).to_le_bytes());
            event.extend_from_slice(name.as_bytes());
            self.queue
                .lock()
                .map_err(|_| io::Error::other("watch queue poisoned"))?
                .push(event);
            if next == 0 {
                return Ok(());
            }
            if next < 12 + length || !next.is_multiple_of(4) {
                return Err(invalid("invalid Windows watch next offset"));
            }
            offset = offset
                .checked_add(next)
                .ok_or_else(|| invalid("Windows watch offset overflow"))?;
        }
    }
}
