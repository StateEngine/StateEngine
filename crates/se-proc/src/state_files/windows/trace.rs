//! Development-only fixed counters; no per-span allocation or logging.
use std::{cell::RefCell, collections::BTreeMap, os::windows::io::AsRawHandle, time::Instant};
const LABELS: [&str; 7] = [
    "metadata-pin",
    "native-open",
    "protected-metadata",
    "protected-readback",
    "security-token",
    "security-verify",
    "other",
];
#[derive(Clone, Copy)]
struct Count {
    calls: u64,
    inclusive_us: u64,
}
const ZERO: Count = Count {
    calls: 0,
    inclusive_us: 0,
};
#[derive(Clone, Copy)]
struct Held {
    handle: usize,
    count: Count,
}
const EMPTY: Held = Held {
    handle: 0,
    count: ZERO,
};
struct Counters {
    stages: [Count; 7],
    handles: [Held; 16],
    overflow: Count,
}
thread_local! {
    static COUNTERS: RefCell<Counters> = const {
        RefCell::new(Counters { stages: [ZERO; 7], handles: [EMPTY; 16], overflow: ZERO })
    };
}
pub(in crate::state_files) fn reset() {
    COUNTERS.with(|c| {
        *c.borrow_mut() = Counters {
            stages: [ZERO; 7],
            handles: [EMPTY; 16],
            overflow: ZERO,
        }
    });
}
pub(in crate::state_files) fn take() -> BTreeMap<String, (u64, u64)> {
    COUNTERS.with(|c| {
        let c = c.borrow();
        let mut result: BTreeMap<_, _> = LABELS
            .iter()
            .zip(c.stages)
            .map(|(name, count)| (name.to_string(), (count.calls, count.inclusive_us)))
            .collect();
        for held in c.handles.iter().filter(|v| v.count.calls != 0) {
            result.insert(
                format!("metadata-pin:handle:{:#x}", held.handle),
                (held.count.calls, held.count.inclusive_us),
            );
        }
        result.insert(
            "metadata-pin:handle-overflow".into(),
            (c.overflow.calls, c.overflow.inclusive_us),
        );
        result
    })
}
fn add(count: &mut Count, elapsed: u64) {
    count.calls = count.calls.saturating_add(1);
    count.inclusive_us = count.inclusive_us.saturating_add(elapsed);
}
pub(in crate::state_files) struct Span {
    index: usize,
    start: Instant,
    handle: Option<usize>,
}
impl Span {
    pub(in crate::state_files) fn new(label: &'static str) -> Self {
        Self {
            index: LABELS.iter().position(|v| *v == label).unwrap_or(6),
            start: Instant::now(),
            handle: None,
        }
    }
    pub(in crate::state_files) fn metadata(file: &std::fs::File) -> Self {
        Self {
            index: 0,
            start: Instant::now(),
            handle: Some(file.as_raw_handle() as usize),
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        COUNTERS.with(|c| {
            let mut c = c.borrow_mut();
            add(&mut c.stages[self.index], elapsed);
            if let Some(handle) = self.handle {
                if let Some(index) = c
                    .handles
                    .iter()
                    .position(|h| h.count.calls != 0 && h.handle == handle)
                    .or_else(|| c.handles.iter().position(|h| h.count.calls == 0))
                {
                    c.handles[index].handle = handle;
                    add(&mut c.handles[index].count, elapsed);
                } else {
                    add(&mut c.overflow, elapsed);
                }
            }
        });
    }
}
