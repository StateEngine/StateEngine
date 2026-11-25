use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(super) struct Binding {
    identity: StdioIdentity,
    sink: Arc<dyn StdioSink>,
    gate: Mutex<(bool, u32)>,
    sequence: AtomicU64,
}
impl Binding {
    pub fn new(config: &StdioConfig) -> Arc<Self> {
        Arc::new(Self {
            identity: config.identity.clone(),
            sink: config.notifications.clone(),
            gate: Mutex::new((true, 0)),
            sequence: AtomicU64::new(0),
        })
    }
    pub fn disable(&self) {
        let mut gate = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        gate.0 = false;
    }
    pub fn draining(&self) -> bool {
        self.gate.lock().unwrap_or_else(|e| e.into_inner()).1 != 0
    }
    pub fn fire(&self, kind: StdioNoticeKind) -> bool {
        {
            let mut gate = self.gate.lock().unwrap_or_else(|e| e.into_inner());
            if !gate.0 {
                return true;
            }
            gate.1 += 1;
        }
        let notice = StdioNotice {
            identity: self.identity.clone(),
            kind,
            sequence: self.sequence.fetch_add(1, Ordering::AcqRel) + 1,
        };
        // No native, registry, arena or binding lock crosses a foreign callback.
        let ok = catch_unwind(AssertUnwindSafe(|| self.sink.notify(notice))).is_ok();
        self.gate.lock().unwrap_or_else(|e| e.into_inner()).1 -= 1;
        ok
    }
}
