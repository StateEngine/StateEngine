use crate::support::*;
use crate::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

pub(crate) struct Watch {
    sink: Arc<dyn ExitSink>,
}
pub(crate) struct Hub {
    lifecycle: LifecycleId,
    generation: AtomicU64,
    sequence: AtomicU64,
    pub failed: AtomicBool,
    sink: Mutex<Option<Arc<dyn ExitSink>>>,
    watches: Mutex<Vec<Weak<Watch>>>,
}
impl Hub {
    pub fn new(lifecycle: LifecycleId, generation: GenerationId, sink: Arc<dyn ExitSink>) -> Self {
        Self {
            lifecycle,
            generation: AtomicU64::new(generation.get()),
            sequence: AtomicU64::new(0),
            failed: AtomicBool::new(false),
            sink: Mutex::new(Some(sink)),
            watches: Mutex::new(Vec::new()),
        }
    }
    pub fn generation(&self, generation: GenerationId) {
        self.generation.store(generation.get(), Ordering::Release);
    }
    pub fn watch(&self, sink: Arc<dyn ExitSink>) -> ProcResult<Arc<Watch>> {
        let mut watches = self
            .watches
            .lock()
            .map_err(|_| unsupported("notification lock poisoned"))?;
        watches.retain(|w| w.strong_count() != 0);
        if watches.len() == 16 {
            return Err(capacity("exit watches per lifecycle", 16));
        }
        let watch = Arc::new(Watch { sink });
        watches.push(Arc::downgrade(&watch));
        Ok(watch)
    }
    pub fn fire(&self, kind: ExitNoticeKind) {
        let sinks = self
            .sink
            .lock()
            .map(|s| s.iter().cloned().collect::<Vec<_>>());
        let watches = self
            .watches
            .lock()
            .map(|s| s.iter().filter_map(Weak::upgrade).collect::<Vec<_>>());
        let (Ok(sinks), Ok(watches)) = (sinks, watches) else {
            self.failed.store(true, Ordering::Release);
            return;
        };
        // Clone references, then drop both locks before invoking foreign callbacks.
        let Ok(generation) = GenerationId::new(self.generation.load(Ordering::Acquire)) else {
            self.failed.store(true, Ordering::Release);
            return;
        };
        let notice = ExitNotice {
            lifecycle: self.lifecycle.clone(),
            generation,
            sequence: self.sequence.fetch_add(1, Ordering::AcqRel) + 1,
            kind,
        };
        for sink in sinks
            .into_iter()
            .chain(watches.into_iter().map(|w| w.sink.clone()))
        {
            if catch_unwind(AssertUnwindSafe(|| sink.notify(notice.clone()))).is_err() {
                self.failed.store(true, Ordering::Release);
            }
        }
    }
    pub fn disable(&self) {
        if let Ok(mut s) = self.sink.lock() {
            *s = None;
        }
        if let Ok(mut s) = self.watches.lock() {
            s.clear();
        }
    }
}
impl NativeReadiness for Hub {
    fn ready(&self) {
        self.fire(ExitNoticeKind::LaunchChanged);
    }
}
