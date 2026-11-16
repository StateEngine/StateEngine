//! Development-only thread-local worker observations; never a product change.
//! Arrays contain calls, inclusive nanoseconds, exclusive nanoseconds, maximum nanoseconds.
use std::{cell::RefCell, collections::BTreeMap, time::Instant};
#[derive(Default)]
struct Active {
    stack: Vec<(&'static str, Instant, u64)>,
    values: BTreeMap<&'static str, [u64; 4]>,
}
thread_local! { static ACTIVE: RefCell<Option<Active>> = const { RefCell::new(None) }; }
pub fn begin() {
    ACTIVE.with(|s| *s.borrow_mut() = Some(Active::default()));
}
pub fn finish() -> serde_json::Value {
    ACTIVE.with(|s| {
        s.borrow_mut().take().map_or(serde_json::Value::Null, |v| {
            assert!(v.stack.is_empty(), "worker observation scopes remain open");
            serde_json::json!(v.values)
        })
    })
}
pub struct Span(bool);
pub fn span(name: &'static str) -> Span {
    Span(ACTIVE.with(|s| {
        let mut s = s.borrow_mut();
        if let Some(active) = s.as_mut() {
            active.stack.push((name, Instant::now(), 0));
            true
        } else {
            false
        }
    }))
}
pub fn observe<T>(name: &'static str, work: impl FnOnce() -> T) -> T {
    let _span = span(name);
    work()
}
impl Drop for Span {
    fn drop(&mut self) {
        if !self.0 {
            return;
        }
        ACTIVE.with(|s| {
            let mut s = s.borrow_mut();
            let active = s.as_mut().expect("active worker observation");
            let (name, start, children) = active.stack.pop().expect("worker observation scope");
            let elapsed = start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
            let v = active.values.entry(name).or_default();
            v[0] += 1;
            v[1] += elapsed;
            v[2] += elapsed.saturating_sub(children);
            v[3] = v[3].max(elapsed);
            if let Some(parent) = active.stack.last_mut() {
                parent.2 += elapsed;
            }
        });
    }
}
