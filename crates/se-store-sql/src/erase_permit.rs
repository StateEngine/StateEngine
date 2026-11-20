//! The only way an erasure projection satisfies the history triggers. A permit
//! names one exact body or operation, lives on the writer thread for the span of
//! the statements it covers, and is cleared when the guard drops.
use std::cell::RefCell;

#[derive(Clone, PartialEq)]
enum Permit {
    Body(i64, &'static str),
    Operation(Vec<u8>),
}
thread_local! {
    static PERMIT: RefCell<Option<Permit>> = const { RefCell::new(None) };
}
/// Clears the permit on drop, including on an early error return.
pub struct Allowed(());
impl Drop for Allowed {
    fn drop(&mut self) {
        PERMIT.with(|permit| *permit.borrow_mut() = None);
    }
}
fn grant(permit: Permit) -> Allowed {
    PERMIT.with(|held| *held.borrow_mut() = Some(permit));
    Allowed(())
}
pub fn body(seq: i64, field: &'static str) -> Allowed {
    grant(Permit::Body(seq, field))
}
pub fn operation(id: Vec<u8>) -> Allowed {
    grant(Permit::Operation(id))
}
pub fn body_allowed(seq: i64, field: &str) -> bool {
    PERMIT.with(
        |held| matches!(&*held.borrow(), Some(Permit::Body(s, f)) if *s == seq && *f == field),
    )
}
pub fn operation_allowed(id: &[u8]) -> bool {
    PERMIT.with(|held| matches!(&*held.borrow(), Some(Permit::Operation(o)) if o == id))
}
