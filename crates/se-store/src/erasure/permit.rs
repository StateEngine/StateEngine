//! The only way an erasure projection satisfies the history triggers. A permit
//! names one exact body or operation, lives on the writer thread for the span of
//! the statements it covers, and is cleared when the guard drops.
use crate::{error::*, *};
use rusqlite::{Connection, functions::FunctionFlags};
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
pub(crate) struct Allowed(());
impl Drop for Allowed {
    fn drop(&mut self) {
        PERMIT.with(|permit| *permit.borrow_mut() = None);
    }
}
fn grant(permit: Permit) -> Allowed {
    PERMIT.with(|held| *held.borrow_mut() = Some(permit));
    Allowed(())
}
pub(crate) fn body(seq: i64, field: &'static str) -> Allowed {
    grant(Permit::Body(seq, field))
}
pub(crate) fn operation(id: Vec<u8>) -> Allowed {
    grant(Permit::Operation(id))
}
pub(crate) fn body_allowed(seq: i64, field: &str) -> bool {
    PERMIT.with(
        |held| matches!(&*held.borrow(), Some(Permit::Body(s, f)) if *s == seq && *f == field),
    )
}
pub(crate) fn operation_allowed(id: &[u8]) -> bool {
    PERMIT.with(|held| matches!(&*held.borrow(), Some(Permit::Operation(o)) if o == id))
}
/// Answer the history triggers' erasure questions from this thread's permit.
/// Only a writer's connection gets this; every other connection keeps the
/// foundation's answer of no.
pub(crate) fn install(c: &Connection) -> StoreResult<()> {
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_INNOCUOUS;
    c.create_scalar_function("se_erase_operation_allowed", 1, flags, |f| {
        let id: Vec<u8> = f.get(0)?;
        Ok(i64::from(operation_allowed(&id)))
    })
    .map_err(sql)?;
    c.create_scalar_function("se_erase_body_allowed", 2, flags, |f| {
        let (seq, field): (i64, String) = (f.get(0)?, f.get(1)?);
        Ok(i64::from(body_allowed(seq, &field)))
    })
    .map_err(sql)
}
