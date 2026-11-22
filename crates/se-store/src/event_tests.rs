//! The apply-side text view is crate-private, so its refusal is tested here.
use crate::*;
#[path = "../tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../tests/support/staging_lease.rs"]
mod staging;
use staging::StagingLease;
use std::io::Cursor;

#[test]
fn apply_side_text_view_refuses_an_unmaterialized_handle() -> Check {
    let f = Fixture::new()?;
    let (store, lease) = f.direct()?;
    let lease = StagingLease::new(&f, lease)?;
    let staged = store.stage_text(&mut Cursor::new(b"staged handle"), 64, &lease)?;
    let error = InputText::Staged(staged)
        .as_materialized()
        .err()
        .ok_or("unmaterialized handle passed the apply-side view")?;
    assert_eq!(error.code, StoreErrorCode::EventInvalid);
    assert_eq!(
        InputText::Inline("already materialized".into()).as_materialized()?,
        "already materialized"
    );
    store.close()?;
    Ok(())
}
