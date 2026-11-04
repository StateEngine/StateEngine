//! Receipt readback must preserve the original operation and owner boundary.
use se_store::*;
use se_types::Read;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;

#[test]
fn event_receipt_keeps_original_key_membership_and_refuses_private_readers() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let original = store.append(
        f.working("retained", Expected::Absent, "original-key")?,
        &*lease,
    )?;
    let head = store.info()?.head;
    let mut owner = store.snapshot(f.scoped(Visibility::Owner))?;
    let receipt = present(owner.event_receipt(original.primary_event.clone())?)?;
    assert_eq!(receipt.state, CommitState::Replayed);
    assert_eq!(receipt.request_key, original.request_key);
    assert_eq!(receipt.primary_event, original.primary_event);
    assert_eq!(receipt.events, original.events);
    assert_eq!(receipt.first, original.first);
    assert_eq!(receipt.last, original.last);
    assert!(matches!(
        owner.event_receipt(event()?)?,
        Read::Absent { .. }
    ));
    owner.close()?;
    let mut private = store.snapshot(f.self_scope(&f.a))?;
    let error = private
        .event_receipt(original.primary_event)
        .err()
        .ok_or("private receipt read succeeded")?;
    assert_eq!(error.code, StoreErrorCode::ScopeMismatch);
    private.close()?;
    assert_eq!(store.info()?.head, head, "receipt lookup wrote a fact");
    store.close()?;
    Ok(())
}
