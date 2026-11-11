//! Real native staging and canonical writes preserve text and store ownership.
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
use se_store::*;
use std::io::Cursor;

fn writer(
    f: &Fixture,
) -> Result<(SqliteDirect, std::sync::Arc<Lease>), Box<dyn std::error::Error>> {
    let (writer, initial) = f.direct()?;
    let native = Lease::acquire_with_backup_ports(
        &f.options.state_directory,
        LeaseMode::DirectClient,
        Some(f.store.clone()),
        true,
    )?;
    drop(initial);
    Ok((writer, native))
}

fn unnamed(fixture: &Fixture) -> Check {
    let entries = std::fs::read_dir(fixture.options.state_directory.join("staging"))?
        .collect::<std::io::Result<Vec<_>>>()?;
    assert!(
        entries.is_empty(),
        "staged text left a named payload behind"
    );
    Ok(())
}

#[test]
fn native_staged_unicode_is_byte_exact_in_the_event_and_projection() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = writer(&f)?;
    let text = "line one\n🦀 e\u{301}\0line two";
    let staged = writer.stage_text(&mut Cursor::new(text.as_bytes()), 1024, &*lease)?;
    unnamed(&f)?;
    let mut batch = f.working(
        "replacement required",
        Expected::Absent,
        "materialized-bytes",
    )?;
    let EventBody::WorkingStateSet { text: target, .. } = &mut batch.events[0].body else {
        return Err("fixture did not construct a working-state event".into());
    };
    *target = InputText::Staged(staged);
    let committed = writer.append(batch, &*lease)?;
    let mut read = writer.snapshot(f.scoped(Visibility::Owner))?;
    let event = present(read.event(committed.primary_event)?)?;
    assert!(matches!(event.body,
        EventBody::WorkingStateSet { text: StoredText::Present(value), .. } if value == text));
    let state = present(read.working_state(f.a.clone())?)?;
    assert!(matches!(state.current.body,
        EventBody::WorkingStateSet { text: StoredText::Present(value), .. } if value == text));
    read.close()?;
    unnamed(&f)?;
    writer.close()?;
    Ok(())
}

#[test]
fn a_foreign_staged_handle_cannot_commit_or_poison_the_destination_key() -> Check {
    let source = Fixture::new()?;
    let destination = Fixture::new()?;
    let (source_writer, source_lease) = writer(&source)?;
    let (mut writer, lease) = writer(&destination)?;
    let staged =
        source_writer.stage_text(&mut Cursor::new(b"foreign body"), 1024, &*source_lease)?;
    let mut batch = destination.working("replacement required", Expected::Absent, "same-key")?;
    let EventBody::WorkingStateSet { text, .. } = &mut batch.events[0].body else {
        return Err("fixture did not construct a working-state event".into());
    };
    *text = InputText::Staged(staged);
    let error = writer
        .append(batch, &*lease)
        .err()
        .ok_or("another store's staged handle committed")?;
    assert_eq!(error.code, StoreErrorCode::GenerationChanged);
    let mut absent = writer.snapshot(destination.scoped(Visibility::Owner))?;
    assert!(matches!(
        absent.working_state(destination.a.clone())?,
        se_types::Read::Absent { .. }
    ));
    absent.close()?;
    writer.append(
        destination.working("valid retry", Expected::Absent, "same-key")?,
        &*lease,
    )?;
    let mut read = writer.snapshot(destination.scoped(Visibility::Owner))?;
    let state = present(read.working_state(destination.a.clone())?)?;
    assert!(matches!(state.current.body,
        EventBody::WorkingStateSet { text: StoredText::Present(value), .. } if value == "valid retry"));
    read.close()?;
    unnamed(&source)?;
    writer.close()?;
    source_writer.close()?;
    Ok(())
}
