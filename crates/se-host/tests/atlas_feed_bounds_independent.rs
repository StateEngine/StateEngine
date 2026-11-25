//! Reviewer checks: a committed record whose first line exceeds the feed
//! title bound still enters the feed instead of stalling the index.
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
use se_store::*;
use se_types::code::*;

const TITLE_BYTES: usize = 160;

fn only_upsert(feed: &RecordFeed) -> Result<&FeedRecord, Box<dyn std::error::Error>> {
    match feed.changes.as_slice() {
        [RecordFeedChange::Upsert(record)] => Ok(record),
        other => Err(format!("expected one upsert, got {} changes", other.len()).into()),
    }
}

fn assert_bounded_title(record: &FeedRecord, first_line: &str) {
    assert!(record.title.len() <= TITLE_BYTES, "{}", record.title.len());
    assert!(!record.title.is_empty());
    assert!(first_line.starts_with(&record.title));
    assert!(record.validate().is_ok());
}

#[test]
fn message_with_long_multibyte_first_line_enters_the_feed() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    // 3-byte characters put the 160-byte cut inside a character: 3 * 80 = 240.
    let first_line = "\u{20ac}".repeat(80);
    let body = format!("{first_line}\nsecond line stays in the body");
    let sent = direct.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.b.clone()),
            message()?,
            &body,
            "atlas-long-title",
        )?,
        &*lease,
    )?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let scope = f.scoped(Visibility::Owner);
    let mut snapshot = reader.snapshot(scope.clone())?;
    let feed = se_atlas_records::feed::next(&mut snapshot, &scope.admission, None)?
        .ok_or("committed message omitted from the feed")?;
    assert_eq!(feed.through, sent.primary_event);
    feed.validate()?;
    let record = only_upsert(&feed)?;
    assert_bounded_title(record, &first_line);
    assert_eq!(record.title.len(), 159, "cut must land on a char boundary");
    assert_eq!(record.body, body);
    assert!(!record.body_truncated);
    snapshot.close()?;
    Ok(())
}

#[test]
fn working_state_with_long_ascii_first_line_enters_the_feed() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let first_line = "a".repeat(250);
    let written = direct.append(
        f.working(&first_line, Expected::Absent, "atlas-long-working")?,
        &*lease,
    )?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let scope = f.scoped(Visibility::Owner);
    let mut snapshot = reader.snapshot(scope.clone())?;
    let feed = se_atlas_records::feed::next(&mut snapshot, &scope.admission, None)?
        .ok_or("committed working state omitted from the feed")?;
    assert_eq!(feed.through, written.primary_event);
    let record = only_upsert(&feed)?;
    assert_bounded_title(record, &first_line);
    assert_eq!(record.title.len(), TITLE_BYTES);
    assert_eq!(record.body, first_line);
    snapshot.close()?;
    Ok(())
}
